#include <tcl.h>
#include <string.h>
#include "qdsh.h"
#include "cursor.h"

int TclGetIntForIndex(Tcl_Interp *, Tcl_Obj *, int, int *);

/* Generated by print_enum in regex.tcl */
enum inst {
    INST_CHR,
    INST_GOTO,
    INST_SPLIT,
    INST_SAVE,
    INST_ANY,
    INST_END,
    INST_START,
    INST_MATCH,
    INST_BRACKET
};

typedef struct {
    int numInsts;
    int codeLength;
    int numSlots;

    /*
     * Align to 32 bits.
     */
    unsigned char prog[1];
} Regex;

typedef struct {
    int specLength; /* Length of "spec" array in bytes */
    int deleted : 1;
    int inUse : 1;
    unsigned char spec[1];
} Subspec;

/* Structures related to regex execution. */
typedef struct {
    const char *charPtr;
    int charIndex;
} Slot;

typedef struct {
    int refCount;
    Slot slots[1];
} Sub;

typedef struct {
    int pc;
    Sub *sub;
} Thread;

typedef struct {
    int numThreads;
    Thread *list;
} ThreadList;

/* Main execution context */
typedef struct {
    unsigned char *prog;
    int numSlots;
    int beginning;
    int turnCount;
    int *lastChecked;
    ThreadList threadLists[2];
    Sub *savedMatch;
    int extantSubs;
} Context;

static void freeRegexIntRep(Tcl_Obj *);
static void dupRegexIntRep(Tcl_Obj *, Tcl_Obj *);

static Regex *getRegexFromObj(Tcl_Interp *, Tcl_Obj *);

/* Execution functions */
static Context *newContext(Regex *regex, int beginning);
static Sub *newSub(Context *ctx);
static void retainSub(Sub *sub);
static void releaseSub(Context *ctx, Sub *sub);
static Sub *updateSub(Context *ctx, Sub *sub, int slot,
                      const char *charPtr, int charIndex);
static int follow(Context *ctx, int pc, Sub *sub, const char *charPtr,
                  int charIndex, int atEnd);
static Sub *execute(Regex *regex, const char *str, const char *end,
                    int charIndex, int beginning);
    
const Tcl_ObjType regexType = {
    "regex",
    freeRegexIntRep,
    dupRegexIntRep,
    NULL,
    NULL
};

/* Type for substitution specification. Really just an indirect
   reference to a byte array object. Type certifies that the subspec
   has been verified. */

static void freeSubspecIntRep(Tcl_Obj *);
static void dupSubspecIntRep(Tcl_Obj *, Tcl_Obj *);

const Tcl_ObjType regexSubspecType = {
    "regexSubspec",
    freeSubspecIntRep,
    dupSubspecIntRep,
    NULL,
    NULL
};

/* Structure used in construction of substitution specification. */
typedef struct {
    Tcl_DString buf;
    Tcl_DString text;
} SpecCtx;

static Context *contextSpace; /* reuse storage. */

#define GET_REGEX(o) ((o)->internalRep.ptrAndLongRep.ptr)
#define SET_REGEX(o, c) ((o)->internalRep.ptrAndLongRep.ptr = (c))

#define GET_SUBSPEC(o) ((o)->internalRep.ptrAndLongRep.ptr)
#define SET_SUBSPEC(o, s) ((o)->internalRep.ptrAndLongRep.ptr = (s))

/* Do Tcl_EvalObjv, keeping interpreter result object but discarding
   all other state. This is used to compile regexes. If an error is
   raised from Tcl, we keep the error message but not the stack trace
   so it will seem like the C code is issuing the error. */
static Tcl_Obj *
doEval(Tcl_Interp *interp, int objc, Tcl_Obj **objv)
{
    int returnCode;
    Tcl_Obj *result;
    Tcl_InterpState interpState;
    
    interpState = Tcl_SaveInterpState(interp, TCL_OK);
    returnCode = Tcl_EvalObjv(interp, objc, objv, TCL_EVAL_GLOBAL);
    result = Tcl_GetObjResult(interp);
    Tcl_IncrRefCount(result);
    Tcl_RestoreInterpState(interp, interpState);
    if (returnCode != TCL_OK) {
        Tcl_SetObjResult(interp, result);
        Tcl_DecrRefCount(result);
        return NULL;
    }
    return result;
}

static Regex *
getRegexFromObj(Tcl_Interp *interp, Tcl_Obj *obj)
{
    unsigned char op, *code, *p, *end, *validDest;
    Tcl_UniChar ch;
    int pass, target1, target2, n, codeLen, size, maxSlot = -1;
    Regex *regex;
    static ssize_t maxSize = -1;
    ssize_t spaceNeeded;
    static Tcl_Obj *compileCmd = NULL;
    Tcl_Obj *cmdLine[2], *result;

    if (obj->typePtr == &regexType) {
        return GET_REGEX(obj);
    }

    if (!compileCmd) {
        compileCmd = Tcl_NewStringObj("::regex::compile", -1);
        Tcl_IncrRefCount(compileCmd);
    }
    cmdLine[0] = compileCmd;
    cmdLine[1] = obj;
    result = doEval(interp, 2, cmdLine);
    if (!result) {
        return NULL;
    }
    code = Tcl_GetByteArrayFromObj(result, &codeLen);
    regex = ckalloc(sizeof(Regex) + codeLen - 1);
    regex->numInsts = 0;
    regex->codeLength = codeLen;
    memcpy(regex->prog, code, codeLen);
    Tcl_DecrRefCount(result);
    code = regex->prog;
    
    /*
     * Table to check for valid jump destinations. 1 if start of
     * instruction, 0 for continuation bytes.
     */
    validDest = ckalloc(codeLen);
    memset(validDest, 0, codeLen);

    /*
     * Validate the regex in two passes. First pass populates
     * validDest by scanning the instructions. Second pass verifies
     * that every jump targets the start of an instruction.
     */
    for (pass = 0; pass < 2; pass++) {
        p = code;
        end = code + codeLen;
        while (p < end) {
            if (pass == 0) {
                regex->numInsts++;
                validDest[p-code] = 1;
            }

            op = *p++;
            switch (op >> 2) {
            case INST_CHR:
                if (!Tcl_UtfCharComplete((char *)p, end-p)) goto error;
                p += Tcl_UtfToUniChar((char *)p, &ch);
                continue;
            case INST_GOTO:
                if (p+1 >= end) goto error;
                target1 = p[0] << 8 | p[1];
                p += 2;
                if (pass == 1 && (target1 >= codeLen || !validDest[target1]))
                    goto error;
                continue;
            case INST_SPLIT:
                if (p+1 >= end) goto error;
                target1 = p[0] << 8 | p[1];
                p += 2;
                if (p+1 >= end) goto error;
                target2 = p[0] << 8 | p[1];
                p += 2;
                if (pass == 1 &&
                    (target1 >= codeLen || target2 >= codeLen ||
                     !validDest[target1] || !validDest[target2])) {
                    goto error;
                }
                continue;
            case INST_SAVE:
                if (p+1 >= end) goto error;
                n = p[0] << 8 | p[1];
                p += 2;
                if (n > maxSlot) maxSlot = n;
                continue;
            case INST_ANY: case INST_END: case INST_START: case INST_MATCH:
                continue;
            case INST_BRACKET:
                if (p+1 >= end) goto error;
                n = p[0] << 8 | p[1];
                p += 2;
                if (op & 2) {
                    size = 1;
                } else {
                    size = 4;
                    p = (unsigned char *)(((uintptr_t)p + 3) & ~3);
                }
                if (n < 1 || p + 2*n*size > end) goto error;
                p += 2*n*size;
                continue;
            default:
                goto error;
            }
        }
    }
    ckfree(validDest);
    
    regex->numSlots = maxSlot + 1;
    if ((regex->numSlots & 1) == 1) {
        /* Regex compiler always emits slots as begin/end pairs. */
        Tcl_SetObjResult(interp, Tcl_NewStringObj("odd number of slots", -1));
        ckfree(regex);
        return NULL;
    }

    /* Set internal representation. */
    if (obj->typePtr && obj->typePtr->freeIntRepProc) {
        obj->typePtr->freeIntRepProc(obj);
    }
    SET_REGEX(obj, regex);
    obj->typePtr = &regexType;

    /* Reserve needed space */
    spaceNeeded = sizeof(Context)
        + regex->codeLength*sizeof(int) /* lastChecked */
        + 2*regex->numInsts*sizeof(Thread); /* threadLists */
    if (maxSize == -1) {
        contextSpace = ckalloc(spaceNeeded);
        maxSize = spaceNeeded;
    } else if (spaceNeeded > maxSize) {
        contextSpace = ckrealloc(contextSpace, spaceNeeded);
        maxSize = spaceNeeded;
    }

    return regex;

error:
    ckfree(validDest);
    ckfree(regex);
    Tcl_SetObjResult(interp, Tcl_ObjPrintf("regex bytecode bad at %d", (int)(p-code)));
    return NULL;
}

static void
freeRegexIntRep(Tcl_Obj *obj)
{
    ckfree(GET_REGEX(obj));
    obj->typePtr = NULL;
}

static void
dupRegexIntRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    Regex *srcRegex, *dstRegex;
    size_t size;

    srcRegex = GET_REGEX(src);
    size = sizeof(Regex) + srcRegex->codeLength - 1;
    dstRegex = ckalloc(size);
    memcpy(dstRegex, srcRegex, size);
    SET_REGEX(dst, dstRegex);
    dst->typePtr = &regexType;
}

/* Execution functions */
static Context *
newContext(Regex *regex, int beginning)
{
    Context *ctx;
    char *p;

    ctx = contextSpace;
    p = (char *)ctx;
    p += sizeof(Context);
    ctx->lastChecked = (int *)p;
    memset(ctx->lastChecked, 0, regex->codeLength*sizeof(int));
    p += regex->codeLength*sizeof(int);
    ctx->threadLists[0].list = (Thread *)p;
    p += regex->numInsts*sizeof(Thread);
    ctx->threadLists[1].list = (Thread *)p;

    ctx->prog = regex->prog;
    ctx->numSlots = regex->numSlots;
    ctx->beginning = beginning;
    ctx->turnCount = 1;
    ctx->threadLists[0].numThreads = 0;
    ctx->threadLists[1].numThreads = 0;
    ctx->savedMatch = NULL;
    ctx->extantSubs = 0;
    return ctx;
}

static Sub *
newSub(Context *ctx)
{
    int i;
    Sub *sub;

    sub = ckalloc(sizeof(Sub) + (ctx->numSlots-1)*sizeof(Slot));
    sub->refCount = 1;
    for (i = 0; i < ctx->numSlots; i++) {
        sub->slots[i].charPtr = NULL;
        sub->slots[i].charIndex = 0;
    }
    ctx->extantSubs++;
    return sub;
}

static void
retainSub(Sub *sub)
{
    sub->refCount++;
}

static void
releaseSub(Context *ctx, Sub *sub)
{
    if (sub->refCount-- <= 1) {
        sub->refCount = 0xdeadbeef;
        ckfree(sub);
        ctx->extantSubs--;
    }
}

static Sub *
updateSub(Context *ctx, Sub *sub, int slot, const char *charPtr,
	  int charIndex)
{
    Sub *result;

    if (sub->refCount > 1) {
        result = newSub(ctx);
        memcpy(result->slots, sub->slots, ctx->numSlots*sizeof(Slot));
        sub->refCount--;
    } else {
        result = sub;
    }
    result->slots[slot].charPtr = charPtr;
    result->slots[slot].charIndex = charIndex;
    return result;
}

#define curList (&ctx->threadLists[ctx->turnCount & 1])
#define nextList (&ctx->threadLists[1 ^ (ctx->turnCount & 1)])

/*
 * Expects sub's ref count to be pre-incremented. Will "match" one
 * ref count of sub by either storing or decrementing.
 */
static int
follow(Context *ctx, int pc, Sub *sub, const char *charPtr,
       int charIndex, int atEnd)
{
    int op;
    unsigned char *cp;
    Thread *thread;

    /*
     * Check if we've already scheduled this thread during this turn.
     */
    if (ctx->lastChecked[pc] == ctx->turnCount) {
        releaseSub(ctx, sub);
        return 0;
    }

    ctx->lastChecked[pc] = ctx->turnCount;
    cp = ctx->prog + pc;
    op = *cp;
    switch (op >> 2) {
    case INST_GOTO:
        return follow(ctx, cp[1] << 8 | cp[2], sub, charPtr, charIndex, atEnd);
    case INST_SPLIT:
        retainSub(sub); /* prevent first follow call from altering sub */
        if (follow(ctx, cp[1] << 8 | cp[2], sub, charPtr, charIndex, atEnd)) {
            releaseSub(ctx, sub);
            return 1;
        }
        return follow(ctx, cp[3] << 8 | cp[4], sub, charPtr, charIndex, atEnd);
    case INST_SAVE:
        sub = updateSub(ctx, sub, cp[1] << 8 | cp[2], charPtr, charIndex);
        return follow(ctx, pc+3, sub, charPtr, charIndex, atEnd);
    case INST_MATCH:
        if (ctx->savedMatch) releaseSub(ctx, ctx->savedMatch);
        ctx->savedMatch = sub;
        return 1;
    case INST_END:
        if (atEnd)
            return follow(ctx, pc+1, sub, charPtr, charIndex, atEnd);
        releaseSub(ctx, sub);
        break;
    case INST_START:
        if (charIndex == ctx->beginning)
            return follow(ctx, pc+1, sub, charPtr, charIndex, atEnd);
        releaseSub(ctx, sub);
        break;
    default:
        if (atEnd) {
            releaseSub(ctx, sub);
        } else {
            thread = &nextList->list[nextList->numThreads++];
            thread->pc = pc;
            thread->sub = sub;
        }
    }
    return 0;
}

static Sub *
execute(Regex *regex, const char *str, const char *end, int charIndex,
        int beginning)
{
    unsigned char *code;
    Context *ctx;
    Sub *sub;
    int i, pc, op, invert, ascii, size, length;
    Tcl_UniChar ch, matchChar;

    ctx = newContext(regex, beginning);
    sub = newSub(ctx);
    code = ctx->prog;

    follow(ctx, 0, sub, str, charIndex, str == end);
    while (str < end) {
        ctx->turnCount++;
        nextList->numThreads = 0;

        /* If all threads died on the previous turn, we're done */
        if (curList->numThreads == 0)
            break;

        str += Tcl_UtfToUniChar(str, &ch);
        charIndex++;
        for (i = 0; i < curList->numThreads; i++) {
            pc = curList->list[i].pc;
            sub = curList->list[i].sub;
            op = code[pc];
            switch (op >> 2) {
            case INST_CHR:
                pc += Tcl_UtfToUniChar(((char *)(code+pc+1)), &matchChar);
                if (matchChar != ch) releaseSub(ctx, sub);
                else if (follow(ctx, pc+1, sub, str, charIndex, str == end)) goto skip;
                break;
            case INST_ANY:
                if (follow(ctx, pc+1, sub, str, charIndex, str == end)) goto skip;
                break;
            case INST_BRACKET:
                invert = op & 1;
                ascii = op & 2;
                length = code[pc+1] << 8 | code[pc+2];
                pc += 3;
#define BINARY_SEARCH(chartype)                                         \
                do {                                                    \
                    int bs, be, pos;                                    \
                    struct Pair {chartype lo, hi;} *ranges;             \
                                                                        \
                    bs = 0;                                             \
                    be = length-1; /* length >= 1 */                    \
                    ranges = (struct Pair *)(code+pc);                  \
                    for (;;) {                                          \
                        if (bs > be) {                                  \
                            if (invert) goto found; else break;         \
                        }                                               \
                        pos = (bs + be) >> 1;                           \
                        if (ch < ranges[pos].lo) be = pos-1;            \
                        else if (ch > ranges[pos].hi) bs = pos+1;       \
                        else if (invert) break;                         \
                        else goto found;                                \
                    }                                                   \
                } while (0)

                if (ascii) {
                    size = 1;
                    BINARY_SEARCH(char);
                } else {
                    size = 4;
                    pc = (pc + 3) & ~3;
                    BINARY_SEARCH(Tcl_UniChar);
                }
#undef BINARY_SEARCH
                releaseSub(ctx, sub);
                break;
found:
                if (follow(ctx, pc+2*length*size, sub, str, charIndex, str == end))
                    goto skip;
                break;
            default:
                Tcl_Panic("unknown op %d\n", op>>2);
            }
        }
skip:
        for (i++; i < curList->numThreads; i++) {
            releaseSub(ctx, curList->list[i].sub);
        }
    }

    sub = ctx->savedMatch;
    if (sub) {
        if (!sub->slots[0].charPtr || !sub->slots[1].charPtr) {
            releaseSub(ctx, sub);
            sub = NULL;
        } else {
            ctx->extantSubs--;
        }
    }
    if (ctx->extantSubs) {
        Tcl_Panic("Leaked %d subs", ctx->extantSubs);
    }
    /*ckfree(ctx);*/ /* contextSpace */
    return sub;
}

#undef curList
#undef nextList

/* Closely modeled after Tcl_RegexpObjCmd, see comments there. */
int
regexMatchCmd(ClientData cd, Tcl_Interp *interp, int objc,
              Tcl_Obj *const objv[])
{
    static const char *const options[] = {
        "-all",   "-cursor", "-indices", "-inline",
        "-start", "--",      NULL
    };
    enum options {
        OPT_ALL,   OPT_CURSOR, OPT_INDICES, OPT_INLINE,
        OPT_START, OPT_LAST
    };
    int i, all, cursor, indices, doinline, beginning,
        charPos, index, length, charLen, ret;
    const char *opt, *str, *end, *p;
    Tcl_Obj *startObj, *obj, *result = NULL, *newVal, *range[2], *curStr = NULL;
    Regex *regex;
    Sub *sub;
    Cursor *cur;

    all = 0;
    cursor = 0;
    indices = 0;
    doinline = 0;
    startObj = NULL;
    for (i = 1; i < objc; i++) {
        opt = Tcl_GetString(objv[i]);
        if (opt[0] != '-') {
            break;
        }
        if (Tcl_GetIndexFromObj(interp, objv[i], options, "option", TCL_EXACT,
                                &index) != TCL_OK) {
            goto optionError;
        }
        switch ((enum options)index) {
        case OPT_ALL:
            all = 1;
            break;
        case OPT_CURSOR:
            cursor = 1;
            break;
        case OPT_INDICES:
            indices = 1;
            break;
        case OPT_INLINE:
            doinline = 1;
            break;
        case OPT_START: {
            int dummy;
            if (++i >= objc) {
                goto endOfForLoop;
            }
            if (TclGetIntForIndex(interp, objv[i], 0, &dummy) != TCL_OK) {
                goto optionError;
            }
	    Tcl_IncrRefCount(objv[i]);
            if (startObj) {
                Tcl_DecrRefCount(startObj);
            }
            startObj = objv[i];
            break;
        }
        case OPT_LAST:
            i++;
            goto endOfForLoop;
        }
    }
    
endOfForLoop:
    if ((objc - i) < 2) {
        Tcl_WrongNumArgs(interp, 1, objv,
                         "?-option ...? exp string ?matchVar? ?subMatchVar ...?");
optionError:
        if (startObj) {
            Tcl_DecrRefCount(startObj);
        }
        return TCL_ERROR;
    }
    objc -= i;
    objv += i;

    obj = objv[1];
    if (cursor) {
	if (startObj) { /* ignore -start option */
	    Tcl_DecrRefCount(startObj);
	}
	if (!(cur = getCursorFromObj(interp, obj))) {
            return TCL_ERROR;
        }
        curStr = cur->strObj;
        Tcl_IncrRefCount(curStr);
        charPos = cur->charPos;
        str = Tcl_GetStringFromObj(curStr, &length);
        end = str + length;
        str += cur->bytePos;
#if 0
    } else if (startObj) {
        TclGetIntForIndex(NULL, startObj, Tcl_GetCharLength(obj)-1, &charPos);
        Tcl_DecrRefCount(startObj);
        str = Tcl_GetStringFromObjAt(obj, charPos, &length, &start);
        end = str + length;
        charPos = start; /* adjusted */
#endif
    } else {
        str = Tcl_GetStringFromObj(obj, &length);
        end = str + length;
	if (startObj) {
	    charLen = Tcl_GetCharLength(obj);
	    ret = TclGetIntForIndex(interp, startObj, charLen-1, &charPos);
	    Tcl_DecrRefCount(startObj);
	    if (ret == TCL_ERROR) {
		return TCL_ERROR;
	    }
	    if (charPos > charLen) {
		charPos = charLen;
	    }
	    str = Tcl_UtfAtIndex(str, charPos);
	} else {
	    charPos = 0;
	}
    }
    p = str;
    beginning = charPos;

    /* Aliasing between exp (objv[0]) and string (objv[1]) is
       permitted. In that case, we simply lose the cursor (if -cursor
       specified) or string (if -start specified) internal rep, which
       is not an issue because henceforth we only access the string
       rep. Neither cursor nor string type invalidates string rep. */
    if (!(regex = getRegexFromObj(interp, objv[0]))) {
        if (curStr)
            Tcl_DecrRefCount(curStr);
        return TCL_ERROR;
    }

    objc -= 2;
    objv += 2;

    if (doinline || objc > regex->numSlots/2) {
        objc = regex->numSlots/2;
    }

    for (;;) {
        sub = execute(regex, p, end, charPos, beginning);
        if (!sub) {
            if (all <= 1) {
                if (!doinline)
                    Tcl_SetObjResult(interp, Tcl_NewIntObj(0));
                if (curStr)
                    Tcl_DecrRefCount(curStr);
                return TCL_OK;
            }
            break;
        }

        if (doinline && all <= 1) {
            result = Tcl_NewObj();
        }
        for (i = 0; i < objc; i++) {
            Slot *s = &sub->slots[i*2];
            if (cursor) {
                char *base = curStr->bytes;
                range[0] = newCursorObj(curStr, s[0].charPtr-base, s[0].charIndex);
                range[1] = newCursorObj(curStr, s[1].charPtr-base, s[1].charIndex);
                newVal = Tcl_NewListObj(2, range);
            } else if (indices) {
                range[0] = Tcl_NewLongObj(s[0].charIndex);
                range[1] = Tcl_NewLongObj(s[1].charIndex-1);
                newVal = Tcl_NewListObj(2, range);
            } else if (s[0].charPtr && s[1].charPtr) {
                newVal = Tcl_NewStringObjWithCharLength(s[0].charPtr,
                    s[1].charPtr-s[0].charPtr,
                    s[1].charIndex-s[0].charIndex);
            } else {
                newVal = Tcl_NewObj();
            }
            if (doinline) {
                Tcl_ListObjAppendElement(NULL, result, newVal);
            } else if (!Tcl_ObjSetVar2(interp, objv[i], NULL, newVal, TCL_LEAVE_ERR_MSG)) {
                ckfree(sub);
                if (curStr)
                    Tcl_DecrRefCount(curStr);
                return TCL_ERROR;
            }
        }

        p = sub->slots[1].charPtr;
        charPos = sub->slots[1].charIndex;
        if (sub->slots[1].charPtr == sub->slots[0].charPtr) {
            p = (char *)Tcl_UtfNext(p);
            charPos++;
        }
        ckfree(sub);
        
        if (all == 0) {
            break;
        }

        all++;
        if (p >= end) {
            break;
        }
    }

    Tcl_SetObjResult(interp, doinline ? result : Tcl_NewIntObj(all ? all-1 : 1));
    if (curStr) {
        Tcl_DecrRefCount(curStr);
    }
    return TCL_OK;
}

static void
specFlushText(SpecCtx *ctx)
{
    char *p, *end;
    int len, adv;
    char b;

    len = Tcl_DStringLength(&ctx->text);
    if (len > 0) {
        p = Tcl_DStringValue(&ctx->text);
        end = p + len;
        while (p < end) {
            adv = end - p;
            if (adv > 0xff-9) {
                adv = 0xff-9;
            }
            b = adv + 9;
            Tcl_DStringAppend(&ctx->buf, &b, 1);
            Tcl_DStringAppend(&ctx->buf, p, adv);
            p += adv;
        }
        Tcl_DStringSetLength(&ctx->text, 0);
    }
}

static void
specAppendRepl(SpecCtx *ctx, char repl)
{
    specFlushText(ctx);
    Tcl_DStringAppend(&ctx->buf, &repl, 1);
}

static Subspec *
getSubspecFromObj(Tcl_Obj *obj)
{
    const char *p, *end, *next, *start;
    int length, specLength;
    Tcl_UniChar ch;
    SpecCtx ctx;
    Subspec *subspec;

    if (obj->typePtr == &regexSubspecType) {
        return GET_SUBSPEC(obj);
    }

    Tcl_DStringInit(&ctx.buf);
    Tcl_DStringInit(&ctx.text);
    p = Tcl_GetStringFromObj(obj, &length);
    end = p + length;
    while (p < end) {
        start = p;
        p += Tcl_UtfToUniChar((char *)p, &ch);
        if (ch == '&') {
            specAppendRepl(&ctx, 0);
        } else if (ch == '\\') {
            next = p + Tcl_UtfToUniChar((char *)p, &ch);
            if (ch >= '0' && ch <= '9') {
                specAppendRepl(&ctx, ch - '0');
                p = next;
            } else if (ch == '\\' || ch == '&') {
                Tcl_DStringAppend(&ctx.text, p, next-p);
                p = next;
            } else {
                Tcl_DStringAppend(&ctx.text, start, p-start);
            }
        } else {
            Tcl_DStringAppend(&ctx.text, start, p-start);
        }
    }
    specFlushText(&ctx);

    specLength = Tcl_DStringLength(&ctx.buf);
    subspec = ckalloc(sizeof(Subspec) + specLength - 1);
    subspec->specLength = specLength;
    subspec->deleted = 0;
    subspec->inUse = 0;
    memcpy(subspec->spec, Tcl_DStringValue(&ctx.buf), specLength);
    Tcl_DStringFree(&ctx.buf);
    Tcl_DStringFree(&ctx.text);

    if (obj->typePtr && obj->typePtr->freeIntRepProc) {
        obj->typePtr->freeIntRepProc(obj);
    }
    SET_SUBSPEC(obj, subspec);
    obj->typePtr = &regexSubspecType;
    return subspec;
}

static void
freeSubspecIntRep(Tcl_Obj *obj)
{
    Subspec *subspec;

    subspec = GET_SUBSPEC(obj);
    if (subspec->inUse) {
        subspec->deleted = 1;
    } else {
        ckfree(subspec);
    }
    SET_SUBSPEC(obj, NULL);
    obj->typePtr = NULL;
}

static void
dupSubspecIntRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    Subspec *srcSpec, *dstSpec;
    size_t size;

    srcSpec = GET_SUBSPEC(src);
    size = sizeof(Subspec) + srcSpec->specLength - 1;
    dstSpec = ckalloc(size);
    memcpy(dstSpec, srcSpec, size);
    SET_SUBSPEC(dst, dstSpec);
    dst->typePtr = &regexSubspecType;
}

int
regexSubCmd(ClientData cd, Tcl_Interp *interp, int objc,
            Tcl_Obj *const objv[])
{
    int all = 0, cursor = 0, i, numChars, length, charPos, ret,
        returnCode = TCL_OK, beginning, index, numMatches = 0;
    const char *opt, *str, *end, *strOrig, *p;
    unsigned char *q;
    Subspec *subspec;
    Tcl_Obj *startIndex = NULL, *obj, *resultObj = NULL, *curStr = NULL;
    Regex *regex;
    Cursor *cur;
    Sub *sub;
    static const char *const options[] = {
	"-all", "-cursor", "-start", "--", NULL
    };
    enum options {
	OPT_ALL, OPT_CURSOR, OPT_START, OPT_LAST
    };

    for (i = 1; i < objc; i++) {
        opt = Tcl_GetString(objv[i]);
        if (opt[0] != '-') {
            break;
        }
        if (Tcl_GetIndexFromObj(interp, objv[i], options, "option",
                                TCL_EXACT, &index) != TCL_OK) {
            goto optionError;
        }
        switch ((enum options)index) {
        case OPT_ALL:
            all = 1;
            break;
        case OPT_CURSOR:
            cursor = 1;
            break;
        case OPT_START:
            if (++i >= objc) {
                goto endOfLoop; /* Treat as non-option */
            }
            if (TclGetIntForIndex(interp, objv[i], 0, &charPos) != TCL_OK) {
                goto optionError;
            }
	    Tcl_IncrRefCount(objv[i]);
            if (startIndex) {
                Tcl_DecrRefCount(startIndex);
            }
            startIndex = objv[i];
            break;
        case OPT_LAST:
            i++;
            goto endOfLoop;
        }
    }

 endOfLoop:
    if (objc-i < 3 || objc-i > 4) {
	Tcl_WrongNumArgs(interp, 1, objv,
		"?-option ...? exp string subSpec ?varName?");
    optionError:
        if (startIndex) {
            Tcl_DecrRefCount(startIndex);
        }
        return TCL_ERROR;
    }

    objc -= i;
    objv += i;

    /*
     * Get the subspec first. By setting subspec->inUse, the subspec
     * will be preserved even if the containing object gets shimmered,
     * which would happen if the same pointer is passed in for both
     * the regexp and the subspec, or the subspec and the string to be
     * matched.
     */
    subspec = getSubspecFromObj(objv[2]);
    if (subspec == NULL) {
	if (startIndex) {
	    Tcl_DecrRefCount(startIndex);
	}
        return TCL_ERROR;
    }
    subspec->inUse = 1;

    /*
     * Next, get the string to be matched. This might: shimmer to
     * cursor, shimmer to string, or not shimmer. In any case, after
     * we obtain the string rep's pointer and character offset, we
     * don't care if the internal rep goes away.
     */
    obj = objv[1];
    if (cursor) {
	if (startIndex) { /* ignore -start option */
	    Tcl_DecrRefCount(startIndex);
	}
	if (!(cur = getCursorFromObj(interp, obj))) {
            returnCode = TCL_ERROR;
            goto done;
        }
        charPos = cur->charPos;
	curStr = cur->strObj;
	Tcl_IncrRefCount(curStr);
        strOrig = Tcl_GetStringFromObj(curStr, &length);
        end = strOrig + length;
        str = strOrig + cur->bytePos;
#if 0
    } else if (startIndex) {
        numChars = Tcl_GetCharLength(objv[1]);
        TclGetIntForIndex(NULL, startIndex, numChars-1, &charPos);
        Tcl_DecrRefCount(startIndex);
        strOrig = Tcl_GetString(obj);
        str = Tcl_GetStringFromObjAt(obj, charPos, &length, &charPos);
        end = str + length;
#endif
    } else {
        str = strOrig = Tcl_GetStringFromObj(obj, &length);
        end = str + length;
	if (startIndex) {
	    numChars = Tcl_GetCharLength(obj);
	    ret = TclGetIntForIndex(interp, startIndex, numChars-1, &charPos);
	    Tcl_DecrRefCount(startIndex);
	    if (ret == TCL_ERROR) {
		returnCode = TCL_ERROR;
		goto done;
	    }
	    if (charPos > numChars) {
		charPos = numChars;
	    }
	    str = Tcl_UtfAtIndex(str, charPos);
	} else {
	    charPos = 0;
	}
    }

    /* Now we're ready to fetch the Regex object from objv[0]. At this
       point, all the info we need to finish will be preserved even if
       any Tcl_Obj parameters previously processed happen to be
       shimmered due to aliasing. */
    if (!(regex = getRegexFromObj(interp, objv[0]))) {
	returnCode = TCL_ERROR;
	goto done;
    }

    p = str;
    beginning = charPos;
    while (p < end) {
        sub = execute(regex, p, end, charPos, beginning);
        if (!sub) {
            break;
        }

        if (numMatches == 0) {
            resultObj = Tcl_NewStringObj(NULL, 0);
            Tcl_IncrRefCount(resultObj);
            /* Copy initial portion of string */
            Tcl_AppendToObj(resultObj, strOrig, p-strOrig);
        }
        numMatches++;

        
        /* Copy from p to start of match */
        Tcl_AppendToObj(resultObj, p, sub->slots[0].charPtr-p);

        /* Copy subspec */
        q = subspec->spec;
        while (q < subspec->spec + subspec->specLength) {
            if (*q < 10) {
                if (*q < regex->numSlots) {
                    Tcl_AppendToObj(resultObj, sub->slots[(*q)*2].charPtr,
                                    sub->slots[(*q)*2+1].charPtr -
                                    sub->slots[(*q)*2].charPtr);
                }
                q++;
            } else {
                Tcl_AppendToObj(resultObj, (char *)(q+1), *q-9);
                q += (*q-9) + 1;
            }
        }

        /* Move cursor to after this match */
        p = sub->slots[1].charPtr;

        /* If we matched the empty string, advance one character. */
        if (p == sub->slots[0].charPtr) {
            if (p < end) {
                p = (char *)Tcl_UtfNext(p);
                Tcl_AppendToObj(resultObj, sub->slots[0].charPtr,
                                p-sub->slots[0].charPtr);
            }
        }
        ckfree(sub);
        if (!all) {
            break;
        }
    }

    if (numMatches == 0) {
        resultObj = obj;
        Tcl_IncrRefCount(resultObj);
    } else if (p < end) {
        Tcl_AppendToObj(resultObj, p, end-p);
    }

    if (objc == 4) {
        if (Tcl_ObjSetVar2(interp, objv[3], NULL, resultObj,
                           TCL_LEAVE_ERR_MSG) == NULL) {
            returnCode = TCL_ERROR;
        } else {
            Tcl_SetObjResult(interp, Tcl_NewIntObj(numMatches));
        }
    } else {
        Tcl_SetObjResult(interp, resultObj);
    }

done:
    if (resultObj) {
        Tcl_DecrRefCount(resultObj);
    }
    if (curStr) {
	Tcl_DecrRefCount(curStr);
    }
    if (subspec->deleted) {
        ckfree(subspec);
    } else {
        subspec->inUse = 0;
    }
    return returnCode;
}