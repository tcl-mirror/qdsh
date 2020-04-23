#include <stdint.h>
#include <tcl.h>
#include <string.h>
#include <signal.h>

#include "qdsh.h"
#include "critbit.h"
#include "cursor.h"
#include "udp_tcl.h"

static void loadCommands(Tcl_Interp *);
static Tcl_Interp *rootInterp;

void
dupCellInternalRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    Tcl_Obj *contents = src->internalRep.ptrAndLongRep.ptr;
    if (contents)
        Tcl_IncrRefCount(contents);
    dst->internalRep.ptrAndLongRep.ptr = contents;
    dst->internalRep.ptrAndLongRep.value =
        src->internalRep.ptrAndLongRep.value;
    dst->typePtr = src->typePtr;
}

void
freeCellInternalRep(Tcl_Obj *obj)
{
    Tcl_Obj *contents = obj->internalRep.ptrAndLongRep.ptr;
    if (contents)
        Tcl_DecrRefCount(contents);
    obj->typePtr = NULL;
}

void
freeIntRep(Tcl_Obj *obj)
{
    if (obj->typePtr && obj->typePtr->freeIntRepProc) {
        obj->typePtr->freeIntRepProc(obj);
    }
}

int
errorMsg(Tcl_Interp *interp, const char *msg) {
    Tcl_SetObjResult(interp, Tcl_NewStringObj(msg, -1));
    return TCL_ERROR;
}

void
takeStringRep(Tcl_Obj *consumerObj, Tcl_Obj *producerObj)
{
    Tcl_GetString(producerObj);
    consumerObj->bytes = producerObj->bytes;
    consumerObj->length = producerObj->length;
    producerObj->bytes = NULL;
    producerObj->length = -1;
}

void
assignObjLoc(Tcl_Obj **loc, Tcl_Obj *val)
{
    if (val) Tcl_IncrRefCount(val);
    if (*loc) Tcl_DecrRefCount(*loc);
    *loc = val;
}

Tcl_Command
ckCreateNRCmd(Tcl_Interp *interp, const char *cmdName,
	      Tcl_ObjCmdProc *proc, Tcl_ObjCmdProc *nreProc,
	      ClientData cd, Tcl_CmdDeleteProc *deleteProc)
{
    int i, cmdLen, nsLen;
    char *nsName, *buf = NULL;
    Tcl_Command token;

    cmdLen = strlen(cmdName);
    for (i = 0; i < cmdLen; i++)
	if (cmdName[i] == ':' && cmdName[i+1] == ':')
	    goto skip;
    if (Tcl_GetCurrentNamespace(interp)->name[0] == '\0')
	goto skip;
    nsName = Tcl_GetCurrentNamespace(interp)->fullName;
    nsLen = strlen(nsName);
    buf = ckalloc(nsLen + cmdLen + 3);
    memcpy(buf, nsName, nsLen);
    buf[nsLen] = ':';
    buf[nsLen + 1] = ':';
    memcpy(buf + nsLen + 2, cmdName, cmdLen);
    buf[nsLen + cmdLen + 2] = '\0';
    cmdName = buf;
skip:
    token = (nreProc == NULL) ?
	Tcl_CreateObjCommand(interp, cmdName, proc, cd, deleteProc) :
	Tcl_NRCreateCommand(interp, cmdName, proc, nreProc, cd, deleteProc);
    if (buf != NULL)
	ckfree(buf);
    if (token == NULL)
	Tcl_SetObjResult(interp, Tcl_ObjPrintf("could not create command %s",
					       cmdName));
    return token;
}

Tcl_Command
ckCreateCmd(Tcl_Interp *interp, const char *cmdName,
	    Tcl_ObjCmdProc *proc,
	    ClientData cd, Tcl_CmdDeleteProc *deleteProc)
{
    return ckCreateNRCmd(interp, cmdName, proc, NULL, cd, deleteProc);
}

static int
lcaseNRCmd(ClientData cd, Tcl_Interp *interp, int objc,
           Tcl_Obj *const objv[])
{
    int i, j, lsLen, hLen, pLen;
    Tcl_Obj **ls, **h, **p, *args;
    char *str;
    
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "ls cases");
        return TCL_ERROR;
    }
    if (Tcl_ListObjGetElements(interp, objv[1], &lsLen, &ls) != TCL_OK ||
        Tcl_ListObjGetElements(interp, objv[2], &hLen, &h) != TCL_OK) {
        return TCL_ERROR;
    }
    if (hLen & 1) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("handler list has odd length", -1));
        return TCL_ERROR;
    }
    for (i = 0; i < hLen; i += 2) {
        if (Tcl_ListObjGetElements(interp, h[i], &pLen, &p) != TCL_OK) {
            return TCL_ERROR;
        }
        if (pLen == 0) {
            if (lsLen == 0)
                return Tcl_NREvalObj(interp, h[i+1], 0);
            continue;
        }
        str = Tcl_GetString(p[pLen-1]);
        if (str[0] == 'a' && str[1] == 'r' && str[2] == 'g' &&
            str[3] == 's' && str[4] == '\0' && lsLen >= pLen-1) {
            args = Tcl_NewListObj(lsLen - pLen + 1, &ls[pLen-1]);
            if (!Tcl_ObjSetVar2(interp, p[pLen-1], NULL, args, TCL_LEAVE_ERR_MSG))
                return TCL_ERROR;
            pLen--;
        } else if (lsLen != pLen) {
            continue;
        }
        for (j = 0; j < pLen; j++) {
            if (!Tcl_ObjSetVar2(interp, p[j], NULL, ls[j], TCL_LEAVE_ERR_MSG))
                return TCL_ERROR;
        }
        return Tcl_NREvalObj(interp, h[i+1], 0);
    }
    return TCL_OK;
}

static int
lcaseCmd(ClientData cd, Tcl_Interp *interp,
         int objc, Tcl_Obj *const objv[])
{
    return Tcl_NRCallObjProc(interp, lcaseNRCmd, NULL, objc, objv);
}

static int
refCountCmd(ClientData cd, Tcl_Interp *interp,
            int objc, Tcl_Obj *const objv[])
{
    if (objc == 2) {
        Tcl_SetObjResult(interp, Tcl_NewIntObj(objv[1]->refCount));
    }
    return TCL_OK;
}

static int
evalDirectCmd(ClientData cd, Tcl_Interp *interp,
              int objc, Tcl_Obj *const objv[])
{
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "script");
	return TCL_ERROR;
    }
    return Tcl_EvalObjEx(interp, objv[1], TCL_EVAL_DIRECT);
}
        

static int
hexCmd(ClientData cd, Tcl_Interp *interp,
       int objc, Tcl_Obj *const objv[])
{
    int i, len;
    unsigned char *src, *dst;
    Tcl_Obj *obj;
    
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "string");
	return TCL_ERROR;
    }
    
    src = Tcl_GetByteArrayFromObj(objv[1], &len);
    obj = Tcl_NewByteArrayObj(NULL, len*2);
    dst = Tcl_GetByteArrayFromObj(obj, NULL);
    for (i = 0; i < len; i++) {
	dst[i*2] = src[i] >> 4;
	dst[i*2+1] = src[i] & 0xf;
    }
    for (i = 0; i < len*2; i++) {
	if (dst[i] < 10) {
	    dst[i] += '0';
	} else {
	    dst[i] += ('a'-10);
	}
    }
    Tcl_SetObjResult(interp, obj);
    return TCL_OK;
}

static int
dupCmd(ClientData cd, Tcl_Interp *interp,
       int objc, Tcl_Obj *const objv[])
{
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "obj");
	return TCL_ERROR;
    }

    Tcl_SetObjResult(interp, Tcl_DuplicateObj(objv[1]));
    return TCL_OK;
}

/* Equivalent to [concat {*}$ls] */
static int
lflattenCmd(ClientData cd, Tcl_Interp *interp,
            int objc, Tcl_Obj *const objv[])
{
    int i, j, len, eltLen, total;
    Tcl_Obj *res, **elts, **eltVals;

    if (objc != 2) {
      Tcl_WrongNumArgs(interp, 1, objv, "list");
      return TCL_ERROR;
    }

    if (Tcl_ListObjGetElements(interp, objv[1], &len, &elts) == TCL_ERROR)
        return TCL_ERROR;

    total = 0;
    for (i = 0; i < len; i++) {
        if (Tcl_ListObjLength(interp, elts[i], &eltLen) == TCL_ERROR)
            return TCL_ERROR;
        total += eltLen;
    }

    res = Tcl_NewListObj(total, NULL);

    for (i = 0; i < len; i++) {
        Tcl_ListObjGetElements(NULL, elts[i], &eltLen, &eltVals);
        for (j = 0; j < eltLen; j++) {
            Tcl_ListObjAppendElement(NULL, res, eltVals[j]);
        }
    }

    Tcl_SetObjResult(interp, res);
    return TCL_OK;
}

static int
bytearrayCmd(ClientData cd, Tcl_Interp *interp,
             int objc, Tcl_Obj *const objv[])
{
    unsigned char *buf;
    int len;
    Tcl_Obj *obj;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "value");
        return TCL_ERROR;
    }

    obj = objv[1];
    buf = Tcl_GetByteArrayFromObj(obj, &len);
    if (obj->bytes != NULL) {
        /* Make sure it's a "pure" byte array. */
        if (Tcl_IsShared(obj)) {
            obj = Tcl_NewByteArrayObj(buf, len);
        } else {
            /* Toss invalid characters */
            Tcl_InvalidateStringRep(obj);
        }
    }
    Tcl_SetObjResult(interp, obj);
    return TCL_OK;
}

/* XXX: this needs to be renamed. It's essentially [encoding convertto
   utf-8]. */
static int
dupBytesCmd(ClientData cd, Tcl_Interp *interp,
            int objc, Tcl_Obj *const objv[])
{
    char *p;
    int len;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "value");
        return TCL_ERROR;
    }

    p = Tcl_GetStringFromObj(objv[1], &len);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj((const unsigned char *)p, len));
    return TCL_OK;
}

static int
findBytesCmd(ClientData cd, Tcl_Interp *interp,
             int objc, Tcl_Obj *const objv[])
{
    unsigned char *hp, *np, *p, *end;
    int hLen, nLen, result;
    
    if (!(objc == 3 || objc == 4)) {
        Tcl_WrongNumArgs(interp, 1, objv, "needle haystack ?start?");
        return TCL_ERROR;
    }

    np = Tcl_GetByteArrayFromObj(objv[1], &nLen);
    p = hp = Tcl_GetByteArrayFromObj(objv[2], &hLen);
    end = hp + hLen;
    
    if (objc == 4) {
        int start;
        if (Tcl_GetIntFromObj(interp, objv[3], &start) != TCL_OK) {
            return TCL_ERROR;
        }
        p += start;
    }

    result = -1;
    if (hLen > 0 && nLen > 0) {
        while (p+nLen <= end) {
            if (p[0] == np[0] && !memcmp(p, np, nLen)) {
                result = p-hp;
                break;
            }
            p++;
        }
    }
    
    Tcl_SetObjResult(interp, Tcl_NewIntObj(result));
    return TCL_OK;
}

static int
byteRangeCmd(ClientData cd, Tcl_Interp *interp,
             int objc, Tcl_Obj *const objv[])
{
    unsigned char *bytes;
    int start, end, origLen;
    Tcl_Obj *obj;

    if (objc != 4) {
        Tcl_WrongNumArgs(interp, 1, objv, "byteArray start end");
        return TCL_ERROR;
    }
    
    obj = objv[1];
    Tcl_GetByteArrayFromObj(obj, &origLen);
    if (TclGetIntForIndex(interp, objv[2], origLen-1, &start) != TCL_OK ||
        TclGetIntForIndex(interp, objv[3], origLen-1, &end) != TCL_OK) {
        return TCL_ERROR;
    }
    bytes = Tcl_GetByteArrayFromObj(obj, NULL);
    end++; /* Switch to inclusive-exclusive indexing */
    if (start < 0)
        start = 0;
    if (end > origLen)
        end = origLen;
    
    if (Tcl_IsShared(obj)) {
        obj = Tcl_NewByteArrayObj(bytes+start, end-start);
    } else {
        memmove(bytes, bytes+start, end-start);
        /* No API available to truncate byte arrays. */
        struct {
            int used;
            int allocated;
        } *intRep = obj->internalRep.twoPtrValue.ptr1;
        intRep->used = end-start;
        Tcl_InvalidateStringRep(obj);
    }
    
    Tcl_SetObjResult(interp, obj);
    return TCL_OK;
}

/* See html::append_escaped_text. If non-Latin languages are to be
 * supported, all of that functionality should migrate to C-side,
 * using binary search for the escapes. This version punts on
 * everything above 0x7f. */
static int
htmlEntityHelperCmd(ClientData cd, Tcl_Interp *interp,
                    int objc, Tcl_Obj *const objv[])
{
    char *p, *end;
    int len, i;
    Tcl_UniChar u;
    Tcl_Obj *ls = NULL;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "string");
        return TCL_ERROR;
    }
    p = Tcl_GetStringFromObj(objv[1], &len);
    end = p + len;
    i = 0;
    while (p < end) {
        p += Tcl_UtfToUniChar(p, &u);
        if (u > 0x7f || u == 34 || u == 38 || u == 39 ||
            u == 60 || u == 62) {
            if (ls == NULL) {
                ls = Tcl_NewObj();
            }
            Tcl_ListObjAppendElement(NULL, ls, Tcl_NewIntObj(i));
        }
        i++;
    }
    if (ls != NULL) {
        Tcl_SetObjResult(interp, ls);
    }
    return TCL_OK;
}

static int
escapeTinydnsCmd(ClientData cd, Tcl_Interp *interp,
		 int objc, Tcl_Obj *const objv[])
{
    char *p, *q;
    int len, i, num;
    Tcl_Obj *res;
    
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "string");
	return TCL_ERROR;
    }
    p = Tcl_GetStringFromObj(objv[1], &len);
    num = 0;
    for (i = 0; i < len; i++) {
	if (p[i] == ':' || p[i] == '\n' || p[i] > 0x7f) {
	    num++;
	}
    }
    if (num == 0) {
	Tcl_SetObjResult(interp, objv[1]);
    } else {
	res = Tcl_NewObj();
	res->length = len + num*3 + 1;
	q = res->bytes = ckalloc(res->length);
	for (i = 0; i < len; i++) {
	    if (p[i] == ':' || p[i] == '\n' || p[i] > 0x7f) {
		*q++ = '\\';
		*q++ = '0' + (p[i] >> 6);
		*q++ = '0' + ((p[i] >> 3) & 7);
		*q++ = '0' + (p[i] & 7);
	    } else {
		*q++ = p[i];
	    }
	}
	*q = '\0';
	Tcl_SetObjResult(interp, res);
    }
    return TCL_OK;
}

Tcl_Obj *
Tcl_NewStringObjWithCharLength(const char *str, int size,
			       int numChars)
{
    Tcl_Obj *obj;
    extern const Tcl_ObjType tclStringType;

    obj = Tcl_NewStringObj(str, size);
    Tcl_ConvertToType(NULL, obj, &tclStringType);
    *((int *)(obj)->internalRep.twoPtrValue.ptr1) = numChars;
    return obj;
}

static int
loadCommandsCmd(ClientData cd, Tcl_Interp *interp,
                int objc, Tcl_Obj *const objv[])
{
    Tcl_Interp *target;

    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "interp");
        return TCL_ERROR;
    }
    target = Tcl_GetSlave(interp, Tcl_GetString(objv[1]));
    if (!target)
        return TCL_ERROR;

    loadCommands(target);
    return TCL_OK;
}

static void
loadCommands(Tcl_Interp *interp)
{
    Sqlite_Init(interp);
    Udp_Init(interp);
    lazyInit(interp);
    byteOpInit(interp);
    pdfInit(interp);
    posixInit(interp);
    sslInit(interp);
    memoInit(interp, "memo");
    hashInit(interp);
    unixSocketInit(interp);

    Tcl_Eval(interp,
	     "proc history args {}\n"
	     "proc eval_in {ns} {\n"
	     "  if {[uplevel 1 {namespace current}] ne $ns} {error $ns {} EVAL_IN}\n"
	     "}\n"
	     "proc source/in {file} {\n"
	     "  try {uplevel #0 [list source $file]} trap EVAL_IN ns \\\n"
	     "      {namespace eval $ns [list source $file]}\n"
	     "}\n");
    Tcl_CreateObjCommand(interp, "hex", hexCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "hmac_sha1", hmacSha1Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "dup", dupCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "lflatten", lflattenCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "bytearray", bytearrayCmd, NULL, NULL);
    /*Tcl_CreateObjCommand(interp, "int->bin", intBinCmd, NULL, NULL);*/
    Tcl_CreateObjCommand(interp, "dup_bytes", dupBytesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "find_bytes", findBytesCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "byte_range", byteRangeCmd, NULL, NULL);
    Tcl_NRCreateCommand(interp, "tree", treeCmd, treeNRCmd, NULL, NULL);
    Tcl_NRCreateCommand(interp, "treeset", treesetCmd, treesetNRCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, ":", recordObjCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "bitset", bitsetCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "cursor", cursorCmd, NULL, NULL);
    Tcl_NRCreateCommand(interp, "lcase", lcaseCmd, lcaseNRCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "parse_command", parseCommandCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "parse_braces", parseQuotedCmd, (ClientData)Tcl_ParseBraces, NULL);
    Tcl_CreateObjCommand(interp, "parse_quoted_string", parseQuotedCmd, (ClientData)Tcl_ParseQuotedString, NULL);
    Tcl_CreateObjCommand(interp, "parse_var_name", parseVarNameCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "def_packed", defPackedCmd, NULL, NULL);

    Tcl_CreateObjCommand(interp, "regex::match", regexMatchCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "regex::sub", regexSubCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "json::parse", jsonParseCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "add_fraction_collate", addFractionCollateCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "lru", lruCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "damt", damtCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "fluid", fluidCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "defcmd", defCmdCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "defconst", defConstCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "_refcount", refCountCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "_eval_direct", evalDirectCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "_html_entity_helper", htmlEntityHelperCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "_escape_tinydns", escapeTinydnsCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "load_commands", loadCommandsCmd, NULL, NULL);
}

static int
init(Tcl_Interp *interp)
{
    loadCommands(interp);
    return TCL_OK;
}

#ifndef NO_SIGINT_HANDLER
static int
doExit(Tcl_Event *evPtr, int flags)
{
    Tcl_Eval(rootInterp, "atexit");
    Tcl_Exit(0);
}

static void
exitSigHandler(int sig)
{
    static Tcl_Event ev = {doExit, NULL};
    Tcl_QueueEvent(&ev, TCL_QUEUE_HEAD);
}
#endif

int
main(int argc, char **argv)
{
#ifndef NO_SIGINT_HANDLER
    struct sigaction sig;

    /* Set up SIGINT/SIGTERM handler */
    sig.sa_handler = exitSigHandler;
    sig.sa_flags = 0;
    sigemptyset(&sig.sa_mask);
    sigaction(SIGINT, &sig, NULL);
    sigaction(SIGTERM, &sig, NULL);
#endif

    rootInterp = Tcl_CreateInterp();
    Tcl_MainEx(argc, argv, init, rootInterp);
    return 0;
}
