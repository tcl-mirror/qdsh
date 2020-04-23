#include <tcl.h>
/*#include <tclStringRep.h>*/
#include <string.h>
#include "qdsh.h"
#include "cursor.h"

/*extern const Tcl_ObjType tclStringType;*/

static void freeCursorIntRep(Tcl_Obj *);
static void dupCursorIntRep(Tcl_Obj *, Tcl_Obj *);
static void updateStringOfCursor(Tcl_Obj *);
    
static Tcl_ObjType cursorType = {
    "cursor",
    freeCursorIntRep,
    dupCursorIntRep,
    updateStringOfCursor,
    NULL
};

static void
freeCursor(Cursor *cur)
{
    Tcl_DecrRefCount(cur->strObj);
    if (cur->posObj) Tcl_DecrRefCount(cur->posObj);
    if (cur->auxObj) Tcl_DecrRefCount(cur->auxObj);
    ckfree(cur);
}

static void
freeCursorIntRep(Tcl_Obj *obj)
{
    freeCursor((Cursor *)obj->internalRep.otherValuePtr);
    obj->typePtr = NULL;
}

static void
dupCursorIntRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    Cursor *srcCur, *dstCur;

    srcCur = src->internalRep.otherValuePtr;
    dstCur = ckalloc(sizeof(Cursor));
    memset(dstCur, 0, sizeof(Cursor));
    assignObjLoc(&dstCur->strObj, srcCur->strObj);
    assignObjLoc(&dstCur->posObj, srcCur->posObj);
    assignObjLoc(&dstCur->auxObj, srcCur->auxObj);
    dstCur->bytePos = srcCur->bytePos;
    dstCur->charPos = srcCur->charPos;
    dst->internalRep.otherValuePtr = dstCur;
    dst->typePtr = &cursorType;
}

static void
updateStringOfCursor(Tcl_Obj *obj)
{
    Cursor *cur;
    Tcl_Obj *ls, *objv[3];

    cur = obj->internalRep.otherValuePtr;
    objv[0] = cur->strObj;
    objv[1] = cur->posObj ? cur->posObj : Tcl_NewIntObj(cur->charPos);
    objv[2] = cur->auxObj;
    ls = Tcl_NewListObj(cur->auxObj ? 3 : 2, objv);
    takeStringRep(obj, ls);
    Tcl_DecrRefCount(ls);
}

static void
moveCursor(Cursor *cur, int index)
{
    int byteLength, newCharPos;
    const char *str, *end, *chPtr;

    str = Tcl_GetStringFromObj(cur->strObj, &byteLength);
    newCharPos = cur->charPos;
    chPtr = str + cur->bytePos;
    end = str + byteLength;

    if (newCharPos == index) {
        return;
    }

    if (newCharPos < index) {
        do {
            if (chPtr == end) break;
            chPtr = Tcl_UtfNext(chPtr);
            newCharPos++;
        } while (newCharPos < index);
    } else {
        do {
            if (chPtr == str) break;
            chPtr = Tcl_UtfPrev(chPtr, str);
            newCharPos--;
        } while (newCharPos > index);
    }

    if (newCharPos != cur->charPos) {
        assignObjLoc(&cur->posObj, NULL);
        assignObjLoc(&cur->auxObj, NULL);
        cur->charPos = newCharPos;
        cur->bytePos = chPtr - str;
    }
}

Cursor *
getCursorFromObj(Tcl_Interp *interp, Tcl_Obj *obj)
{
    int objc, charPos;
    Tcl_Obj **objv;
    Cursor *cur;
    /*String *str;*/

    if (obj->typePtr == &cursorType)
	return (Cursor *)obj->internalRep.otherValuePtr;
    
    if (Tcl_ListObjGetElements(interp, obj, &objc, &objv) != TCL_OK)
	return NULL;

    if (objc != 2 && objc != 3) {
        errorMsg(interp, "cursor must have two or three elements");
	return NULL;
    }

    if (Tcl_GetIntFromObj(interp, objv[1], &charPos) != TCL_OK)
        return NULL;

    cur = ckalloc(sizeof(Cursor));
    memset(cur, 0, sizeof(Cursor));
    assignObjLoc(&cur->strObj, objv[0]);

    /* We ensure a string rep exists here and from this point on
       assume that no one invalidates it, meaning we can access bytes
       without calling Tcl_GetString first. This assumption should be
       safe because we increment the ref count here and if script side
       still possess the string object it would be "shared". */
    (void) Tcl_GetString(cur->strObj);

#if 0
    if (cur->strObj->typePtr == &tclStringType) {
        str = GET_STRING(cur->strObj);
        cur->bytePos = str->byteCursor;
        cur->charPos = str->charCursor;
    } else {
#endif
	cur->bytePos = 0;
	cur->charPos = 0;
#if 0
    }
#endif

    moveCursor(cur, charPos);
    if (cur->charPos != charPos) {
        freeCursor(cur);
        errorMsg(interp, "character index out of range");
	return NULL;
    }
    
    if (objv[1]->bytes)
        assignObjLoc(&cur->posObj, objv[1]);
    if (objc == 3)
        assignObjLoc(&cur->auxObj, objv[2]);

    freeIntRep(obj);
    obj->internalRep.otherValuePtr = cur;
    obj->typePtr = &cursorType;
    return cur;
}

/* No validation of bytePos and charPos */
Tcl_Obj *
newCursorObj(Tcl_Obj *strObj, int bytePos, int charPos)
{
    Tcl_Obj *obj;
    Cursor *cur;

    cur = ckalloc(sizeof(Cursor));
    memset(cur, 0, sizeof(Cursor));
    assignObjLoc(&cur->strObj, strObj);
    cur->bytePos = bytePos;
    cur->charPos = charPos;
    obj = Tcl_NewObj();
    obj->typePtr = &cursorType;
    obj->internalRep.otherValuePtr = cur;
    Tcl_InvalidateStringRep(obj);
    return obj;
}

static int
incrOrConsume(Tcl_Interp *interp, Tcl_Obj *varName, Tcl_Obj *incr, int consume)
{
    Cursor *cur;
    int displacement = 1, allocated = 0, startBytePos, startCharPos;
    Tcl_Obj *varValue, *updated;

    varValue = Tcl_ObjGetVar2(interp, varName, NULL, 0);
    if (!varValue ||
        (incr && Tcl_GetIntFromObj(interp, incr, &displacement) == TCL_ERROR) ||
        !(cur = getCursorFromObj(interp, varValue))) {
        return TCL_ERROR;
    }
    
    if (Tcl_IsShared(varValue)) {
        varValue = Tcl_DuplicateObj(varValue);
        cur = varValue->internalRep.otherValuePtr;
        allocated = 1;
    }
    
    startBytePos = cur->bytePos;
    startCharPos = cur->charPos;
    moveCursor(cur, startCharPos + displacement);
    if (cur->charPos != startCharPos) {
	/* Update cursor variable */
	Tcl_InvalidateStringRep(varValue);
	updated = Tcl_ObjSetVar2(interp, varName, NULL, varValue, TCL_LEAVE_ERR_MSG);
	if (!updated) {
	    if (allocated) Tcl_DecrRefCount(varValue);
	    return TCL_ERROR;
	}

	/* Return string range if cursor moved forward and consume==1 */
	if (cur->charPos > startCharPos && consume) {
            Tcl_SetObjResult(interp,
                Tcl_NewStringObjWithCharLength(cur->strObj->bytes + startBytePos,
                                               cur->bytePos - startBytePos,
                                               cur->charPos - startCharPos));
        }
    } else if (allocated) {
	Tcl_DecrRefCount(varValue);
    }

    return TCL_OK;
}

static int
moveObj(Tcl_Interp *interp, Tcl_Obj **obj, int displacement, int *allocated)
{
    Cursor *cur;
    int oldPos;
    
    if (!(cur = getCursorFromObj(interp, *obj)))
        return TCL_ERROR;
    
    if (Tcl_IsShared(*obj)) {
        *obj = Tcl_DuplicateObj(*obj);
        cur = (*obj)->internalRep.otherValuePtr;
        if (allocated) *allocated = 1;
    }
    oldPos = cur->charPos;
    moveCursor(cur, oldPos + displacement);
    if (cur->charPos != oldPos) Tcl_InvalidateStringRep(*obj);
    return TCL_OK;
}

static int
cursorRange(Tcl_Interp *interp, Tcl_Obj *startObj, Tcl_Obj *endObj)
{
    Cursor *start, *end;
    char *str;
    int len;
    
    if (!(start = getCursorFromObj(interp, startObj))) {
        return TCL_ERROR;
    }
    if (endObj) {
        if (!(end = getCursorFromObj(interp, endObj)))
            return TCL_ERROR;
        if (start->strObj != end->strObj &&
            (start->strObj->length != end->strObj->length ||
             memcmp(start->strObj->bytes, end->strObj->bytes,
		    start->strObj->length) != 0))
            return errorMsg(interp, "strings don't match");

        if (start->bytePos < end->bytePos) {
            Tcl_SetObjResult(interp,
                             Tcl_NewStringObjWithCharLength(start->strObj->bytes + start->bytePos,
                                               end->bytePos - start->bytePos,
                                               end->charPos - start->charPos));
        }
        return TCL_OK;
    } else {
        str = Tcl_GetStringFromObj(start->strObj, &len);
	Tcl_SetObjResult(interp,
			 Tcl_NewStringObjWithCharLength(str + start->bytePos,
							len - start->bytePos,
							Tcl_GetCharLength(start->strObj) - start->charPos));
    }
    return TCL_OK;
}

int
cursorCmd(ClientData cd, Tcl_Interp *interp,
          int objc, Tcl_Obj *const objv[])
{
    Cursor *cur;
    int index, displacement;
    Tcl_Obj *res;
    static const char *const options[] = {
        "byte",    "consume", "end",   "eof",    "find", "incr",
        "index",   "move",    "range", "string", "pos",  "get_aux",
        "set_aux", NULL
    };
    enum option {
        OPT_BYTE, OPT_CONSUME, OPT_END,  OPT_EOF,   OPT_FIND,
        OPT_INCR, OPT_INDEX,   OPT_MOVE, OPT_RANGE, OPT_STRING,
        OPT_POS,  OPT_GET_AUX, OPT_SET_AUX
    };

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "subcommand ?arg ...?");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], options, "option", 0,
                            &index) != TCL_OK) {
        return TCL_ERROR;
    }

    switch ((enum option)index) {
    case OPT_CONSUME:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "cursor displacemet");
            return TCL_ERROR;
        }
        return incrOrConsume(interp, objv[2], objv[3], 1);
    case OPT_END:
    case OPT_EOF:
        if (objc != 3) {
badArgsCursor:            
            Tcl_WrongNumArgs(interp, 2, objv, "cursor");
            return TCL_ERROR;
        }
        if (!(cur = getCursorFromObj(interp, objv[2]))) {
            return TCL_ERROR;
        } else {
            int len;
            Tcl_GetStringFromObj(cur->strObj, &len);
            Tcl_SetObjResult(interp, (index == OPT_EOF) ?
                Tcl_NewBooleanObj(cur->bytePos == len) :
                             newCursorObj(cur->strObj, len, Tcl_GetCharLength(cur->strObj)));
            return TCL_OK;
        }
    case OPT_FIND:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "cursor substring");
            return TCL_ERROR;
        } else if (!(cur = getCursorFromObj(interp, objv[2]))) {
            return TCL_ERROR;
        } else {
            int charPos, subLen, strLen;
            char *sub, *str, *end;
            const char *p;

            str = Tcl_GetStringFromObj(cur->strObj, &strLen);
            end = str + strLen;
            sub = Tcl_GetStringFromObj(objv[3], &subLen);
            charPos = cur->charPos;
            if (subLen > 0) {
              Tcl_UniChar ch, firstChar;

              Tcl_UtfToUniChar(sub, &firstChar);
              for (p = str+cur->bytePos; p+subLen <= end; p = Tcl_UtfNext(p)) {
                Tcl_UtfToUniChar(p, &ch);
                if (ch == firstChar && Tcl_UtfNcmp(sub, p, subLen) == 0) {
                  res = newCursorObj(cur->strObj, p-str, charPos);
                  Tcl_SetObjResult(interp, Tcl_NewListObj(1, &res));
                  return TCL_OK;
                }
                charPos++;
              }
            }
            return TCL_OK;
        }
    case OPT_INCR:
        if (objc != 3 && objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "varName ?displacement?");
            return TCL_ERROR;
        }
        return incrOrConsume(interp, objv[2], objc == 3 ? NULL : objv[3], 0);
    case OPT_INDEX:
        if (objc != 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "cursor");
            return TCL_ERROR;
        }
        if (!(cur = getCursorFromObj(interp, objv[2]))) {
            return TCL_ERROR;
        }
        if (cur->bytePos < cur->strObj->length) {
            char *chPtr = cur->strObj->bytes + cur->bytePos;
            Tcl_SetObjResult(interp, Tcl_NewStringObjWithCharLength(chPtr, Tcl_UtfNext(chPtr)-chPtr, 1));
        }
        return TCL_OK;
    case OPT_MOVE:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "cursor displacemet");
            return TCL_ERROR;
        }
        res = objv[2];
        if (Tcl_GetIntFromObj(interp, objv[3], &displacement) == TCL_ERROR ||
            moveObj(interp, &res, displacement, NULL) == TCL_ERROR) {
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, res);
        return TCL_OK;
    case OPT_RANGE:
        if (objc != 3 && objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "start ?end?");
            return TCL_ERROR;
        }
        return cursorRange(interp, objv[2], objc == 3 ? NULL : objv[3]);
    case OPT_BYTE:
    case OPT_STRING:
    case OPT_POS:
        if (objc != 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "cursor");
            return TCL_ERROR;
        }
        if (!(cur = getCursorFromObj(interp, objv[2])))
            return TCL_ERROR;
        if (index == OPT_BYTE) {
            Tcl_SetObjResult(interp, Tcl_NewIntObj(cur->bytePos));
        } else if (index == OPT_STRING) {
#if 0
	    if (cur->strObj->typePtr == &tclStringType) {
		String *str = GET_STRING(cur->strObj);
		str->byteCursor = cur->bytePos;
		str->charCursor = cur->charPos;
	    }
#endif
	    Tcl_SetObjResult(interp, cur->strObj);
        } else {
            Tcl_SetObjResult(interp, Tcl_NewIntObj(cur->charPos));
        }
        return TCL_OK;
    case OPT_GET_AUX:
        if (objc != 3)
            goto badArgsCursor;
        if (!(cur = getCursorFromObj(interp, objv[2])))
            return TCL_ERROR;
        if (cur->auxObj)
            Tcl_SetObjResult(interp, cur->auxObj);
        return TCL_OK;
    case OPT_SET_AUX:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "cursor val");
            return TCL_ERROR;
        }
        if (!(cur = getCursorFromObj(interp, objv[2])))
            return TCL_ERROR;
        res = objv[2];
        if (cur->auxObj != objv[3]) {
            if (Tcl_IsShared(objv[2])) {
                res = Tcl_DuplicateObj(objv[2]);
                cur = res->internalRep.otherValuePtr;
            }
            assignObjLoc(&cur->auxObj, objv[3]);
            Tcl_InvalidateStringRep(res);
        }
        Tcl_SetObjResult(interp, res);
        return TCL_OK;
    }

    /* Not reached */
    return TCL_OK;
}

