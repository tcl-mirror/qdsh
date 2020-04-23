#include <tcl.h>
#include "qdsh.h"
#include "cursor.h"

static Tcl_Parse parseInfo;

static int
parseFailResult(Tcl_Interp *interp, Tcl_Obj *curObj)
{
    Tcl_Obj *errorArray[2];

    errorArray[0] = curObj;
    errorArray[1] = Tcl_GetObjResult(interp);
    Tcl_SetObjResult(interp, Tcl_NewListObj(2, errorArray));
    Tcl_SetErrorCode(interp, "PARSE", "FAIL", NULL);
    return TCL_ERROR;
}

static int
advanceCursorTo(Tcl_Interp *interp, Tcl_Obj *varObj, Tcl_Obj *curObj,
		Cursor *cur, const char *end)
{
    const char *str;
    int strLen, numChars;

    str = Tcl_GetStringFromObj(cur->strObj, &strLen);
    if (end < str || end > str + strLen) {
	Tcl_Panic("out of range");
    }
    numChars = Tcl_NumUtfChars(str + cur->bytePos, end - (str + cur->bytePos));
    if (Tcl_IsShared(curObj)) {
	return Tcl_ObjSetVar2(interp, varObj, NULL,
			      newCursorObj(cur->strObj, end - str,
					   cur->charPos + numChars),
			      TCL_LEAVE_ERR_MSG) ? TCL_OK : TCL_ERROR;
    }
    
    cur->bytePos = end - str;
    cur->charPos += numChars;
    assignObjLoc(&cur->posObj, NULL);
    assignObjLoc(&cur->auxObj, NULL);
    Tcl_InvalidateStringRep(curObj);
    return TCL_OK;
}
    
int
parseCommandCmd(ClientData cd, Tcl_Interp *interp,
                int objc, Tcl_Obj *const objv[])
{
    const char *str;
    int strLen, ret, nested;
    Cursor *cur;
    Tcl_Obj *curObj;

    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "nested cursorVar");
	return TCL_ERROR;
    }
    if (Tcl_GetBooleanFromObj(interp, objv[1], &nested) == TCL_ERROR ||
	!(curObj = Tcl_ObjGetVar2(interp, objv[2], NULL, TCL_LEAVE_ERR_MSG)) ||
	!(cur = getCursorFromObj(interp, curObj))) {
	return TCL_ERROR;
    }

    str = Tcl_GetStringFromObj(cur->strObj, &strLen);
    if (Tcl_ParseCommand(interp, str + cur->bytePos, strLen - cur->bytePos,
			 nested, &parseInfo) == TCL_ERROR) {
	return parseFailResult(interp, curObj);
    }

    ret = advanceCursorTo(interp, objv[2], curObj, cur,
			  parseInfo.commandStart + parseInfo.commandSize);
    if (ret == TCL_OK) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(parseInfo.commandStart,
						  parseInfo.commandSize));
    }
    Tcl_FreeParse(&parseInfo);
    return ret;
}

int
parseVarNameCmd(ClientData cd, Tcl_Interp *interp,
                int objc, Tcl_Obj *const objv[])
{
    const char *str;
    Tcl_Obj *curObj;
    int strLen, ret;
    Cursor *cur;

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "cursorVar");
	return TCL_ERROR;
    }
    if (!(curObj = Tcl_ObjGetVar2(interp, objv[1], NULL, TCL_LEAVE_ERR_MSG)) ||
	!(cur = getCursorFromObj(interp, curObj))) {
	return TCL_ERROR;
    }
    
    str = Tcl_GetStringFromObj(cur->strObj, &strLen);
    if (Tcl_ParseVarName(interp, str + cur->bytePos, strLen - cur->bytePos,
			 &parseInfo, 0) == TCL_ERROR) {
	return parseFailResult(interp, curObj);
    }

    ret = advanceCursorTo(interp, objv[1], curObj, cur,
			  parseInfo.tokenPtr[0].start +
			  parseInfo.tokenPtr[0].size);
    if (ret == TCL_OK) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(parseInfo.tokenPtr[0].start,
						  parseInfo.tokenPtr[0].size));
    }
    Tcl_FreeParse(&parseInfo);
    return ret;
}

int parseQuotedCmd(ClientData cd, Tcl_Interp *interp,
                   int objc, Tcl_Obj *const objv[])
{
    const char *str, *end;
    int strLen, ret;
    typedef int (*Fun)(Tcl_Interp *, const char *, int, Tcl_Parse *, int, const char **);
    Cursor *cur;
    Tcl_Obj *curObj;

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "cursorVar");
	return TCL_ERROR;
    }

    if (!(curObj = Tcl_ObjGetVar2(interp, objv[1], NULL, TCL_LEAVE_ERR_MSG)) ||
	!(cur = getCursorFromObj(interp, curObj))) {
	return TCL_ERROR;
    }

    str = Tcl_GetStringFromObj(cur->strObj, &strLen) + cur->bytePos;
    if (((Fun)cd)(interp, str, strLen - cur->bytePos,
		  &parseInfo, 0, &end) == TCL_ERROR) {
        return parseFailResult(interp, curObj);
    }

    ret = advanceCursorTo(interp, objv[1], curObj, cur, end);
    if (ret == TCL_OK && end - str >= 2) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj(str+1, end-str-2));
    }
    Tcl_FreeParse(&parseInfo);
    return TCL_OK;
}
