#include <tcl.h>
#include <string.h>
#include "qdsh.h"

static void updateDamtStringRep(Tcl_Obj *);

const Tcl_ObjType damtType = {
    "damt",
    freeCellInternalRep,
    dupCellInternalRep,
    updateDamtStringRep,
    NULL
};

#define OBJ_DOLLAR(o) ((o)->internalRep.ptrAndLongRep.ptr)
#define OBJ_CENT(o) ((o)->internalRep.ptrAndLongRep.value)

static int
parseDamt(Tcl_Interp *interp, char *str, Tcl_Obj **dollarOut, unsigned long *centOut)
{
    enum State {
        S_START, S_DOLLAR_SIGN, S_MINUS, S_ZERO, S_DOLLAR, S_CENT1, S_CENT2, S_DONE
    } state = S_START;
    char *p;
    const char *dollarStart = NULL;
    Tcl_Obj *dollarObj = NULL;
    unsigned long centAmt = 0;
    
    for (p = str; *p; p++) {
        switch (state) {
        case S_START:
            if (*p != '$') goto bad;
            state = S_DOLLAR_SIGN;
            break;
        case S_DOLLAR_SIGN:
            if (*p == '-') {
                centAmt = 100;
                state = S_MINUS;
                break;
            }
            /* Fall through */
        case S_MINUS:
            dollarStart = p;
            if (*p == '0') state = S_ZERO;
            else if (*p >= '1' && *p <= '9') state = S_DOLLAR;
            else goto bad;
            break;
        case S_DOLLAR:
            if (*p >= '0' && *p <= '9') break;
            /* Fall through */
        case S_ZERO:
            if (*p != '.') goto bad;
            dollarObj = Tcl_NewStringObj(dollarStart, p-dollarStart);
            state = S_CENT1;
            break;
        case S_CENT1:
            if (*p < '0' || *p > '9') goto bad;
            centAmt += (*p-'0')*10;
            state = S_CENT2;
            break;
        case S_CENT2:
            if (*p < '0' || *p > '9') goto bad;
            centAmt += *p-'0';
            state = S_DONE;
            break;
        case S_DONE:
            goto bad;
        }
    }

    /* Rule out trailing characters and "$-0.00" */
    if (state != S_DONE ||
        (str[1] == '-' && str[2] == '0' && str[4] == '0' && str[5] == '0')) {
bad:
        if (dollarObj) {
            Tcl_DecrRefCount(dollarObj);
        }
	Tcl_SetErrorCode(interp, "DAMT", "FORMAT", NULL);
	return errorMsg(interp, "bad damt");
    }

    *dollarOut = dollarObj;
    *centOut = centAmt;
    return TCL_OK;
}

static int
getDamtFromObj(Tcl_Interp *interp, Tcl_Obj *obj, Tcl_Obj **dollarOut,
               unsigned long *centOut)
{
    Tcl_Obj *dollarObj;
    unsigned long centAmt;
    
    if (obj->typePtr != &damtType) {
        if (parseDamt(interp, Tcl_GetString(obj), &dollarObj, &centAmt) != TCL_OK)
	    return TCL_ERROR;
        freeIntRep(obj);
        Tcl_IncrRefCount(dollarObj);
        OBJ_DOLLAR(obj) = dollarObj;
        OBJ_CENT(obj) = centAmt;
        obj->typePtr = &damtType;
    }
    *dollarOut = OBJ_DOLLAR(obj);
    *centOut = OBJ_CENT(obj);
    return TCL_OK;
}

static void
formatAmount(Tcl_Obj *dollarAmt, long centAmt, Tcl_DString *ds)
{
    char *dollarRep;
    char centRep[3];
    int dollarLen;
    
    if (centAmt >= 100) {
        Tcl_DStringAppend(ds, "-", 1);
        centAmt -= 100;
    }
    dollarRep = Tcl_GetStringFromObj(dollarAmt, &dollarLen);
    centRep[0] = '.';
    centRep[1] = (centAmt / 10) + '0';
    centRep[2] = (centAmt % 10) + '0';
    Tcl_DStringAppend(ds, dollarRep, dollarLen);
    Tcl_DStringAppend(ds, centRep, 3);
}

static void
updateDamtStringRep(Tcl_Obj *obj)
{
    Tcl_DString ds;

    Tcl_DStringInit(&ds);
    Tcl_DStringAppend(&ds, "$", 1);
    formatAmount(OBJ_DOLLAR(obj), OBJ_CENT(obj), &ds);
    obj->length = Tcl_DStringLength(&ds);
    obj->bytes = ckalloc(obj->length+1);
    memcpy(obj->bytes, Tcl_DStringValue(&ds), obj->length);
    obj->bytes[obj->length] = '\0';
    Tcl_DStringFree(&ds);
}

static Tcl_Obj *
commaDollar(Tcl_Obj *dollarObj)
{
    int len, newLen;
    char *origStr, *dst, *src;
    Tcl_Obj *res;

    origStr = Tcl_GetStringFromObj(dollarObj, &len);
    if (len <= 3)
	return dollarObj;

    /* Need to insert at least one comma. Allocate new object. */
    newLen = len + ((len-1)/3);
    res = Tcl_NewObj();
    Tcl_SetObjLength(res, newLen);

    /* Copy numbers over while inserting commas. */
    src = origStr + len;
    dst = Tcl_GetStringFromObj(res, NULL) + newLen;
    for (;;) {
	*--dst = *--src; if (src == origStr) break;
	*--dst = *--src; if (src == origStr) break;
	*--dst = *--src; if (src == origStr) break;
	*--dst = ',';
    }
    return res;
}

int
damtCmd(ClientData cd, Tcl_Interp *interp,
        int objc, Tcl_Obj *const objv[])
{
    static const char *const options[] = {
        "from_cents", "to_cents",     "from_number", "display",
	"show",       "comma_dollar", "_create",     "_parse",
        NULL
    };
    enum option {
	OPT_FROM_CENTS, OPT_TO_CENTS,     OPT_FROM_NUMBER, OPT_DISPLAY,
        OPT_SHOW,       OPT_COMMA_DOLLAR, OPT_CREATE,      OPT_PARSE
    };
    int index;
    Tcl_Obj *cmdLine[2], *dollarObj, *elts[2];
    unsigned long centAmt;
    static struct {
        char *implCmd, *argName;
        Tcl_Obj *cmdObj;
    }  tclCmds[] = {
        /* OPT_FROM_CENTS */ {"::damt::from_cents", "cents", NULL},
        /* OPT_TO_CENTS */ {"::damt::to_cents", "damt", NULL},
        /* OPT_FROM_NUMBER */ {"::damt::from_number", "number", NULL},
	/* OPT_DISPLAY */ {"::damt::display", "damt", NULL}
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
    case OPT_FROM_CENTS:
    case OPT_TO_CENTS:
    case OPT_FROM_NUMBER:
    case OPT_DISPLAY:
        if (objc != 3) {
            Tcl_WrongNumArgs(interp, 2, objv, tclCmds[index].argName);
            return TCL_ERROR;
        }
        if (!tclCmds[index].cmdObj) {
            tclCmds[index].cmdObj = Tcl_NewStringObj(tclCmds[index].implCmd, -1);
            Tcl_IncrRefCount(tclCmds[index].cmdObj);
        }
        cmdLine[0] = tclCmds[index].cmdObj;
        cmdLine[1] = objv[2];
        return Tcl_EvalObjv(interp, 2, cmdLine, 0);
    case OPT_SHOW:
    case OPT_COMMA_DOLLAR:
	if (objc != 3) {
	    Tcl_WrongNumArgs(interp, 2, objv, "damt");
	    return TCL_ERROR;
	}
	if (getDamtFromObj(interp, objv[2], &dollarObj, &centAmt) != TCL_OK)
	    return TCL_ERROR;
	if (index == OPT_SHOW) {
	    Tcl_DString ds;

	    Tcl_DStringInit(&ds);
	    formatAmount(dollarObj, centAmt, &ds);
	    Tcl_DStringResult(interp, &ds); /* frees ds */
	} else {
	    Tcl_SetObjResult(interp, commaDollar(dollarObj));
	}
	return TCL_OK;
    case OPT_CREATE:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "dollars cents");
            return TCL_ERROR;
        } else {
            long centAmt;
            Tcl_Obj *res;

            if (Tcl_GetLongFromObj(interp, objv[3], &centAmt) != TCL_OK) {
                return TCL_ERROR;
            }
            res = Tcl_NewObj();
            Tcl_InvalidateStringRep(res);
            res->typePtr = &damtType;
            OBJ_DOLLAR(res) = objv[2];
            Tcl_IncrRefCount(objv[2]);
            OBJ_CENT(res) = centAmt;
            Tcl_SetObjResult(interp, res);
        }
        return TCL_OK;
    case OPT_PARSE:
        if (objc != 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "damt");
            return TCL_ERROR;
        }
	if (getDamtFromObj(interp, objv[2], &dollarObj, &centAmt) != TCL_OK)
	    return TCL_ERROR;
	elts[0] = dollarObj;
	elts[1] = Tcl_NewLongObj(centAmt);
	Tcl_SetObjResult(interp, Tcl_NewListObj(2, elts));
        return TCL_OK;
    }

    /* Not reached */
    return TCL_OK;
}
