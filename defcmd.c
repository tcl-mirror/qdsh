#include <string.h>
#include <tcl.h>
#include "qdsh.h"

typedef struct {
    int n;
    Tcl_Obj *ls[1];
} DefCmd;

static int
nrCallback(ClientData data[], Tcl_Interp *interp, int result)
{
    int i, len, prefix;
    Tcl_Obj **ls;

    len = (int)data[0];
    prefix = (int)data[1];
    ls = (Tcl_Obj **)data[2];

    for (i = prefix; i < len; i++) {
        Tcl_DecrRefCount(ls[i]);
    }
    ckfree(ls);
    return result;
}

static int
nrHandler(ClientData cd, Tcl_Interp *interp,
          int objc, Tcl_Obj *const objv[])
{
    int i, len;
    DefCmd *def;
    Tcl_Obj **ls, *obj;

    def = (DefCmd *)cd;
    len = objc - 1 + def->n;
    ls = ckalloc(sizeof(Tcl_Obj *) * len);
    for (i = 0; i < def->n; i++) {
        ls[i] = def->ls[i];
    }
    for (i = 0; i < objc-1; i++) {
        obj = objv[i+1];
        Tcl_IncrRefCount(obj);
        ls[def->n+i] = obj;
    }
    Tcl_NRAddCallback(interp, nrCallback, (ClientData)(intptr_t)len, (ClientData)(intptr_t)def->n,
                      (ClientData)ls, NULL);
    return Tcl_NREvalObjv(interp, len, ls, 0);
}

static int
handler(ClientData cd, Tcl_Interp *interp,
        int objc, Tcl_Obj *const objv[])
{
    return Tcl_NRCallObjProc(interp, nrHandler, cd, objc, objv);
}

static void
deleteDefCmd(ClientData cd)
{
    int i;
    DefCmd *def;

    def = (DefCmd *)cd;
    for (i = 0; i < def->n; i++)
        Tcl_DecrRefCount(def->ls[i]);
    ckfree(def);
}

int
defCmdCmd(ClientData cd, Tcl_Interp *interp,
          int objc, Tcl_Obj *const objv[])
{
    int len, i;
    DefCmd *def;
    
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmdName args ...");
        return TCL_ERROR;
    }
    len = objc-2;
    def = ckalloc(sizeof(DefCmd)+sizeof(Tcl_Obj *)*(len-1));
    def->n = len;
    for (i = 0; i < len; i++) {
        def->ls[i] = objv[i+2];
        Tcl_IncrRefCount(def->ls[i]);
    }
    return ckCreateCmd(interp, Tcl_GetString(objv[1]), handler, (ClientData)def, deleteDefCmd)
	? TCL_OK : TCL_ERROR;
}

static int
constHandler(ClientData cd, Tcl_Interp *interp,
	     int objc, Tcl_Obj *const objv[])
{
    if (objc != 1) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, (Tcl_Obj *)cd);
    return TCL_OK;
}

static void
deleteConstCmd(ClientData cd)
{
    Tcl_DecrRefCount((Tcl_Obj *)cd);
}
    
int
defConstCmd(ClientData cd, Tcl_Interp *interp,
	    int objc, Tcl_Obj *const objv[])
{
    Tcl_Obj *val;
    
    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "cmdName val");
	return TCL_ERROR;
    }
    val = objv[2];
    Tcl_IncrRefCount(val);
    if (ckCreateCmd(interp, Tcl_GetString(objv[1]), constHandler, (ClientData)val, deleteConstCmd))
	return TCL_OK;
    Tcl_DecrRefCount(val);
    return TCL_ERROR;
}
