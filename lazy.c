#include <string.h>
#include <tcl.h>

typedef struct {
    Tcl_Obj *orig;
    Tcl_Obj *saved;
} Promise;

#define GET_PROMISE(obj) ((Promise *)(&(obj)->internalRep.twoPtrValue))

static void freePromiseRep(Tcl_Obj *obj);
static void dupPromiseRep(Tcl_Obj *src, Tcl_Obj *dup);
static void updatePromiseString(Tcl_Obj *obj);

static const Tcl_ObjType promiseType = {
    "promise",
    freePromiseRep,
    dupPromiseRep,
    updatePromiseString,
    NULL
};

static void
freePromiseRep(Tcl_Obj *obj)
{
    Promise *promise = GET_PROMISE(obj);
    if (promise->orig) Tcl_DecrRefCount(promise->orig);
    Tcl_DecrRefCount(promise->saved);
    obj->typePtr = NULL;
}

static void
dupPromiseRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    Promise *srcPromise, *dstPromise;

    srcPromise = GET_PROMISE(src);
    dstPromise = GET_PROMISE(dst);
    dstPromise->orig = srcPromise->orig;
    dstPromise->saved = srcPromise->saved;
    dst->typePtr = &promiseType;
}

static void
updatePromiseString(Tcl_Obj *obj)
{
    Promise *promise = GET_PROMISE(obj);
    Tcl_GetString(promise->orig);
    obj->bytes = promise->orig->bytes;
    obj->length = promise->orig->length;
    promise->orig->bytes = NULL;
}

static int
forcePost(ClientData cd[], Tcl_Interp *interp, int result)
{
    Tcl_Obj *obj, *orig;
    Promise *promise;
    
    obj = (Tcl_Obj *)cd[0];
    if (result == TCL_OK) {
        /*
         * Tricky point: if obj has no string rep and we free the old
         * intrep of obj, we will not be able to come up with a string
         * if asked by Tcl.
         *
         * We could call Tcl_GetString now to ensure obj has a string
         * rep before converting to promise type, but obj is often a
         * command list containing large arguments, so we'd like to
         * avoid stringifying unless absolutely necessary.
         *
         * Solution: keep the old object around if it currently has no
         * string rep.
         */
        if (obj->bytes == NULL) {
            orig = Tcl_DuplicateObj(obj);
            Tcl_IncrRefCount(orig);
        } else {
            orig = NULL;
        }
        if (obj->typePtr && obj->typePtr->freeIntRepProc)
            obj->typePtr->freeIntRepProc(obj);
        promise = GET_PROMISE(obj);
        promise->orig = orig;
        promise->saved = Tcl_GetObjResult(interp);
        Tcl_IncrRefCount(promise->saved);
	obj->typePtr = &promiseType;
    }

    /* Match ref count increment in forceNRCmd */
    Tcl_DecrRefCount(obj);
    return result;
}

static int
forceNRCmd(ClientData cd, Tcl_Interp *interp,
	   int objc, Tcl_Obj *const objv[])
{
    Promise *promise;
    
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "promise");
	return TCL_ERROR;
    }

    if (objv[1]->typePtr == &promiseType) {
        promise = GET_PROMISE(objv[1]);
        Tcl_SetObjResult(interp, promise->saved);
	return TCL_OK;
    }

    Tcl_IncrRefCount(objv[1]);
    Tcl_NRAddCallback(interp, forcePost, (ClientData)objv[1], NULL, NULL, NULL);
    return Tcl_NREvalObj(interp, objv[1], 0);
}

static int
forceCmd(ClientData cd, Tcl_Interp *interp,
	 int objc, Tcl_Obj *const objv[])
{
    return Tcl_NRCallObjProc(interp, forceNRCmd, cd, objc, objv);
}

void
lazyInit(Tcl_Interp *interp) {
    Tcl_NRCreateCommand(interp, "force", forceCmd, forceNRCmd, NULL, NULL);
}
