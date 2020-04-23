#include <stdlib.h>
#include <tcl.h>

typedef struct Memo {
    Tcl_Obj *orig;
    Tcl_Obj *value;
    int cmdListLength;
    Tcl_Obj *cmdList[1];
} Memo;

static void freeMemoRep(Tcl_Obj *obj);
static void dupMemoRep(Tcl_Obj *src, Tcl_Obj *dup);
static void updateMemoString(Tcl_Obj *obj);

static const Tcl_ObjType memoType = {
    "memo",
    freeMemoRep,
    dupMemoRep,
    updateMemoString,
    NULL
};

static int epoch = 0;

static Memo **
memoLoc(Tcl_Obj *obj)
{
    return (Memo **)&obj->internalRep.ptrAndLongRep.ptr;
}

static long *
epochLoc(Tcl_Obj *obj)
{
    return (long *)&obj->internalRep.ptrAndLongRep.value;
}

static void
freeMemoRep(Tcl_Obj *obj)
{
    int i;
    
    Memo *memo = *memoLoc(obj);
    if (memo->orig) Tcl_DecrRefCount(memo->orig);
    Tcl_DecrRefCount(memo->value);
    for (i = 0; i < memo->cmdListLength; i++) {
        Tcl_DecrRefCount(memo->cmdList[i]);
    }
    ckfree(memo);
    obj->typePtr = NULL;
}

static Memo *
allocMemo(Tcl_Obj *orig, Tcl_Obj *value, int cmdListLength, Tcl_Obj **cmdList)
{
    Memo *m;
    int i;
    
    m = ckalloc(sizeof(Memo) + sizeof(Tcl_Obj *)*(cmdListLength-1));
    m->orig = orig;
    if (orig) Tcl_IncrRefCount(orig);
    m->value = value;
    Tcl_IncrRefCount(value);
    m->cmdListLength = cmdListLength;
    for (i = 0; i < cmdListLength; i++) {
        m->cmdList[i] = cmdList[i];
        Tcl_IncrRefCount(cmdList[i]);
    }
    return m;
}


static void
dupMemoRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    Memo *srcMemo;

    srcMemo = *memoLoc(src);
    *memoLoc(dst) = allocMemo(srcMemo->orig, srcMemo->value, srcMemo->cmdListLength,
                              srcMemo->cmdList);
    *epochLoc(dst) = *epochLoc(src);
    dst->typePtr = &memoType;
}

static void updateMemoString(Tcl_Obj *obj)
{
    Memo *memo = *memoLoc(obj);
    Tcl_GetString(memo->orig);
    obj->bytes = memo->orig->bytes;
    obj->length = memo->orig->length;
    memo->orig->bytes = NULL;
}

static int
memoPostEval(ClientData cd[], Tcl_Interp *interp, int result)
{
    Tcl_Obj *cmdList, *obj, **objv, *orig;
    int objc;
    Memo *memo;

    cmdList = (Tcl_Obj *)cd[0];
    obj = (Tcl_Obj *)cd[1];
    
    if (result == TCL_OK) {
        Tcl_ListObjGetElements(NULL, cmdList, &objc, &objv);
        orig = obj->bytes ? NULL : Tcl_DuplicateObj(obj);
        memo = allocMemo(orig, Tcl_GetObjResult(interp), objc-1, objv);
        if (obj->typePtr && obj->typePtr->freeIntRepProc) {
            obj->typePtr->freeIntRepProc(obj);
        }
        *memoLoc(obj) = memo;
        *epochLoc(obj) = epoch;
        obj->typePtr = &memoType;
    }
    Tcl_DecrRefCount(cmdList);
    return result;
}

static int
memoNRCmd(ClientData cd, Tcl_Interp *interp,
          int objc, Tcl_Obj *const objv[])
{
    int i;
    Tcl_Obj *cmdList;
    Memo *memo;

    if (objc < 2) {
        return TCL_OK;
    }

    if (objv[objc-1]->typePtr != &memoType || *epochLoc(objv[objc-1]) != epoch)
        goto calc;
    memo = *memoLoc(objv[objc-1]);
    if (memo->cmdListLength != objc-2) goto calc;
    for (i = 0; i < memo->cmdListLength; i++) {
        if (memo->cmdList[i] != objv[i+1]) goto calc;
    }
    Tcl_SetObjResult(interp, memo->value);
    return TCL_OK;

calc:
    cmdList = Tcl_NewListObj(objc-1, &objv[1]);
    Tcl_IncrRefCount(cmdList);
    Tcl_NRAddCallback(interp, memoPostEval, (ClientData)cmdList,
                      (ClientData)objv[objc-1], NULL, NULL);
    return Tcl_NREvalObj(interp, cmdList, 0);
}

static int
memoCmd(ClientData cd, Tcl_Interp *interp,
        int objc, Tcl_Obj *const objv[])
{
    return Tcl_NRCallObjProc(interp, memoNRCmd, cd, objc, objv);
}

static int
invalidateCmd(ClientData cd, Tcl_Interp *interp,
              int objc, Tcl_Obj *const objv[])
{
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, NULL);
        return TCL_ERROR;
    }
    epoch++;
    return TCL_OK;
}

void
memoInit(Tcl_Interp *interp, char *cmdName)
{
    Tcl_NRCreateCommand(interp, cmdName, memoCmd, memoNRCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "_invalidate_memo", invalidateCmd, NULL, NULL);
}
