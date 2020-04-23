#include <tcl.h>
#include "qdsh.h"

/* Ref count: one for command containing Ctx, and one for each
   activation. */
typedef struct {
    int refCount;
    Tcl_HashTable table;
} Ctx;

typedef struct Fluid Fluid;
typedef struct Saved Saved;

/* Ref count: one for fluid context, and one for each Tcl_Obj
   referencing the fluid. */
struct Fluid {
    int refCount;
    Ctx *ctx;
    Tcl_Obj *val;
    Saved *saved;
};

struct Saved {
    Tcl_Obj *val;
    Saved *prev;
};

typedef struct {
    int n;
    Fluid *ls[1];
} Activation;

static void freeFluidIntRep(Tcl_Obj *);
static void dupFluidIntRep(Tcl_Obj *, Tcl_Obj *);

static Tcl_ObjType fluidType = {
    "fluid",
    freeFluidIntRep,
    dupFluidIntRep,
    NULL, /* string rep */
    NULL, /* set from any */
};

static void
retainFluid(Fluid *fluid)
{
    fluid->refCount++;
}

static void
releaseFluid(Fluid *fluid)
{
    Saved *saved, *old;
    
    if (--fluid->refCount == 0) {
        if (fluid->val) {
            Tcl_DecrRefCount(fluid->val);
            saved = fluid->saved;
            while (saved) {
                Tcl_DecrRefCount(saved->val);
                old = saved;
                saved = saved->prev;
                ckfree(old);
            }
        }
        ckfree(fluid);
    }
}

static Fluid **
getFluidPtr(Tcl_Obj *obj)
{
    return (Fluid **)&obj->internalRep.otherValuePtr;
}

static void
freeFluidIntRep(Tcl_Obj *obj)
{
    releaseFluid(*getFluidPtr(obj));
    *getFluidPtr(obj) = NULL;
    obj->typePtr = NULL;
}

static void
dupFluidIntRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    *getFluidPtr(dst) = *getFluidPtr(src);
    dst->typePtr = &fluidType;
}

static void
retainCtx(Ctx *ctx)
{
    ctx->refCount++;
}

static void
releaseCtx(Ctx *ctx)
{
    Fluid *fluid;
    Tcl_HashEntry *entry;
    Tcl_HashSearch search;

    if (--ctx->refCount == 0) {
        entry = Tcl_FirstHashEntry(&ctx->table, &search);
        while (entry) {
            fluid = (Fluid *)Tcl_GetHashValue(entry);
            fluid->ctx = NULL;
            releaseFluid(fluid);
            entry = Tcl_NextHashEntry(&search);
        }
        Tcl_DeleteHashTable(&ctx->table);
        ckfree(ctx);
    }
}

static void
deleteCtx(ClientData cd)
{
    releaseCtx((Ctx *)cd);
}

static int
noSuchFluid(Tcl_Interp *interp, char *name)
{
    Tcl_SetObjResult(interp, Tcl_ObjPrintf("no such fluid %s", name));
    return TCL_ERROR;
}

static Fluid *
getFluidFromObj(Tcl_Obj *obj, Ctx *ctx, int create)
{
    char *name;
    Fluid *fluid;
    Tcl_HashEntry *entry;
    int isNew = 0;

    if (obj->typePtr == &fluidType &&
        (*getFluidPtr(obj))->ctx == ctx) {
        return *getFluidPtr(obj);
    }
    name = Tcl_GetString(obj);
    if (create) {
        entry = Tcl_CreateHashEntry(&ctx->table, name, &isNew);
        if (isNew) {
            fluid = ckalloc(sizeof(Fluid));
            fluid->refCount = 1; /* reference by Ctx */
            fluid->ctx = ctx;
            fluid->val = NULL;
            fluid->saved = NULL;
            Tcl_SetHashValue(entry, (ClientData)fluid);
        } else {
            fluid = (Fluid *)Tcl_GetHashValue(entry);
        }
    } else if ((entry = Tcl_FindHashEntry(&ctx->table, name))) {
        fluid = (Fluid *)Tcl_GetHashValue(entry);
    } else {
        return NULL;
    }
    
    freeIntRep(obj);
    obj->typePtr = &fluidType;
    *getFluidPtr(obj) = fluid;
    retainFluid(fluid);
    return fluid;
}

static int
fluidCleanup(ClientData data[], Tcl_Interp *interp, int result)
{
    int i;
    Activation *a;
    Fluid *fluid;
    Saved *old;

    a = (Activation *)data[0];
    for (i = 0; i < a->n; i++) {
        fluid = a->ls[i];
        Tcl_DecrRefCount(fluid->val);
        if (fluid->saved) {
            old = fluid->saved;
            fluid->val = old->val;
            fluid->saved = old->prev;
            ckfree(old);
        } else {
            fluid->val = NULL;
        }
    }
    releaseCtx(a->ls[0]->ctx); /* a->n >= 1 */
    ckfree(a);
    return result;
}

static int
fluidHandlerNRCmd(ClientData cd, Tcl_Interp *interp,
                  int objc, Tcl_Obj *const objv[])
{
    Ctx *ctx;
    Fluid *fluid;
    Saved *saved;
    int i, numBindings, index;
    Activation *a;
    static const char *const options[] = {
        "get", "let", NULL
    };
    enum option {
        OPT_GET, OPT_LET
    };

    ctx = (Ctx *)cd;
    if (objc < 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "cmd ?arg ...?");
	return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], options, "option", 0,
                            &index) != TCL_OK) {
        return TCL_ERROR;
    }
    switch ((enum option)index) {
    case OPT_GET:
        if (objc != 3 && objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "var ?default?");
            return TCL_ERROR;
        }
        if ((fluid = getFluidFromObj(objv[2], ctx, 0)) && fluid->val) {
            Tcl_SetObjResult(interp, fluid->val);
        } else if (objc == 3) {
            return noSuchFluid(interp, Tcl_GetString(objv[2]));
        } else {
            Tcl_SetObjResult(interp, objv[3]);
        }
        return TCL_OK;
    case OPT_LET:
        objc -= 2;
        objv += 2;
        if ((objc & 1) == 0) {
            Tcl_WrongNumArgs(interp, 2, objv, "var val ?var val ...? script");
            return TCL_ERROR;
        }
        numBindings = (objc-1)/2;
        a = ckalloc(sizeof(Activation) + (numBindings-1)*sizeof(Fluid *));
        a->n = numBindings;
        for (i = 0; i < numBindings; i++) {
            fluid = getFluidFromObj(objv[i*2], ctx, 1);
            /* fluid != NULL because we called getFluidFromObj with create = 1 */
            if (fluid->val) {
                saved = ckalloc(sizeof(Saved));
                saved->val = fluid->val;
                saved->prev = fluid->saved;
                fluid->saved = saved;
            }
            fluid->val = objv[i*2+1];
            Tcl_IncrRefCount(fluid->val);
            a->ls[i] = fluid;
        }
        retainCtx(ctx);
        Tcl_NRAddCallback(interp, fluidCleanup, (ClientData)a, NULL, NULL, NULL);
        return Tcl_NREvalObj(interp, objv[objc-1], 0);
    }

    /* Not reached */
    return TCL_OK;
}

static int
fluidHandlerCmd(ClientData cd, Tcl_Interp *interp,
                int objc, Tcl_Obj *const objv[])
{
    return Tcl_NRCallObjProc(interp, fluidHandlerNRCmd, cd, objc, objv);
}

int
fluidCmd(ClientData cd, Tcl_Interp *interp,
         int objc, Tcl_Obj *const objv[])
{
    Ctx *ctx;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmdName");
        return TCL_ERROR;
    }
    ctx = ckalloc(sizeof(Ctx));
    if (!ckCreateNRCmd(interp, Tcl_GetString(objv[1]), fluidHandlerCmd,
		       fluidHandlerNRCmd, (ClientData)ctx, deleteCtx)) {
	ckfree(ctx);
	return TCL_ERROR;
    }
    ctx->refCount = 1;
    Tcl_InitHashTable(&ctx->table, TCL_STRING_KEYS);
    return TCL_OK;
}
