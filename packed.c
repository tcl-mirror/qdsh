#include <string.h>
#include <tcl.h>
#include "qdsh.h"

typedef struct Spec {
    int refCount;
    char *tag;
    struct Spec *parent;
    int len;
    Tcl_Obj *obj[1];
} Spec;

static void
retainSpec(Spec *spec)
{
    spec->refCount++;
}

static void
releaseSpec(Spec *spec)
{
    int i;
    
    if (--spec->refCount == 0) {
	ckfree(spec->tag);
	if (spec->parent)
	    releaseSpec(spec->parent);
	for (i = 0; i < spec->len; i++) {
	    Tcl_DecrRefCount(spec->obj[i]);
	}
	ckfree(spec);
    }
}

static void
setSpec(Tcl_Obj *obj, Spec *spec)
{
    retainSpec(spec);
    obj->internalRep.twoPtrValue.ptr1 = spec;
}

static void
setVal(Tcl_Obj *obj, Tcl_Obj *val)
{
    Tcl_IncrRefCount(val);
    obj->internalRep.twoPtrValue.ptr2 = val;
}

#define INT_SPEC(obj) ((Spec *)(obj)->internalRep.twoPtrValue.ptr1)
#define INT_VAL(obj) ((Tcl_Obj*)(obj)->internalRep.twoPtrValue.ptr2)

void
dupPackedIntRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    setSpec(dst, INT_SPEC(src));
    setVal(dst, INT_VAL(src));
    dst->typePtr = src->typePtr;
}

void
freePackedIntRep(Tcl_Obj *obj)
{
    Tcl_DecrRefCount(INT_VAL(obj));
    releaseSpec(INT_SPEC(obj));
    obj->typePtr = NULL;
}

void
updatePackedStringRep(Tcl_Obj *obj)
{
    char *str;
    int strLen, tagLen;
    Spec *spec;

    spec = (Spec *)INT_SPEC(obj);
    str = Tcl_GetStringFromObj(INT_VAL(obj), &strLen);
    tagLen = strlen(spec->tag);
    obj->length = strLen + tagLen + 3;
    obj->bytes = ckalloc(obj->length + 1);
    obj->bytes[0] = '{';
    memcpy(obj->bytes + 1, spec->tag, tagLen);
    obj->bytes[tagLen + 1] = '}';
    obj->bytes[tagLen + 2] = ':';
    memcpy(obj->bytes + tagLen + 3, str, strLen);
    obj->bytes[obj->length] = '\0';
}

static Tcl_ObjType packedType =
    { "packed", freePackedIntRep, dupPackedIntRep, updatePackedStringRep, NULL};

static Tcl_Obj *
stripTag(char *tag, Tcl_Obj *obj)
{
    char *str;
    int i, strLen;

    str = Tcl_GetStringFromObj(obj, &strLen);
    if (str[0] != '{')
	return NULL;
    for (i = 0; tag[i] != '\0'; i++)
	if (str[i+1] != tag[i])
	    return NULL;
    if (str[i+1] != '}' || str[i+2] != ':')
	return NULL;
    return Tcl_NewStringObj(&str[i + 3], strLen - i - 3);
}

static Tcl_Obj *
untag(Spec *spec, Tcl_Obj *obj)
{
    Spec *p;
    Tcl_Obj *val;

    if (obj->typePtr == &packedType) {
	p = spec;
	do {
	    if (INT_SPEC(obj) == p)
		return INT_VAL(obj);
	    p = p->parent;
	} while (p);
    }

    p = spec;
    do {
	if ((val = stripTag(p->tag, obj)) != NULL)
	    return val;
	p = p->parent;
    } while (p);

    return NULL;
}

static int
unpack(Tcl_Interp *interp, Spec *spec, Tcl_Obj *obj)
{
    int ret, i;
    Tcl_Obj **ls, *val;

    val = untag(spec, obj);
    if (val) {
	Tcl_SetObjResult(interp, val);
	return TCL_OK;
    }

    ls = ckalloc(sizeof(Tcl_Obj *) * (spec->len + 1));
    for (i = 0; i < spec->len; i++)
	ls[i] = spec->obj[i];
    ls[spec->len] = obj;
    Tcl_IncrRefCount(obj);
    ret = Tcl_EvalObjv(interp, spec->len + 1, ls, TCL_EVAL_GLOBAL);
    if (ret == TCL_OK) {
	val = untag(spec, Tcl_GetObjResult(interp));
	if (val) {
	    /* Eval succeeded. Save result in obj */
	    freeIntRep(obj);
	    obj->typePtr = &packedType;
	    setSpec(obj, spec);
	    setVal(obj, val);
	    Tcl_SetObjResult(interp, val);
	} else {
	    ret = errorMsg(interp, "converter did not correctly tag object");
	}
    } else {
	ret = TCL_ERROR;
    }
    Tcl_DecrRefCount(obj);
    ckfree(ls);
    return ret;
}

static int
handlerCmd(ClientData cd, Tcl_Interp *interp,
	   int objc, Tcl_Obj *const objv[])
{
    Tcl_Obj *res;
    Spec *spec;

    spec = (Spec *)cd;
    if (objc == 2) {
	res = Tcl_NewObj();
	Tcl_InvalidateStringRep(res);
	res->typePtr = &packedType;
	setSpec(res, spec);
	setVal(res, objv[1]);
	Tcl_SetObjResult(interp, res);
	return TCL_OK;
    } else if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-unpack? obj");
	return TCL_ERROR;
    }
    return unpack(interp, spec, objv[2]);
}

static void
delHandler(ClientData cd)
{
    releaseSpec((Spec *)cd);
}

int
defPackedCmd(ClientData cd, Tcl_Interp *interp,
             int objc, Tcl_Obj *const objv[])
{
    char *tag;
    int tagLen, lsLen, i;
    Tcl_Obj **ls;
    Spec *spec, *parent = NULL;
    Tcl_CmdInfo parentCmdInfo;
    
    if (objc != 4 && objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmd tag converter ?parent?");
	return TCL_ERROR;
    }
    tag = Tcl_GetStringFromObj(objv[2], &tagLen);
    if (objc == 5 && Tcl_GetString(objv[4])[0] != '\0') {
	if (!Tcl_GetCommandInfoFromToken(Tcl_GetCommandFromObj(interp, objv[4]),
					 &parentCmdInfo)
	    || parentCmdInfo.objProc != handlerCmd) {
	    return errorMsg(interp, "bad parent");
	}
	parent = (Spec *)parentCmdInfo.objClientData;
    }

    /* Verify tag */
    for (i = 0; i < tagLen; i++)
	if (tag[i] == '{' || tag[i] == '}' || tag[i] == '\0')
badTag:
	    return errorMsg(interp, "bad tag");

    for (spec = parent; spec != NULL; spec = spec->parent)
	if (strcmp(tag, spec->tag) == 0)
	    goto badTag;
    
    if (Tcl_ListObjGetElements(interp, objv[3], &lsLen, &ls) != TCL_OK)
	return TCL_ERROR;

    spec = ckalloc(sizeof(Spec) + sizeof(Tcl_Obj *)*(lsLen-1));
    spec->refCount = 1; /* Retained by this proc */
    spec->tag = ckalloc(tagLen + 1);
    memcpy(spec->tag, tag, tagLen);
    spec->tag[tagLen] = '\0';
    spec->parent = parent;
    if (parent)
	retainSpec(parent);
    spec->len = lsLen;
    for (i = 0; i < lsLen; i++) {
	spec->obj[i] = ls[i];
	Tcl_IncrRefCount(spec->obj[i]);
    }
    if (!ckCreateCmd(interp, Tcl_GetString(objv[1]), handlerCmd,
		     (ClientData)spec, delHandler)) {
	releaseSpec(spec);
	return TCL_ERROR;
    }
    return TCL_OK;
}
