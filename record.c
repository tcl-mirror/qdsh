#include <tcl.h>
#include <string.h>
#include "qdsh.h"

static void selFreeIntRep(Tcl_Obj *);
static void selDupIntRep(Tcl_Obj *, Tcl_Obj *);

static Tcl_ObjType selectorType =
    {"recordSelector", selFreeIntRep, selDupIntRep, NULL, NULL};

static void shapeFreeIntRep(Tcl_Obj *);
static void shapeDupIntRep(Tcl_Obj *, Tcl_Obj *);
static void shapeSetStringRep(Tcl_Obj *);

static Tcl_ObjType shapeType =
    {"recordShape", shapeFreeIntRep, shapeDupIntRep, shapeSetStringRep, NULL};

static Tcl_HashEntry **
selEntryLoc(Tcl_Obj *obj)
{
    return (Tcl_HashEntry **)&obj->internalRep.ptrAndLongRep.ptr;
}

static int *
selIndexLoc(Tcl_Obj *obj)
{
    return (int *)&obj->internalRep.ptrAndLongRep.value;
}

static void
retainEntry(Tcl_HashEntry *entry)
{
    Tcl_SetHashValue(entry, (ClientData)(1 + (intptr_t)Tcl_GetHashValue(entry)));
}

static void
releaseEntry(Tcl_HashEntry *entry)
{
    intptr_t rc;

    rc = (intptr_t)Tcl_GetHashValue(entry);
    if (rc <= 1) {
        Tcl_DeleteHashEntry(entry);
    } else {
        Tcl_SetHashValue(entry, (ClientData)(rc - 1));
    }
}

static Tcl_HashEntry *
lookupAndRetain(Tcl_Obj *obj)
{
    Tcl_HashEntry *entry;
    int isNew;
    static int init = 0;
    static Tcl_HashTable table;
    
    if (!init) {
        Tcl_InitHashTable(&table, TCL_STRING_KEYS);
        init = 1;
    }
    entry = Tcl_CreateHashEntry(&table, Tcl_GetString(obj), &isNew);
    if (isNew) {
        Tcl_SetHashValue(entry, (ClientData)1);
    } else {
        retainEntry(entry);
    }
    return entry;
}

static void
getSelector(Tcl_Obj *obj, Tcl_HashEntry **entryOut, int *indexOut)
{
    Tcl_HashEntry *entry;
    
    if (obj->typePtr != &selectorType) {
        entry = lookupAndRetain(obj);
        freeIntRep(obj);
        *selEntryLoc(obj) = entry;
        *selIndexLoc(obj) = -1;
        obj->typePtr = &selectorType;
    }
    *entryOut = *selEntryLoc(obj);
    *indexOut = *selIndexLoc(obj);
}

static void
selFreeIntRep(Tcl_Obj *obj)
{
    releaseEntry(*selEntryLoc(obj));
}

static void
selDupIntRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    *selEntryLoc(dst) = *selEntryLoc(src);
    *selIndexLoc(dst) = *selIndexLoc(src);
    dst->typePtr = &selectorType;
    retainEntry(*selEntryLoc(dst));
}
    
static Tcl_HashEntry ***
shapeFieldsLoc(Tcl_Obj *obj)
{
    return (Tcl_HashEntry ***)&obj->internalRep.ptrAndLongRep.ptr;
}

static unsigned long *
shapeSizeLoc(Tcl_Obj *obj)
{
    return &obj->internalRep.ptrAndLongRep.value;
}

static void
shapeFreeIntRep(Tcl_Obj *obj) {
    unsigned long sz;
    int i;

    sz = *shapeSizeLoc(obj);
    for (i = 0; i < sz; i++) {
        releaseEntry((*shapeFieldsLoc(obj))[i]);
    }
    ckfree(*shapeFieldsLoc(obj));
}

static void
shapeDupIntRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    unsigned long sz;
    int i;

    sz = *shapeSizeLoc(src);
    *shapeFieldsLoc(dst) = ckalloc(sz * sizeof(Tcl_HashEntry *));
    for (i = 0; i < sz; i++) {
        (*shapeFieldsLoc(dst))[i] = (*shapeFieldsLoc(src))[i];
        retainEntry((*shapeFieldsLoc(dst))[i]);
    }
    *shapeSizeLoc(dst) = sz;
    dst->typePtr = &shapeType;
}

static void
shapeSetStringRep(Tcl_Obj *obj)
{
    int i, sz;
    Tcl_DString ds;
    Tcl_HashEntry **fields;

    sz = *shapeSizeLoc(obj);
    fields = *shapeFieldsLoc(obj);
    Tcl_DStringInit(&ds);
    for (i = 0; i < sz; i++) {
        Tcl_DStringAppendElement(&ds, Tcl_GetHashValue(fields[i]));
    }
    if (ds.string == ds.staticSpace) {
        obj->bytes = ckalloc(ds.length+1);
        memcpy(obj->bytes, ds.staticSpace, ds.length);
    } else {
        obj->bytes = ds.string;
    }
    obj->length = ds.length;
    obj->bytes[ds.length] = '\0';

    /* Not calling Tcl_DStringFree */
}

static int
getShape(Tcl_Interp *interp, Tcl_Obj *obj,
         Tcl_HashEntry ***fieldsOut, unsigned long *sizeOut)
{
    int i, objc;
    Tcl_Obj **objv;
    Tcl_HashEntry **fields;
    
    if (obj->typePtr != &shapeType) {
        if (Tcl_ListObjGetElements(interp, obj, &objc, &objv) != TCL_OK)
            return TCL_ERROR;

        fields = ckalloc(objc * sizeof(Tcl_HashEntry *));
        for (i = 0; i < objc; i++) {
            fields[i] = lookupAndRetain(objv[i]);
        }
        freeIntRep(obj);
        *shapeFieldsLoc(obj) = fields;
        *shapeSizeLoc(obj) = objc;
        obj->typePtr = &shapeType;
    }
    *fieldsOut = *shapeFieldsLoc(obj);
    *sizeOut = *shapeSizeLoc(obj);
    return TCL_OK;
}

int
recordObjCmd(ClientData cd, Tcl_Interp *interp,
             int objc, Tcl_Obj *const objv[]) {
    unsigned long length;
    int recLength, i, index;
    Tcl_Obj *recObj, **recVals, *field;
    Tcl_HashEntry **fields, *symbol;

    if (objc == 3) {
        recObj = objv[1];
        if (Tcl_ListObjGetElements(interp, recObj, &recLength, &recVals) != TCL_OK) {
            return TCL_ERROR;
        }
    } else if (objc == 4) {
        recObj = Tcl_ObjGetVar2(interp, objv[1], NULL, 0);
        if (recObj == NULL ||
            Tcl_ListObjGetElements(interp, recObj, &recLength, &recVals) != TCL_OK) {
            return TCL_ERROR;
        }
        if (Tcl_IsShared(recObj)) {
            /* Note: Tcl_DuplicateObj doesn't do the job because internal rep is still shared */
            recObj = Tcl_NewListObj(recLength, recVals);
            Tcl_ListObjGetElements(NULL, recObj, &recLength, &recVals);
        }
    } else {
        Tcl_WrongNumArgs(interp, 1, objv, "record field ?value?");
        return TCL_ERROR;
    }

    if (recLength < 1)
        goto bad_record;

    if (getShape(interp, recVals[0], &fields, &length) != TCL_OK)
        return TCL_ERROR;

    if (recLength < length+1)
        goto bad_record;

    field = objv[2];
    getSelector(field, &symbol, &index);

    if (index == -1 || index >= length || fields[index] != symbol) {
        for (i = 0; i < length; i++) {
            if (fields[i] == symbol) {
                index = *selIndexLoc(field) = i;
                goto found;
            }
        }
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("field \"%s\" not found in record", Tcl_GetString(field)));
        return TCL_ERROR;
    }
 found:

    if (objc == 3) {
        Tcl_SetObjResult(interp, recVals[index+1]);
        return TCL_OK;
    }

    Tcl_DecrRefCount(recVals[index+1]);
    recVals[index+1] = objv[3];
    Tcl_IncrRefCount(recVals[index+1]);
    Tcl_InvalidateStringRep(recObj);
    if (Tcl_ObjSetVar2(interp, objv[1], NULL, recObj, TCL_LEAVE_ERR_MSG) == NULL) {
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, recObj);
    return TCL_OK;

 bad_record:
    Tcl_SetObjResult(interp, Tcl_NewStringObj("bad record", -1));
    return TCL_ERROR;
}
