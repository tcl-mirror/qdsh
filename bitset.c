#include <tcl.h>
#include <string.h>

#include "qdsh.h"

static void updateStringOfBitset(Tcl_Obj *);

static Tcl_ObjType bitListType =
    {"bitlist", freeCellInternalRep, dupCellInternalRep, NULL, NULL};

static Tcl_ObjType bitsetType =
    {"bitset", freeCellInternalRep, dupCellInternalRep, updateStringOfBitset, NULL};

static Tcl_ObjType indexType =
    {"index", freeCellInternalRep, dupCellInternalRep, NULL, NULL};

enum option {
    OPT_ALL,    OPT_FROMINT, OPT_INDEX, OPT_INVERT, OPT_ISSET, OPT_LIST,
    OPT_REMOVE, OPT_SET,     OPT_SOME,  OPT_TOINT,  OPT_TOLIST
};

#define BITLIST_ALL(obj) \
    (obj)->internalRep.ptrAndLongRep.value
#define BITLIST_LIST(obj) \
    (obj)->internalRep.ptrAndLongRep.ptr

#define BITSET_VALUE(obj) \
    (obj)->internalRep.ptrAndLongRep.value
#define BITSET_BITLIST(obj) \
    (obj)->internalRep.ptrAndLongRep.ptr

#define INDEX_NUM(obj) \
    (obj)->internalRep.ptrAndLongRep.value
#define INDEX_BITLIST(obj) \
    (obj)->internalRep.ptrAndLongRep.ptr

static void
wrongNumArgs(Tcl_Interp *interp, Tcl_Obj *const objv[], char *args)
{
    Tcl_DString ds;

    Tcl_DStringInit(&ds);
    Tcl_DStringAppend(&ds, "bitlist ", -1);
    Tcl_DStringAppend(&ds, Tcl_GetString(objv[2]), -1);
    if (args) {
        Tcl_DStringAppend(&ds, " ", 1);
        Tcl_DStringAppend(&ds, args, -1);
    }
    Tcl_WrongNumArgs(interp, 1, objv, Tcl_DStringValue(&ds));
    Tcl_DStringFree(&ds);
}

static int
getBitList(Tcl_Interp *interp, Tcl_Obj *obj, int *objc, Tcl_Obj ***objv)
{
    Tcl_Obj *list;
    int all = 0, i;
    
    if (obj->typePtr == &bitListType) {
        list = BITLIST_LIST(obj);
        Tcl_ListObjGetElements(NULL, list, objc, objv);
        return TCL_OK;
    }

    list = Tcl_DuplicateObj(obj);
    if (Tcl_ListObjGetElements(interp, list, objc, objv) != TCL_OK) {
        Tcl_DecrRefCount(list);
        return TCL_ERROR;
    }
    
    for (i = 0; i < *objc; i++) {
        all = (all << 1) | 1;
    }

    if (obj->typePtr && obj->typePtr->freeIntRepProc) {
        obj->typePtr->freeIntRepProc(obj);
    }
    obj->typePtr = &bitListType;
    BITLIST_ALL(obj) = all;
    BITLIST_LIST(obj) = list;
    Tcl_IncrRefCount(list);
    if (!obj->bytes) {
        obj->bytes = Tcl_GetString(list);
        obj->length = list->length;
        list->bytes = NULL;
    }
    return TCL_OK;
}

static int
find(Tcl_Interp *interp, Tcl_Obj *list, Tcl_Obj *obj, int *result)
{
    int objc, len, byteLen, otherLen, otherByteLen, i;
    Tcl_Obj **objv;
    char *str, *otherStr;

    if (obj->typePtr == &indexType && INDEX_BITLIST(obj) == list) {
        *result = INDEX_NUM(obj);
        return TCL_OK;
    }

    getBitList(interp, list, &objc, &objv);
    str = Tcl_GetStringFromObj(obj, &byteLen);
    len = Tcl_NumUtfChars(str, byteLen);
    for (i = 0; i < objc; i++) {
        otherStr = Tcl_GetStringFromObj(objv[i], &otherByteLen);
        otherLen = Tcl_NumUtfChars(otherStr, otherByteLen);
        if (len == otherLen && Tcl_UtfNcmp(str, otherStr, len) == 0) {
            if (obj->typePtr && obj->typePtr->freeIntRepProc) {
                obj->typePtr->freeIntRepProc(obj);
            }
            INDEX_BITLIST(obj) = list;
            INDEX_NUM(obj) = i;
            obj->typePtr = &indexType;
            Tcl_IncrRefCount(list);
            *result = i;
            return TCL_OK;
        }
    }
    Tcl_SetObjResult(interp, Tcl_ObjPrintf("cannot find \"%s\" in list", str));
    return TCL_ERROR;
}

/* We could calculate this in logarithmic time by sorting both lists
 * first. Unclear that this will improve performance since bitsets are
 * small and most bitsets will be statically cached by the Tcl value
 * system. */
static int
getValue(Tcl_Interp *interp, Tcl_Obj *list, Tcl_Obj *bits, long *result)
{
    int objc, value, i, index;
    Tcl_Obj **objv;

    if (bits->typePtr == &bitsetType && BITSET_BITLIST(bits) == list) {
        *result = BITSET_VALUE(bits);
        return TCL_OK;
    }
    
    if (Tcl_ListObjGetElements(interp, bits, &objc, &objv) != TCL_OK) {
        return TCL_ERROR;
    }

    value = 0;
    for (i = 0; i < objc; i++) {
        if (find(interp, list, objv[i], &index) != TCL_OK) {
            return TCL_ERROR;
        }
        value |= (1 << index);
    }
    *result = value;

    if (bits->typePtr && bits->typePtr->freeIntRepProc) {
        bits->typePtr->freeIntRepProc(bits);
    }
    BITSET_VALUE(bits) = value;
    BITSET_BITLIST(bits) = list;
    bits->typePtr = &bitsetType;
    Tcl_IncrRefCount(list);
    return TCL_OK;
}

static Tcl_Obj *
newBitset(Tcl_Obj *list, long value)
{
    Tcl_Obj *res;

    res = Tcl_NewObj();
    BITSET_VALUE(res) = value;
    BITSET_BITLIST(res) = list;
    res->typePtr = &bitsetType;
    Tcl_IncrRefCount(list);
    Tcl_InvalidateStringRep(res);
    return res;
}

static void
sel(Tcl_Obj *list, Tcl_Obj *obj, int value)
{
    int bitsSet = 0, acc, objc, i;
    Tcl_Obj **objv;

    for (acc = value; acc != 0; acc >>= 1) {
        if ((acc & 1) == 1) bitsSet++;
    }
    Tcl_SetListObj(obj, bitsSet, NULL);

    getBitList(NULL, list, &objc, &objv);
    for (i = 0; i < objc; i++) {
        if ((value & 1) == 1) {
            Tcl_ListObjAppendElement(NULL, obj, objv[i]);
        }
        value >>= 1;
    }
}

static int
doOneSet(Tcl_Interp *interp, enum option cmd, int objc, Tcl_Obj *const objv[])
{
    int all;
    long value;
    Tcl_Obj *res;
    
    if (objc != 4) {
        wrongNumArgs(interp, objv, "set");
        return TCL_ERROR;
    }
    if (getValue(interp, objv[1], objv[3], &value) != TCL_OK)
        return TCL_ERROR;
    switch (cmd) {
    case OPT_INVERT:
        all = BITLIST_ALL(objv[1]);
        Tcl_SetObjResult(interp, newBitset(objv[1], all^value));
        return TCL_OK;
    case OPT_TOINT:
        Tcl_SetObjResult(interp, Tcl_NewLongObj(value));
        return TCL_OK;
    case OPT_TOLIST:
        res = Tcl_NewObj();
        sel(objv[1], res, value);
        Tcl_SetObjResult(interp, res);
        return TCL_OK;
    default:
        /* Not reached */
        return TCL_ERROR;
    }
}

static int
doTwoSet(Tcl_Interp *interp, enum option cmd, int objc, Tcl_Obj *const objv[])
{
    long value, bits;
    
    if (objc != 5) {
        wrongNumArgs(interp, objv, "set1 set2");
        return TCL_ERROR;
    }
    
    if (getValue(interp, objv[1], objv[3], &value) != TCL_OK ||
        getValue(interp, objv[1], objv[4], &bits) != TCL_OK) {
        return TCL_ERROR;
    }

    switch (cmd) {
    case OPT_ISSET:
        Tcl_SetObjResult(interp, Tcl_NewBooleanObj((value & bits) == bits));
        return TCL_OK;
    case OPT_REMOVE:
        Tcl_SetObjResult(interp, (value == (value&~bits)) ?
                         objv[3] : newBitset(objv[1], value&~bits));
        return TCL_OK;
    case OPT_SET:
        Tcl_SetObjResult(interp, (value == (value|bits)) ?
                         objv[3] : newBitset(objv[1], value|bits));
        return TCL_OK;
    case OPT_SOME:
	Tcl_SetObjResult(interp, Tcl_NewBooleanObj((value & bits) != 0));
	return TCL_OK;
    default:
        /* not reached */
        return TCL_ERROR;
    }
}

int
bitsetCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    long value;
    int index, listLen;
    static const char *const options[] = {
        "all",    "fromint", "index",  "invert", "isset", "list",
        "remove", "set",     "some",   "toint",  "tolist", NULL
    };
    Tcl_Obj *list, **listElements;
    
    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "bitlist cmd ?arg ...?");
        return TCL_ERROR;
    }
    list = objv[1];
    if (getBitList(interp, list, &listLen, &listElements) != TCL_OK ||
        Tcl_GetIndexFromObj(interp, objv[2], options, "option", 0,
                            &index) != TCL_OK) {
        return TCL_ERROR;
    }

    switch ((enum option)index) {
    case OPT_INVERT:
    case OPT_TOINT:
    case OPT_TOLIST:
        return doOneSet(interp, (enum option)index, objc, objv);
    case OPT_ISSET:
    case OPT_REMOVE:
    case OPT_SET:
    case OPT_SOME:
        return doTwoSet(interp, (enum option)index, objc, objv);
    case OPT_FROMINT:
        if (objc != 4) {
            wrongNumArgs(interp, objv, "int");
            return TCL_ERROR;
        }
        if (Tcl_GetLongFromObj(interp, objv[3], &value) != TCL_OK) {
            return TCL_ERROR;
        }
        if (value < 0 || (value >> listLen) != 0) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("value does not fit in bitset", -1));
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, newBitset(list, value));
        return TCL_OK;
    case OPT_INDEX:
        if (objc != 4) {
            wrongNumArgs(interp, objv, "element");
            return TCL_ERROR;
        } else {
            int index, result;
            result = find(interp, list, objv[3], &index);
            if (result == TCL_OK) {
                Tcl_SetObjResult(interp, Tcl_NewIntObj(index));
            }
            return result;
        }
    case OPT_LIST:
    case OPT_ALL:
        if (objc != 3) {
            wrongNumArgs(interp, objv, NULL);
            return TCL_ERROR;
        }
        if ((enum option)index == OPT_LIST) {
            Tcl_SetObjResult(interp, list);
        } else {
            Tcl_SetObjResult(interp, newBitset(list, BITLIST_ALL(list)));
        }
        return TCL_OK;
    }

    /* Not reached */
    return TCL_ERROR;
}

static void
updateStringOfBitset(Tcl_Obj *obj)
{
    long value;
    Tcl_Obj *list;

    value = BITSET_VALUE(obj);
    list = BITSET_BITLIST(obj);

    if (value == 0) {
        obj->bytes = ckalloc(1);
        obj->bytes[0] = '\0';
        obj->length = 0;
    } else {
        Tcl_Obj *ls = Tcl_NewObj();
        sel(list, ls, value);
        (void)Tcl_GetString(ls);
        obj->bytes = ls->bytes;
        obj->length = ls->length;
        ls->bytes = NULL;
        Tcl_DecrRefCount(ls);
    }
}
