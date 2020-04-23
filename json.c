#include <yajl/yajl_parse.h>
#include <yajl/yajl_gen.h>
#include <tcl.h>

#include "qdsh.h"

enum Type {
    TYPE_NULL, TYPE_BOOL, TYPE_INT, TYPE_DOUBLE,
    TYPE_STRING, TYPE_LIST, TYPE_DICT,
    NUM_TYPES
};

static Tcl_Obj *typeNames[NUM_TYPES];
static Tcl_Obj *cur, *stack;
static Tcl_Obj *fieldList = NULL, *nullObj;

static Tcl_Obj *
newObj(enum Type type, Tcl_Obj *val)
{
    Tcl_Obj *objv[3];
    objv[0] = fieldList;
    objv[1] = typeNames[type];
    objv[2] = val;
    return Tcl_NewListObj(3, objv);
}

static void
emitObj(Tcl_Obj *obj)
{
    Tcl_ListObjAppendElement(NULL, cur, obj);
}

static int
null_callback(void *ctx) {
    emitObj(nullObj);
    return 1;
}

static int
boolean_callback(void *ctx, int val) {
    emitObj(newObj(TYPE_BOOL, Tcl_NewIntObj(!!val)));
    return 1;
}

static int
number_callback(void *ctx, const char *str, size_t len)
{
    enum Type t = TYPE_INT;
    int i;

    for (i = 0; i < len; i++) {
        if (str[i] < '0' || str[i] > '9') {
            t = TYPE_DOUBLE;
            break;
        }
    }
    emitObj(newObj(t, Tcl_NewStringObj((char *)str, len)));
    return 1;
}

static int
string_callback(void *ctx, const unsigned char *str, size_t len)
{
    emitObj(newObj(TYPE_STRING, Tcl_NewStringObj((char *)str, len)));
    return 1;
}

static int
map_start_callback(void *ctx)
{
    static Tcl_Obj *tree = NULL, *create;

    if (!tree) {
        tree = Tcl_NewStringObj("tree", -1);
        Tcl_IncrRefCount(tree);
        create = Tcl_NewStringObj("create", -1);
        Tcl_IncrRefCount(create);
    }
    
    Tcl_ListObjAppendElement(NULL, stack, cur);
    Tcl_DecrRefCount(cur);
    cur = Tcl_NewObj();
    Tcl_IncrRefCount(cur);
    emitObj(tree);
    emitObj(create);
    return 1;
}

static int
map_key_callback(void *ctx, const unsigned char *str, size_t len)
{
    emitObj(Tcl_NewStringObj((char *)str, len));
    return 1;
}

static int
map_end_callback(void *ctx)
{
    Tcl_Interp *interp = ctx;
    int len;
    Tcl_Obj *obj;


    if (Tcl_EvalObj(interp, cur) == TCL_ERROR) {
        return 0;
    }
        
    obj = newObj(TYPE_DICT, Tcl_GetObjResult(interp));
    Tcl_DecrRefCount(cur);
    Tcl_ListObjLength(NULL, stack, &len);
    Tcl_ListObjIndex(NULL, stack, len-1, &cur);
    Tcl_IncrRefCount(cur);
    Tcl_ListObjReplace(NULL, stack, len-1, 1, 0, NULL);
    emitObj(obj);
    return 1;
}

static int
array_start_callback(void *ctx)
{
    Tcl_ListObjAppendElement(NULL, stack, cur);
    Tcl_DecrRefCount(cur);
    cur = Tcl_NewObj();
    Tcl_IncrRefCount(cur);
    return 1;
}

static int
array_end_callback(void *ctx)
{
    int len;
    Tcl_Obj *obj = newObj(TYPE_LIST, cur);

    Tcl_DecrRefCount(cur);
    Tcl_ListObjLength(NULL, stack, &len);
    Tcl_ListObjIndex(NULL, stack, len-1, &cur);
    Tcl_IncrRefCount(cur);
    Tcl_ListObjReplace(NULL, stack, len-1, 1, 0, NULL);
    emitObj(obj);
    return 1;
}

static yajl_callbacks callbacks = {
    null_callback,
    boolean_callback,
    NULL, /* integer callback */
    NULL, /* double callback */
    number_callback,
    string_callback,
    map_start_callback,
    map_key_callback,
    map_end_callback,
    array_start_callback,
    array_end_callback
};

int
jsonParseCmd(ClientData cd, Tcl_Interp *interp, int objc,
             Tcl_Obj *const objv[])
{
    char *str, *error;
    int i, len;
    yajl_status status;
    Tcl_Obj *res;
    yajl_handle handle;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "string");
        return TCL_ERROR;
    }

    handle = yajl_alloc(&callbacks, NULL, interp);
    if (!fieldList) {
        fieldList = Tcl_NewStringObj("type val", -1);
        Tcl_IncrRefCount(fieldList);
        typeNames[TYPE_NULL] = Tcl_NewStringObj("null", -1);
        typeNames[TYPE_INT] = Tcl_NewStringObj("int", -1);
        typeNames[TYPE_DOUBLE] = Tcl_NewStringObj("double", -1);
        typeNames[TYPE_BOOL] = Tcl_NewStringObj("boolean", -1);
        typeNames[TYPE_STRING] = Tcl_NewStringObj("string", -1);
        typeNames[TYPE_LIST] = Tcl_NewStringObj("list", -1);
        typeNames[TYPE_DICT] = Tcl_NewStringObj("dict", -1);
        for (i = 0; i < NUM_TYPES; i++) {
            Tcl_IncrRefCount(typeNames[i]);
        }
        nullObj = newObj(TYPE_NULL, Tcl_NewObj());
        Tcl_IncrRefCount(nullObj);
    }

    str = Tcl_GetStringFromObj(objv[1], &len);
    cur = Tcl_NewObj();
    Tcl_IncrRefCount(cur);
    stack = Tcl_NewObj();
    Tcl_IncrRefCount(stack);

    if ((status = yajl_parse(handle, (const unsigned char *)str, len)) != yajl_status_ok ||
        (status = yajl_complete_parse(handle)) != yajl_status_ok) {
        if (status != yajl_status_client_canceled) {
            error = (char *)yajl_status_to_string(status);
            Tcl_SetObjResult(interp, Tcl_NewStringObj(error, -1));
            /*yajl_free_error(handle, (unsigned char *)error);*/
        }
        return TCL_ERROR;
    }

    if (Tcl_ListObjLength(interp, cur, &len) == TCL_ERROR) {
        return TCL_ERROR;
    }
    if (len < 1) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("didn't parse an object", -1));
        return TCL_ERROR;
    }

    Tcl_ListObjIndex(interp, cur, 0, &res);
    Tcl_SetObjResult(interp, res);
    Tcl_DecrRefCount(cur);
    Tcl_DecrRefCount(stack);
    yajl_free(handle);
    return TCL_OK;
}
