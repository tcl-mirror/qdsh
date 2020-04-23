#include <tcl.h>
#include <string.h>

#include "critbit.h"

typedef enum TreeType {
    T_MAP, T_SET
} TreeType;

typedef struct Node {
    int refCount;
} Node;

typedef struct IntNode {
    int refCount;
    Node *child[2];
    int byte;
    int size;
    unsigned char otherBits;
} IntNode;

typedef struct ExtNode {
    int refCount;
    Tcl_Obj *key;
    Tcl_Obj *value;
} ExtNode;

typedef struct ForState {
    TreeType type;
    Tcl_Obj *keyVar;
    Tcl_Obj *valueVar;
    Tcl_Obj *script;
    Node **stack;
    int stackSize;
    int stackCapacity;
} ForState;

static void freeTreeInternalRep(Tcl_Obj *);
static void dupTreeInternalRep(Tcl_Obj *, Tcl_Obj *);
static void updateStringOfTree(Tcl_Obj *);
static int setTreeFromAny(Tcl_Interp *, Tcl_Obj *);

static void dupTreesetInternalRep(Tcl_Obj *, Tcl_Obj *);
static void updateStringOfTreeset(Tcl_Obj *);
static int setTreesetFromAny(Tcl_Interp *, Tcl_Obj *);

const Tcl_ObjType treeType = {
    "tree",
    freeTreeInternalRep,
    dupTreeInternalRep,
    updateStringOfTree,
    setTreeFromAny
};

const Tcl_ObjType treesetType = {
    "treeset",
    freeTreeInternalRep, /* shared */
    dupTreesetInternalRep,
    updateStringOfTreeset,
    setTreesetFromAny
};

static Node *treeCreate(int, Tcl_Obj *const[]);
static Node *treesetCreate(int, Tcl_Obj *const[]);
static Tcl_Obj *treeToList(Node *);
static Tcl_Obj **nodeToList(Node *, Tcl_Obj **);
static void nodeSet(TreeType, Node **, Tcl_Obj *, Tcl_Obj *);
static Node *nodeRemove(Node *, Tcl_Obj *);
static Tcl_Obj *treeKeys(Node *);

static int forNext(Tcl_Interp *, ForState *);
static void forPushNode(ForState *, Node *);
static int forCallback(ClientData [], Tcl_Interp *, int);
static void forCleanup(ForState *);

static void
normalizeUtf(Tcl_Obj *obj)
{
    char *p, *q;
    int i, len, nuls;

    p = Tcl_GetStringFromObj(obj, &len);
    nuls = 0;
    for (i = 0; i < len; i++) {
	if (p[i] == (char)0xc0 && p[i+1] == (char)0x80) {
	    nuls++;
	}
    }
    if (nuls == 0) {
	return;
    }
    obj->bytes = q = ckalloc(len - nuls + 1);
    obj->length = len - nuls;
    for (i = 0; i < len; i++) {
	if (p[i] == (char)0xc0 && p[i+1] == (char)0x80) {
	    *q++ = '\0';
	    i++;
	} else {
	    *q++ = p[i];
	}
    }
    *q = '\0';
    ckfree(p);
}

static int
isInternal(Node *n)
{
    return (n->refCount & 1);
}

static void
retainNode(Node *n)
{
    n->refCount += 2;
}

static int
nodeShared(Node *n)
{
    return n->refCount > 3;
}

static void
releaseNode(Node *n)
{
    if (n->refCount <= 3) {
	if (isInternal(n)) {
	    IntNode *i = (IntNode *)n;
	    releaseNode(i->child[0]);
	    releaseNode(i->child[1]);
	} else {
	    ExtNode *e = (ExtNode *)n;
	    Tcl_DecrRefCount(e->key);
	    Tcl_DecrRefCount(e->value);
	}
	ckfree(n);
    } else {
	n->refCount -= 2;
    }
}

static void
nodeAssign(Node **loc, Node *val)
{
    if (val) retainNode(val);
    if (*loc) releaseNode(*loc);
    *loc = val;
}

static int
nodeSize(Node *n)
{
    if (!n) return 0;
    if (isInternal(n)) return ((IntNode *)n)->size;
    return 1;
}

static void
freeTreeInternalRep(Tcl_Obj *obj)
{
    Node *root = (Node *)obj->internalRep.otherValuePtr;
    if (root) releaseNode(root);
    obj->typePtr = NULL;
}

static void
dupTreeInternalRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    Node *root = src->internalRep.otherValuePtr;
    if (root) retainNode(root);
    dst->internalRep.otherValuePtr = root;
    dst->typePtr = &treeType;
}

static void
updateStringOfTree(Tcl_Obj *obj)
{
    Node *n;
    Tcl_Obj *ls;

    n = obj->internalRep.otherValuePtr;
    ls = treeToList(n);
    Tcl_GetString(ls);
    obj->bytes = ls->bytes;
    obj->length = ls->length;
    ls->bytes = NULL;
    Tcl_DecrRefCount(ls);
}

static int
setTreeFromAny(Tcl_Interp *interp, Tcl_Obj *obj)
{
    int objc;
    Tcl_Obj **objv;
    Node *root;

    if (obj->typePtr == &treeType) return TCL_OK;
    if (Tcl_ListObjGetElements(interp, obj, &objc, &objv) != TCL_OK) return TCL_ERROR;
    if ((objc & 1) == 1) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("missing value to go with key", -1));
	return TCL_ERROR;
    }
    root = treeCreate(objc, objv);
    if (obj->typePtr && obj->typePtr->freeIntRepProc) obj->typePtr->freeIntRepProc(obj);
    obj->internalRep.otherValuePtr = root;
    obj->typePtr = &treeType;
    return TCL_OK;
}

static void
dupTreesetInternalRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    Node *root = src->internalRep.otherValuePtr;
    if (root) retainNode(root);
    dst->internalRep.otherValuePtr = root;
    dst->typePtr = &treesetType;
}

static void
updateStringOfTreeset(Tcl_Obj *obj)
{
    Node *n;
    Tcl_Obj *ls;

    n = obj->internalRep.otherValuePtr;
    ls = treeKeys(n);
    Tcl_GetString(ls);
    obj->bytes = ls->bytes;
    obj->length = ls->length;
    ls->bytes = NULL;
    Tcl_DecrRefCount(ls);
}

static int
setTreesetFromAny(Tcl_Interp *interp, Tcl_Obj *obj)
{
    int objc;
    Tcl_Obj **objv;
    Node *root;

    if (obj->typePtr == &treesetType) return TCL_OK;
    if (Tcl_ListObjGetElements(interp, obj, &objc, &objv) != TCL_OK) return TCL_ERROR;
    root = treesetCreate(objc, objv);
    if (obj->typePtr && obj->typePtr->freeIntRepProc) obj->typePtr->freeIntRepProc(obj);
    obj->internalRep.otherValuePtr = root;
    obj->typePtr = &treesetType;
    return TCL_OK;
}

static int
extractSingle(Tcl_Interp *interp, Tcl_Obj *obj, Tcl_Obj **dst)
{
    int objc;
    Tcl_Obj **objv;

    if (Tcl_ListObjGetElements(interp, obj, &objc, &objv) != TCL_OK) return TCL_ERROR;
    if (objc == 0) {
        *dst = NULL;
    } else if (objc == 1) {
        *dst = objv[0];
    } else {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("too many elements in list", -1));
        return TCL_ERROR;
    }
    return TCL_OK;
}

static Node *
treeCreate(int objc, Tcl_Obj *const objv[])
{
    Node *root = NULL;
    int i;

    for (i = 0; i < objc; i += 2) {
	normalizeUtf(objv[i]);
	nodeSet(T_MAP, &root, objv[i], objv[i+1]);
    }

    /* root will already be referenced if non-null (due to nodeAssign) */
    return root;
}

static Node *
treesetCreate(int objc, Tcl_Obj *const objv[])
{
    Node *root = NULL;
    int i;

    for (i = 0; i < objc; i++) {
	normalizeUtf(objv[i]);
	nodeSet(T_SET, &root, objv[i], objv[i]);
    }

    /* root will already be referenced if non-null (due to nodeAssign) */
    return root;
}

static Tcl_Obj *
treeToList(Node *node)
{
    Tcl_Obj **objv, *ls;

    if (!node) return Tcl_NewObj();
    objv = ckalloc(sizeof(Tcl_Obj *) * nodeSize(node) * 2);
    nodeToList(node, objv);
    ls = Tcl_NewListObj(nodeSize(node)*2, objv);
    ckfree(objv);
    return ls;
}

static Tcl_Obj **
nodeToList(Node *n, Tcl_Obj **objv)
{
    if (isInternal(n)) {
	IntNode *i = (IntNode *)n;
	objv = nodeToList(i->child[0], objv);
	return nodeToList(i->child[1], objv);
    } else {
	ExtNode *e = (ExtNode *)n;
	objv[0] = e->key;
	objv[1] = e->value;
	return objv+2;
    }
}

static void
nodeCollectKeys(Node *n, Tcl_Obj *ls)
{
    if (isInternal(n)) {
	IntNode *i = (IntNode *)n;
	nodeCollectKeys(i->child[0], ls);
	nodeCollectKeys(i->child[1], ls);
    } else {
	ExtNode *e = (ExtNode *)n;
	Tcl_ListObjAppendElement(NULL, ls, e->key);
    }
}

static Tcl_Obj *
treeKeys(Node *tree)
{
    Tcl_Obj *res = Tcl_NewListObj(nodeSize(tree), NULL);
    if (tree) nodeCollectKeys(tree, res);
    return res;
}

static ExtNode *
nodeGet(Node *n, Tcl_Obj *key)
{
    unsigned char *keyStr, *k;
    int keyLen, l;

    if (!n) return NULL;
    normalizeUtf(key);
    keyStr = (unsigned char *)Tcl_GetStringFromObj(key, &keyLen);
    for (;;) {
	if (isInternal(n)) {
	    IntNode *i = (IntNode *)n;
	    int dir, c = 0;
	    if (i->byte < keyLen) c = keyStr[i->byte];
	    dir = (1 + (i->otherBits | c)) >> 8;
	    n = i->child[dir];
	} else {
	    ExtNode *e = (ExtNode *)n;
            k = (unsigned char *)Tcl_GetStringFromObj(e->key, &l);
            return (keyLen == l && memcmp(keyStr, k, keyLen) == 0) ? e : NULL;
	}
    }
}

static Node *
newIntNode(Node *left, Node *right, int byte, unsigned char otherBits)
{
    IntNode *n = ckalloc(sizeof(IntNode));
    n->refCount = 1; /* mark internal */
    n->child[0] = left;
    retainNode(n->child[0]);
    n->child[1] = right;
    retainNode(n->child[1]);
    n->byte = byte;
    n->otherBits = otherBits;
    n->size = nodeSize(left) + nodeSize(right);
    return (Node *)n;
}

static Node *
newExtNode(Tcl_Obj *key, Tcl_Obj *value)
{
    ExtNode *n = ckalloc(sizeof(ExtNode));
    n->refCount = 0;
    n->key = key;
    Tcl_IncrRefCount(n->key);
    n->value = value;
    Tcl_IncrRefCount(n->value);
    return (Node *)n;
}

static Node *
nodeInsert(Node *n, Tcl_Obj *key, Tcl_Obj *value, int newByte,
           unsigned char newOtherBits, int newDir)
{
    unsigned char *keyStr;
    int c = 0, keyLen;
    Node *left, *right;
    IntNode *i;
    
    i = (IntNode *)n;
    keyStr = (unsigned char *)Tcl_GetStringFromObj(key, &keyLen);
    if (isInternal(n) &&
	(newDir == -1 || i->byte < newByte ||
	 (i->byte == newByte && newOtherBits > i->otherBits))) {
	if (i->byte < keyLen) c = keyStr[i->byte];
	if ((1 + (i->otherBits | c)) >> 8) {
	    left = i->child[0];
	    right = nodeInsert(i->child[1], key, value, newByte, newOtherBits, newDir);
	} else {
	    left = nodeInsert(i->child[0], key, value, newByte, newOtherBits, newDir);
	    right = i->child[1];
	}
	return newIntNode(left, right, i->byte, i->otherBits);
    } else if (newDir == -1) {
	return newExtNode(key, value);
    } else {
	Node *new = newExtNode(key, value);
	if (newDir) { left = new; right = n; }
	else { left = n; right = new; }
	return newIntNode(left, right, newByte, newOtherBits);
    }
}

static void
nodeInsertInPlace(Node **loc, Tcl_Obj *key, Tcl_Obj *value, int newByte,
                  unsigned char newOtherBits, int newDir)
{
    unsigned char *keyStr;
    int c = 0, keyLen, dir;
    Node *left, *right, *n, *newNode;
    IntNode *i;
    
    keyStr = (unsigned char *)Tcl_GetStringFromObj(key, &keyLen);

    for (;;) {
        n = *loc;
        if (!isInternal(n)) break;
        i = (IntNode *)n;
        if (i->byte > newByte) break;
        if (i->byte == newByte && i->otherBits > newOtherBits) break;
        i->size++;
        if (i->byte < keyLen) c = keyStr[i->byte];
        dir = (1 + (i->otherBits | c)) >> 8;
        loc = &i->child[dir];
    }

    newNode = newExtNode(key, value);
    if (newDir) { left = newNode; right = *loc; }
    else { left = *loc; right = newNode; }
    nodeAssign(loc, newIntNode(left, right, newByte, newOtherBits));
}

static void
nodeSet(TreeType type, Node **loc, Tcl_Obj *key, Tcl_Obj *value)
{
    Node *n;
    unsigned char *keyStr, *k, newOtherBits;
    int l, keyLen, newByte, newDir;
    ExtNode *e;
    int shared;

    if (!*loc) {
        nodeAssign(loc, newExtNode(key, value));
        return;
    }

    keyStr = (unsigned char *)Tcl_GetStringFromObj(key, &keyLen);

    /* Find the differing byte and bit */
    n = *loc;
    shared = 0;
    while (isInternal(n)) {
	int dir, c = 0;
	IntNode *i = (IntNode *)n;

        if (nodeShared(n) && !shared) shared = 1;
	if (i->byte < keyLen) c = keyStr[i->byte];
	dir = (1 + (i->otherBits | c)) >> 8;
	n = i->child[dir];
    }

    e = (ExtNode *)n;
    k = (unsigned char *)Tcl_GetStringFromObj(e->key, &l);
    for (newByte = 0; newByte < keyLen; newByte++) {
	if (keyStr[newByte] != k[newByte]) {
	    newOtherBits = keyStr[newByte] ^ k[newByte];
	    goto different;
	}
    }
    if (k[newByte] != '\0') {
	newOtherBits = k[newByte];
	goto different;
    }
    if (type == T_SET) {
        /* value exists in tree, nothing else to do */
        return;
    } else if (!shared && !nodeShared(n)) {
        Tcl_IncrRefCount(value);
        Tcl_DecrRefCount(e->value);
        e->value = value;
    } else {
        nodeAssign(loc, nodeInsert(*loc, key, value, -1, -1, -1));
    }
    return;
    
different:
    while (newOtherBits & (newOtherBits - 1)) newOtherBits &= (newOtherBits - 1);
    newOtherBits ^= 255;
    newDir = (1 + (newOtherBits | k[newByte])) >> 8;
    if (shared) {
        nodeAssign(loc, nodeInsert(*loc, key, value, newByte, newOtherBits, newDir));
    } else {
        nodeInsertInPlace(loc, key, value, newByte, newOtherBits, newDir);
    }
}

/* As with nodeSet, an in-place version is also possible */
static Node *
nodeRemove(Node *n, Tcl_Obj *key)
{
    IntNode *i;
    ExtNode *e;
    int c = 0, dir, keyLen, l;
    Node *children[2];
    unsigned char *keyStr, *k;

    if (!n) return NULL;
    keyStr = (unsigned char *)Tcl_GetStringFromObj(key, &keyLen);
    if (isInternal(n)) {
        i = (IntNode *)n;
        if (i->byte < keyLen) c = keyStr[i->byte];
        dir = (1 + (i->otherBits | c)) >> 8;
        children[0] = i->child[0];
        children[1] = i->child[1];
        children[dir] = nodeRemove(i->child[dir], key);
        if (!children[dir]) return i->child[1-dir];
        return newIntNode(children[0], children[1], i->byte, i->otherBits);
    } else {
        e = (ExtNode *)n;
        k = (unsigned char *)Tcl_GetStringFromObj(e->key, &l);
        return (keyLen == l && memcmp(keyStr, k, keyLen) == 0) ? NULL : n;
    }
}

/* NOTE: does not increment ref count of root */
static Tcl_Obj *
newTreeObj(TreeType type, Node *root)
{
    Tcl_Obj *res = Tcl_NewObj();
    res->typePtr = (type == T_MAP) ? &treeType : &treesetType;
    res->internalRep.otherValuePtr = root;
    Tcl_InvalidateStringRep(res);
    return res;
}

static int
getTree(TreeType type, Tcl_Interp *interp, Tcl_Obj *obj, Node **rootPtr)
{
    if ((type == T_MAP ?
         setTreeFromAny(interp, obj) :
         setTreesetFromAny(interp, obj)) == TCL_ERROR) {
        return TCL_ERROR;
    }

    *rootPtr = (Node *)obj->internalRep.otherValuePtr;
    return TCL_OK;
}

static int
treeObjReplace(TreeType type, Tcl_Interp *interp, Tcl_Obj *treeObj, Tcl_Obj *key,
	       Tcl_Obj *value, Tcl_Obj **output, int *outputAllocated)
{
    Node *tree, **loc;
    int allocated = 0;

    if (!treeObj) {
	treeObj = Tcl_NewObj();
	allocated = 1;
    } else if (Tcl_IsShared(treeObj)) {
	treeObj = Tcl_DuplicateObj(treeObj);
	allocated = 1;
    }

    if (getTree(type, interp, treeObj, &tree) == TCL_ERROR) {
        if (allocated) Tcl_DecrRefCount(treeObj);
        return TCL_ERROR;
    }
    loc = (Node **)&treeObj->internalRep.otherValuePtr;
    normalizeUtf(key);
    if (!value) {
        nodeAssign(loc, nodeRemove(tree, key));
    } else {
        nodeSet(type, loc, key, value);
    }
    Tcl_InvalidateStringRep(treeObj);
    *output = treeObj;
    if (outputAllocated) *outputAllocated = allocated;
    return TCL_OK;
}

static int
treeObjMerge(TreeType type, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
    int i;
    Node *tree = NULL, *n;
    ForState state;
    
    /* If non-empty trees exists, use the first such as the base. */ 
    for (i = 0; i < objc; i++) {
        if (getTree(type, interp, objv[i], &tree) == TCL_ERROR) return TCL_ERROR;
        if (tree)  {
            retainNode(tree);
            break;
        }
    }
    
    state.stackCapacity = 8;
    state.stackSize = 0;
    state.stack = ckalloc(state.stackCapacity * sizeof(Node *));
    
    for (i++; i < objc; i++) {
        if (getTree(type, interp, objv[i], &n) == TCL_ERROR) goto cleanup;
        if (n) {
            retainNode(n);
            for (;;) {
                while (isInternal(n)) {
                    forPushNode(&state, ((IntNode *)n)->child[1]);
                    nodeAssign(&n, ((IntNode *)n)->child[0]);
                }
                nodeSet(type, &tree, ((ExtNode *)n)->key, ((ExtNode *)n)->value);
                releaseNode(n);
                if (state.stackSize == 0) break;
                n = state.stack[--state.stackSize]; /* carry over reference */
            }
        }
    }
    ckfree(state.stack);
    Tcl_SetObjResult(interp, newTreeObj(type, tree));
    return TCL_OK;
    
cleanup:
    if (tree) releaseNode(tree);
    for (i = 0; i < state.stackSize; i++) releaseNode(state.stack[i]);
    ckfree(state.stack);
    return TCL_ERROR;
}

/* Note: not the same as treesetCmd! */
static int
treeSetCmd(TreeType type, Tcl_Interp *interp, Tcl_Obj *varName, Tcl_Obj *key, Tcl_Obj *value)
{
    Tcl_Obj *varValue, *result, *updated;
    int allocated;

    /* Don't care about errors. Array/scalar misuse will be caught by
       Tcl_ObjSetVar2 below. */
    varValue = Tcl_ObjGetVar2(interp, varName, NULL, 0);
    if (treeObjReplace(type, interp, varValue, key, value,
                       &updated, &allocated) == TCL_ERROR) {
	return TCL_ERROR;
    }
    result = Tcl_ObjSetVar2(interp, varName, NULL, updated, TCL_LEAVE_ERR_MSG);
    if (!result) {
        if (allocated) Tcl_DecrRefCount(updated);
	return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, result);
    return TCL_OK;
}

static int
treeForCmd(TreeType type, Tcl_Interp *interp, int objc,
           Tcl_Obj *const objv[])
{
    Node *tree;
    Tcl_Obj **varArray, *keyVar, *valueVar;
    int varCount;
    ForState *state;

    if (objc != 5) {
        char *usage = (type == T_MAP) ? "{k v} treeValue body" : "varName set body";
        Tcl_WrongNumArgs(interp, 2, objv, usage);
        return TCL_ERROR;
    }

    if (type == T_MAP) {
	if (Tcl_ListObjGetElements(interp, objv[2], &varCount, &varArray) == TCL_ERROR)
	    return TCL_ERROR;
	if (varCount != 2) {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj("must have exactly two variable names", -1));
	    return TCL_ERROR;
	}
	keyVar = varArray[0];
	valueVar = varArray[1];
    } else {
	keyVar = objv[2];
    }

    if (getTree(type, interp, objv[3], &tree) == TCL_ERROR) return TCL_ERROR;
    if (!tree) return TCL_OK;

    state = ckalloc(sizeof(*state));
    state->type = type;
    state->keyVar = keyVar;
    Tcl_IncrRefCount(state->keyVar);
    if (type == T_MAP) {
        state->valueVar = valueVar;
        Tcl_IncrRefCount(state->valueVar);
    } else {
        state->valueVar = NULL;
    }
    state->script = objv[4];
    Tcl_IncrRefCount(state->script);
    
    state->stackCapacity = 8;
    state->stackSize = 0;
    state->stack = ckalloc(state->stackCapacity * sizeof(Node *));

    forPushNode(state, tree);
    return forNext(interp, state);
}

static int
forNext(Tcl_Interp *interp, ForState *state)
{
    Node *n;
    ExtNode *e;
    
    if (state->stackSize == 0) {
        forCleanup(state);
        return TCL_OK;
    }

    n = state->stack[--state->stackSize];
    while (isInternal(n)) {
        IntNode *i = (IntNode *)n;
        forPushNode(state, i->child[1]);
        nodeAssign(&n, i->child[0]);
    }

    e = (ExtNode *)n;
    if (!Tcl_ObjSetVar2(interp, state->keyVar, NULL, e->key, TCL_LEAVE_ERR_MSG) ||
        (state->type == T_MAP && !Tcl_ObjSetVar2(interp, state->valueVar, NULL, e->value,
                                                 TCL_LEAVE_ERR_MSG))) {
        releaseNode((Node *)e);
        forCleanup(state);
        return TCL_ERROR;
    }

    releaseNode((Node *)e);
    Tcl_NRAddCallback(interp, forCallback, state, NULL, NULL, NULL);
    return Tcl_NREvalObj(interp, state->script, 0);
}

static int
forCallback(ClientData data[], Tcl_Interp *interp, int result)
{
    ForState *state;
    
    state = (ForState *)data[0];

    switch (result) {
    case TCL_OK:
    case TCL_CONTINUE: return forNext(interp, state);
    case TCL_BREAK: result = TCL_OK;
    }

    forCleanup(state);
    return result;
}

static void
forCleanup(ForState *state)
{
    int i;
    
    Tcl_DecrRefCount(state->keyVar);
    if (state->type == T_MAP) Tcl_DecrRefCount(state->valueVar);
    Tcl_DecrRefCount(state->script);
    for (i = 0; i < state->stackSize; i++) releaseNode(state->stack[i]);
    ckfree(state->stack);
    ckfree(state);
}

static void
forPushNode(ForState *state, Node *node)
{
    if (state->stackSize == state->stackCapacity) {
        state->stackCapacity *= 2;
        state->stack = ckrealloc(state->stack, state->stackCapacity*sizeof(Node *));
    }

    retainNode(node);
    state->stack[state->stackSize++] = node;
}

static int
nodeAset(Tcl_Interp *interp, Node *n, Tcl_Obj *arrayName)
{
    IntNode *i;
    ExtNode *e;

    if (!n) return TCL_OK;
    if (isInternal(n)) {
        i = (IntNode *)n;
        return (nodeAset(interp, i->child[0], arrayName) == TCL_ERROR ||
                nodeAset(interp, i->child[1], arrayName) == TCL_ERROR)
            ? TCL_ERROR : TCL_OK;
    }
    e = (ExtNode *)n;
    return Tcl_ObjSetVar2(interp, arrayName, e->key, e->value, TCL_LEAVE_ERR_MSG)
        ? TCL_OK : TCL_ERROR;
}

int
treeCmd(ClientData cd, Tcl_Interp *interp,
	int objc, Tcl_Obj *const objv[])
{
    return Tcl_NRCallObjProc(interp, treeNRCmd, cd, objc, objv);
}

int
treeNRCmd(ClientData cd, Tcl_Interp *interp,
          int objc, Tcl_Obj *const objv[])
{
    int index;
    Node *tree;
    ExtNode *node;
    Tcl_Obj *obj;
    static const char *const options[] = {
        "_getchild", "_info", "aset", "create", "exists",
        "for",       "get",   "get*", "getor",  "keys",
        "max",       "merge", "min",  "remove", "replace",
        "replace*",  "set",   "set*", "size",   "tolist",
        "unset",     NULL
    };
    enum option {
        OPT_GETCHILD,    OPT_INFO,  OPT_ASET,    OPT_CREATE, OPT_EXISTS,
        OPT_FOR,         OPT_GET,   OPT_GETSTAR, OPT_GETOR,  OPT_KEYS,
        OPT_MAX,         OPT_MERGE, OPT_MIN,     OPT_REMOVE, OPT_REPLACE,
        OPT_REPLACESTAR, OPT_SET,   OPT_SETSTAR, OPT_SIZE,   OPT_TOLIST,
        OPT_UNSET
    };
    
    if (objc < 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "cmd ?arg ...?");
	return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], options, "option", 0,
                            &index) != TCL_OK) {
        return TCL_ERROR;
    }
    switch ((enum option)index) {
    case OPT_GETCHILD: {
        int dir;
        
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "treeValue dir");
            return TCL_ERROR;
        }
        if (getTree(T_MAP, interp, objv[2], &tree) != TCL_OK ||
            Tcl_GetIntFromObj(interp, objv[3], &dir) != TCL_OK)
            return TCL_ERROR;
        if (!tree || !isInternal(tree)) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("tree has no children", -1));
            return TCL_ERROR;
        }

        retainNode(((IntNode *)tree)->child[dir&1]);
        Tcl_SetObjResult(interp, newTreeObj(T_MAP, ((IntNode *)tree)->child[dir&1]));
        return TCL_OK;
    }
    case OPT_INFO: {
        Tcl_Obj *info[4];
            
        if (objc != 3) goto badNumArgsNeedTree;
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR) return TCL_ERROR;
        if (!tree) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj("empty", -1));
            return TCL_OK;
        }
        
        if (isInternal(tree)) {
            IntNode *n = (IntNode *)tree;
            info[0] = Tcl_NewStringObj("internal", -1);
            info[1] = Tcl_NewIntObj(n->refCount >> 1);
            info[2] = Tcl_NewIntObj(n->byte);
            info[3] = Tcl_NewIntObj(n->otherBits);
        } else {
            ExtNode *n = (ExtNode *)tree;
            info[0] = Tcl_NewStringObj("external", -1);
            info[1] = Tcl_NewIntObj(n->refCount >> 1);
            info[2] = n->key;
            info[3] = n->value;
        }
        Tcl_SetObjResult(interp, Tcl_NewListObj(4, info));
        return TCL_OK;
    }
    case OPT_ASET:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "treeValue arrayName");
            return TCL_ERROR;
        }
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR)
            return TCL_ERROR;
        return nodeAset(interp, tree, objv[3]);
    case OPT_CREATE:
        if ((objc & 1) == 1) {
            Tcl_WrongNumArgs(interp, 2, objv, "?key value ...?");
            return TCL_ERROR;
        }
        tree = treeCreate(objc-2, objv+2);
        Tcl_SetObjResult(interp, newTreeObj(T_MAP, tree));
        return TCL_OK;
    case OPT_EXISTS:
        if (objc != 4) {
badNumArgsNeedTreeKey:
            Tcl_WrongNumArgs(interp, 2, objv, "treeValue key");
            return TCL_ERROR;
        }
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR)
            return TCL_ERROR;
        Tcl_SetObjResult(interp, Tcl_NewBooleanObj(nodeGet(tree, objv[3]) != NULL));
        return TCL_OK;
    case OPT_FOR:
        return treeForCmd(T_MAP, interp, objc, objv);
    case OPT_GET:
        if (objc != 4) goto badNumArgsNeedTreeKey;
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR) return TCL_ERROR;
        node = nodeGet(tree, objv[3]);
        if (!node) {
            Tcl_SetObjResult(interp, Tcl_ObjPrintf("key \"%s\" not known in tree", Tcl_GetString(objv[3])));
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, node->value);
        return TCL_OK;
    case OPT_GETSTAR:
        if (objc != 4) goto badNumArgsNeedTreeKey;
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR) return TCL_ERROR;
        node = nodeGet(tree, objv[3]);
        Tcl_SetObjResult(interp, node ? Tcl_NewListObj(1, &node->value) : Tcl_NewObj());
        return TCL_OK;
    case OPT_GETOR:
        if (objc != 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "treeValue key default");
            return TCL_ERROR;
        }
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR) return TCL_ERROR;
        node = nodeGet(tree, objv[3]);
        Tcl_SetObjResult(interp, node ? node->value : objv[4]);
        return TCL_OK;
    case OPT_KEYS:
        if (objc != 3) goto badNumArgsNeedTree;
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR) return TCL_ERROR;
        Tcl_SetObjResult(interp, treeKeys(tree));
        return TCL_OK;
    case OPT_MAX:
        if (objc != 3) goto badNumArgsNeedTree;
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR) return TCL_ERROR;
        if (tree) {
            Tcl_Obj *ls[2];
            while (isInternal(tree)) tree = ((IntNode *)tree)->child[1];
            ls[0] = ((ExtNode *)tree)->key;
            ls[1] = ((ExtNode *)tree)->value;
            Tcl_SetObjResult(interp, Tcl_NewListObj(2, ls));
        }
        return TCL_OK;
    case OPT_MERGE:
        return treeObjMerge(T_MAP, interp, objc-2, objv+2);
    case OPT_MIN:
        if (objc != 3) goto badNumArgsNeedTree;
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR) return TCL_ERROR;
        if (tree) {
            Tcl_Obj *ls[2];
            while (isInternal(tree)) tree = ((IntNode *)tree)->child[0];
            ls[0] = ((ExtNode *)tree)->key;
            ls[1] = ((ExtNode *)tree)->value;
            Tcl_SetObjResult(interp, Tcl_NewListObj(2, ls));
        }
        return TCL_OK;
    case OPT_REMOVE:
        if (objc != 4) goto badNumArgsNeedTreeKey;
        if (treeObjReplace(T_MAP, interp, objv[2], objv[3], NULL, &obj, NULL) == TCL_ERROR)
            return TCL_ERROR;
        Tcl_SetObjResult(interp, obj);
        return TCL_OK;
    case OPT_REPLACE:
    case OPT_REPLACESTAR:
        if (objc != 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "treeValue key value");
            return TCL_ERROR;
        }
        if (index == OPT_REPLACE) {
            obj = objv[4];
        } else if (extractSingle(interp, objv[4], &obj) == TCL_ERROR) {
            return TCL_ERROR;
        }
        if (treeObjReplace(T_MAP, interp, objv[2], objv[3], obj, &obj, NULL) == TCL_ERROR)
            return TCL_ERROR;
        Tcl_SetObjResult(interp, obj);
        return TCL_OK;
    case OPT_SET:
    case OPT_SETSTAR:
        if (objc != 5) {
            Tcl_WrongNumArgs(interp, 2, objv, "varName key value");
            return TCL_ERROR;
        }
        if (index == OPT_SET) {
            obj = objv[4];
        } else if (extractSingle(interp, objv[4], &obj) == TCL_ERROR) {
            return TCL_ERROR;
        }
        return treeSetCmd(T_MAP, interp, objv[2], objv[3], obj);
    case OPT_SIZE:
        if (objc != 3) {
badNumArgsNeedTree:
            Tcl_WrongNumArgs(interp, 2, objv, "treeValue");
            return TCL_ERROR;
        }
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR)
            return TCL_ERROR;
        Tcl_SetObjResult(interp, Tcl_NewIntObj(nodeSize(tree)));
        return TCL_OK;
    case OPT_TOLIST:
        if (objc != 3) goto badNumArgsNeedTree;
        if (getTree(T_MAP, interp, objv[2], &tree) == TCL_ERROR) return TCL_ERROR;
        Tcl_SetObjResult(interp, treeToList(tree));
        return TCL_OK;
    case OPT_UNSET:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "varName key");
            return TCL_ERROR;
        }
        return treeSetCmd(T_MAP, interp, objv[2], objv[3], NULL);
    }

    /* Not reached */
    return TCL_OK;
}

int
treesetCmd(ClientData cd, Tcl_Interp *interp,
           int objc, Tcl_Obj *const objv[])
{
    return Tcl_NRCallObjProc(interp, treesetNRCmd, cd, objc, objv);
}

/* Note: not the same as treeSetCmd! */
int
treesetNRCmd(ClientData cd, Tcl_Interp *interp,
             int objc, Tcl_Obj *const objv[])
{
    int index;
    Node *tree;
    ExtNode *node;
    Tcl_Obj *obj;
    static const char *const options[] = {
        "add",    "contains", "create", "for",    "get*", "merge",
        "remove", "set",      "size",   "tolist", "unset",
        NULL
    };
    enum option {
        OPT_ADD,    OPT_CONTAINS, OPT_CREATE, OPT_FOR,  OPT_GETSTAR,
        OPT_MERGE,  OPT_REMOVE,   OPT_SET,    OPT_SIZE, OPT_TOLIST,
        OPT_UNSET
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
    case OPT_ADD:
        if (objc != 4) {
badNumArgsNeedTreeKey:
            Tcl_WrongNumArgs(interp, 2, objv, "set value");
            return TCL_ERROR;
        }

        if (treeObjReplace(T_SET, interp, objv[2], objv[3], objv[3],
                           &obj, NULL) == TCL_ERROR) {
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, obj);
        return TCL_OK;
    case OPT_CONTAINS:
        if (objc != 4)
            goto badNumArgsNeedTreeKey;
        if (getTree(T_SET, interp, objv[2], &tree) == TCL_ERROR)
            return TCL_ERROR;
        Tcl_SetObjResult(interp, Tcl_NewBooleanObj(nodeGet(tree, objv[3]) != NULL));
        return TCL_OK;
    case OPT_CREATE:
        tree = treesetCreate(objc-2, objv+2);
        Tcl_SetObjResult(interp, newTreeObj(T_SET, tree));
        return TCL_OK;
    case OPT_FOR:
        return treeForCmd(T_SET, interp, objc, objv);
    case OPT_GETSTAR:
        if (objc != 4)
            goto badNumArgsNeedTreeKey;
        if (getTree(T_SET, interp, objv[2], &tree) == TCL_ERROR)
            return TCL_ERROR;
        node = nodeGet(tree, objv[3]);
        Tcl_SetObjResult(interp, node ? Tcl_NewListObj(1, &node->value) : Tcl_NewObj());
        return TCL_OK;
    case OPT_MERGE:
        return treeObjMerge(T_SET, interp, objc-2, objv+2);
    case OPT_REMOVE:
        if (objc != 4)
            goto badNumArgsNeedTreeKey;
        if (treeObjReplace(T_SET, interp, objv[2], objv[3], NULL,
                           &obj, NULL) == TCL_ERROR) {
            return TCL_ERROR;
        }
        Tcl_SetObjResult(interp, obj);
        return TCL_OK;
    case OPT_SET:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "varName value");
            return TCL_ERROR;
        }
        return treeSetCmd(T_SET, interp, objv[2], objv[3], objv[3]);
    case OPT_SIZE:
        if (objc != 3) {
badNumArgsNeedTree:
            Tcl_WrongNumArgs(interp, 2, objv, "set");
            return TCL_ERROR;
        }
        if (getTree(T_SET, interp, objv[2], &tree) == TCL_ERROR)
            return TCL_ERROR;
        Tcl_SetObjResult(interp, Tcl_NewIntObj(nodeSize(tree)));
        return TCL_OK;
    case OPT_TOLIST:
        if (objc != 3)
            goto badNumArgsNeedTree;
        if (getTree(T_SET, interp, objv[2], &tree) == TCL_ERROR)
            return TCL_ERROR;
        Tcl_SetObjResult(interp, treeKeys(tree));
        return TCL_OK;
    case OPT_UNSET:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "varName value");
            return TCL_ERROR;
        }
        return treeSetCmd(T_SET, interp, objv[2], objv[3], NULL);
    }

    /* Not reached */
    return TCL_OK;
}
