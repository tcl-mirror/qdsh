#include <tcl.h>
#include <string.h>
#include "qdsh.h"

typedef struct Node {
    Tcl_Obj *key;
    Tcl_Obj *val;
    struct Node *prev;
    struct Node *next;
} Node;

typedef struct {
    int size;
    int max;
    Node *list;
    Tcl_HashTable table;
} LRU;

static void
freeLRU(ClientData cd)
{
    Node *n, *cur;
    LRU *lru = (LRU *)cd;

    n = lru->list;
    if (n) {
        do {
            Tcl_DecrRefCount(n->key);
            Tcl_DecrRefCount(n->val);
            cur = n;
            n = n->next;
            ckfree(cur);
        } while (n != lru->list);
    }
    Tcl_DeleteHashTable(&lru->table);
}

static Tcl_Obj *
lruKeys(LRU *lru)
{
    Node *n;
    Tcl_Obj *ls = Tcl_NewListObj(lru->size, NULL);

    n = lru->list;
    if (n) {
        do {
            Tcl_ListObjAppendElement(NULL, ls, n->key);
            n = n->next;
        } while (n != lru->list);
    }
    return ls;
}

static void
insertAt(Node **loc, Node *node)
{
    node->next = *loc;
    node->prev = (*loc)->prev;
    (*loc)->prev->next = node;
    (*loc)->prev = node;
    *loc = node;
}

static void
moveToHead(LRU *lru, Node *node)
{
    if (lru->list != node) {
	node->next->prev = node->prev;
	node->prev->next = node->next;
	insertAt(&lru->list, node);
    }
}

static int
lruHandler(ClientData cd, Tcl_Interp *interp,
           int objc, Tcl_Obj *const objv[])
{
    int index, isNew;
    LRU *lru;
    Tcl_HashEntry *entry;
    Node *node;
    static const char *const options[] = {
        "delete", "get", "get*", "keys", "max", "put", "size", NULL
    };
    enum option {
        OPT_DELETE, OPT_GET, OPT_GETSTAR, OPT_KEYS, OPT_MAX, OPT_PUT, OPT_SIZE
    };

    lru = (LRU *)cd;
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmd args ...");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], options, "option", 0,
                            &index) != TCL_OK) {
        return TCL_ERROR;
    }
    switch ((enum option)index) {
    case OPT_DELETE:
	if (objc != 3) {
	    Tcl_WrongNumArgs(interp, 2, objv, "key");
	    return TCL_ERROR;
	}
        entry = Tcl_FindHashEntry(&lru->table, Tcl_GetString(objv[2]));
	if (entry) {
	    node = (Node *)Tcl_GetHashValue(entry);
	    node->next->prev = node->prev;
	    node->prev->next = node->next;
	    if (lru->list == node)
		lru->list = lru->size == 1 ? NULL : node->next;
	    Tcl_DeleteHashEntry(entry);
	    Tcl_DecrRefCount(node->key);
	    Tcl_DecrRefCount(node->val);
	    ckfree(node);
	    lru->size--;
	}
	return TCL_OK;
    case OPT_GET:
	if (objc != 3 && objc != 4) {
	    Tcl_WrongNumArgs(interp, 2, objv, "key ?default?");
	    return TCL_ERROR;
	}
	entry = Tcl_FindHashEntry(&lru->table, Tcl_GetString(objv[2]));
	if (entry) {
	    node = (Node *)Tcl_GetHashValue(entry);
	    moveToHead(lru, node);
	    Tcl_SetObjResult(interp, node->val);
	} else if (objc == 4) {
	    Tcl_SetObjResult(interp, objv[3]);
	} else {
	    return errorMsg(interp, "no such key");
	}
	return TCL_OK;
    case OPT_GETSTAR:
        if (objc != 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "key");
            return TCL_ERROR;
        }
        entry = Tcl_FindHashEntry(&lru->table, Tcl_GetString(objv[2]));
        if (entry) {
            node = (Node *)Tcl_GetHashValue(entry);
            moveToHead(lru, node);
	    Tcl_SetObjResult(interp, Tcl_NewListObj(1, &node->val));
	}
        return TCL_OK;
    case OPT_KEYS:
        if (objc != 2) {
            goto zeroArg;
        }
        Tcl_SetObjResult(interp, lruKeys(lru));
        return TCL_OK;
    case OPT_MAX:
        if (objc != 2) {
            goto zeroArg;
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj(lru->max));
        return TCL_OK;
    case OPT_PUT:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "key value");
            return TCL_ERROR;
        }
        isNew = 0;
        entry = Tcl_CreateHashEntry(&lru->table, Tcl_GetString(objv[2]), &isNew);
        if (isNew) {
            if (lru->size == lru->max) {
		/* Take over tail node and shift up */
                node = lru->list->prev;
		lru->list = node;
                Tcl_DeleteHashEntry(Tcl_FindHashEntry(&lru->table, Tcl_GetString(node->key)));
		Tcl_SetObjResult(interp, Tcl_NewListObj(2, (Tcl_Obj **)node)); /* key, val */
            } else {
                node = ckalloc(sizeof(Node));
                memset(node, 0, sizeof(Node));
		if (lru->list == NULL) {
		    lru->list = node;
                    node->next = node->prev = node;
                } else {
		    insertAt(&lru->list, node);
		}
		lru->size++;
	    }
            assignObjLoc(&node->key, objv[2]);
            assignObjLoc(&node->val, objv[3]);
            Tcl_SetHashValue(entry, (ClientData)node);
        } else {
            node = (Node *)Tcl_GetHashValue(entry);
	    Tcl_SetObjResult(interp, Tcl_NewListObj(2, (Tcl_Obj **)node)); /* key, val */
            assignObjLoc(&node->val, objv[3]);
        }
        return TCL_OK;
    case OPT_SIZE:
        if (objc != 2) {
            goto zeroArg;
        }
        Tcl_SetObjResult(interp, Tcl_NewIntObj(lru->size));
        return TCL_OK;
    }

zeroArg:
    Tcl_WrongNumArgs(interp, 2, objv, NULL);
    return TCL_ERROR;
}

int
lruCmd(ClientData cd, Tcl_Interp *interp,
       int objc, Tcl_Obj *const objv[])
{
    int max;
    LRU *lru;
    
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmd max");
        return TCL_ERROR;
    }
    if (Tcl_GetIntFromObj(interp, objv[2], &max) != TCL_OK)
        return TCL_ERROR;
    if (max <= 1)
	return errorMsg(interp, "max must be greater than 1");
    
    lru = ckalloc(sizeof(LRU));
    lru->max = max;
    lru->size = 0;
    lru->list = NULL;
    Tcl_InitHashTable(&lru->table, TCL_STRING_KEYS);
    return ckCreateCmd(interp, Tcl_GetString(objv[1]), lruHandler,
		       (ClientData)lru, freeLRU) ? TCL_OK : TCL_ERROR;
}
