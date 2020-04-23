#ifndef _CURSOR_H
#define _CURSOR_H

typedef struct Cursor {
    Tcl_Obj *strObj, *posObj, *auxObj;
    int bytePos;
    int charPos;
} Cursor;

Cursor *getCursorFromObj(Tcl_Interp *, Tcl_Obj *);
int cursorCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
Tcl_Obj *newCursorObj(Tcl_Obj *string, int bytePos, int charPos);

#define GET_CURSOR_FROM_OBJ(obj) \
  ((obj)->internalRep.otherValuePtr)

#endif /* !defined(_CURSOR_H) */
