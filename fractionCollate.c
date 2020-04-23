#include <tcl.h>

#define SQLITE_UTF8 1

int sqlite3_create_collation(
  void*,
  const char *zName,
  int eTextRep,
  void *pArg,
  int(*xCompare)(void*,int,const void*,int,const void*)
);
const char *sqlite3_errmsg(void *);

static int fractionCollFunc(
  void *NotUsed,
  int nKey1, const void *pKey1,
  int nKey2, const void *pKey2
){
  const char *zKey1, *zKey2;
  int i, rc;

  zKey1 = pKey1;
  zKey2 = pKey2;

  /* Compare integer portion */
  rc = 0;
  for(i = 0; ; i++) {
    if( (i == nKey1 || zKey1[i] == '.') &&
        (i == nKey2 || zKey2[i] == '.') ){
      /* Both keys have integer portions of the same number of digits */
      if( rc == 0 )
        break; /* Go on to compare fraction portions */
      return rc;
    }else if( i == nKey1 || zKey1[i] == '.' ){
      return -1;
    }else if( i == nKey2 || zKey2[i] == '.'){
      return 1;
    }else if( rc == 0 ){
      rc = zKey1[i] - zKey2[i];
    }
  }

  if( i == nKey1 && i == nKey2 ){
    return 0; /* Neither have fractional parts */
  }else if ( i < nKey1 && i < nKey2 ){
    i++; /* Both have fractional parts. Skip decimal point */
  }else{
    /* One number has a fractional part and one doesn't. Longer one wins */
    return nKey1 - nKey2;
  }

  /* Compare fraction parts */
  for(; ; i++) {
    if( i == nKey1 && i == nKey2 ){
      return 0;
    }else if( i < nKey1 && i < nKey2 ){
      if( zKey1[i] != zKey2[i] )
        return zKey1[i] - zKey2[i];
    }else{
      /* Equal so far. One has more digits than the other. Longer wins */
      return nKey1 - nKey2;
    }
  }

  return 0;
}

/*
 * WARNING: due to SQLite not exposing enough API, this is zero
 * verification that the given command is a SQLite instance and will
 * happily segfault or worse if you pass in anything else.
 */
int
addFractionCollateCmd(ClientData cd, Tcl_Interp *interp,
                      int objc, Tcl_Obj *const objv[])
{
    Tcl_CmdInfo cmdInfo;
    void **lib;

    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "db");
        return TCL_ERROR;
    }
    
    if (Tcl_GetCommandInfo(interp, Tcl_GetString(objv[1]), &cmdInfo) == 0) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("no such command", -1));
        return TCL_ERROR;
    }

    lib = (void **)cmdInfo.objClientData;
    if (sqlite3_create_collation(*lib, "FRACTION", SQLITE_UTF8, NULL, fractionCollFunc)) {
        Tcl_SetResult(interp, (char *)sqlite3_errmsg(*lib), TCL_VOLATILE);
        return TCL_ERROR;
    }

    return TCL_OK;
}
