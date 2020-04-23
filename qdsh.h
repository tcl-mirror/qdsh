#ifndef _QDSH_H
#define _QDSH_H

/* From tclInt.h */
extern int TclGetChannelFromObj(Tcl_Interp *interp,
                                Tcl_Obj *objPtr, Tcl_Channel *chanPtr,
                                int *modePtr, int flags);
int TclGetIntForIndex(Tcl_Interp *, Tcl_Obj *, int, int *);

/* Compatibility with defunct utf8-only branch */
Tcl_Obj *Tcl_NewStringObjWithCharLength(const char *, int, int);

/* 32-bit pointers */
#define ALIGN_PTR(x) (((x) + 3) & ~3)

/* Generic dup and free procedures for types for which the internal
 * rep is ptrAndLongRep with ptr pointing at a Tcl_Obj. */
void dupCellInternalRep(Tcl_Obj *, Tcl_Obj *);
void freeCellInternalRep(Tcl_Obj *);

/* Helpers for Tcl API */
void freeIntRep(Tcl_Obj *);
int errorMsg(Tcl_Interp *, const char *);
void takeStringRep(Tcl_Obj *, Tcl_Obj *);
void assignObjLoc(Tcl_Obj **, Tcl_Obj *);
Tcl_Command ckCreateCmd(Tcl_Interp *, const char *, Tcl_ObjCmdProc *,
			ClientData, Tcl_CmdDeleteProc *);
Tcl_Command ckCreateNRCmd(Tcl_Interp *, const char *, Tcl_ObjCmdProc *,
			  Tcl_ObjCmdProc *, ClientData, Tcl_CmdDeleteProc *);

/* tclsqlite3.c */
int Sqlite_Init(Tcl_Interp *);

/* lazy.c */
void lazyInit(Tcl_Interp *);

/* ssl.c */
void sslInit(Tcl_Interp *);

/* memo.c */
void memoInit(Tcl_Interp *, char *);

/* byteOp.c */
void byteOpInit(Tcl_Interp *);

/* hmacSha1.c */
int hmacSha1Cmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* record.c */
int recordObjCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* bitset.c */
int bitsetCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* parse.c */
int parseCommandCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
int parseVarNameCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
int parseQuotedCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* regex.c */
int regexMatchCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
int regexSubCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* json.c */
int jsonParseCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* fractionCollate.c */
int addFractionCollateCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* pdf.c */
void pdfInit(Tcl_Interp *);

/* lru.c */
int lruCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* posix.c */
void posixInit(Tcl_Interp *);

/* hash.c */
void hashInit(Tcl_Interp *);
/*int md5Cmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
int md5CtxCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
int sha1Cmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
int sha1SumCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);*/

/* damt.c */
int damtCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* unixSockets.c */
void unixSocketInit(Tcl_Interp *);

/* fluid.c */
int fluidCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* defcmd.c */
int defCmdCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
int defConstCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);

/* intBin.c */
/*int intBinCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);*/

/* packed.c */
int defPackedCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
  
#endif /* !defined(_QDSH_) */
