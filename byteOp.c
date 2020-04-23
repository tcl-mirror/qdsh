#include <string.h>
#include <tcl.h>

enum op {OP_AND, OP_OR, OP_XOR};

static int
byteOpCmd(ClientData cd, Tcl_Interp *interp,
	  int objc, Tcl_Obj *const objv[])
{
    Tcl_Obj *longer, *shorter, *tmp;
    unsigned char *lp, *sp, *tmpp;
    int i, llen, slen, tmplen, repeat = 0;

    if (objc == 4 && strcmp(Tcl_GetString(objv[1]), "-repeat") == 0) {
	repeat = 1;
	objv++;
    } else if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "?-repeat? bytes bytes");
	return TCL_ERROR;
    }

    longer = objv[1];
    shorter = objv[2];
    lp = Tcl_GetByteArrayFromObj(longer, &llen);
    sp = Tcl_GetByteArrayFromObj(shorter, &slen);
    
    if (slen > llen || (slen == llen && Tcl_IsShared(longer) && !Tcl_IsShared(shorter))) {
	tmp = longer; tmpp = lp; tmplen = llen;
	longer = shorter; lp = sp; llen = slen;
	shorter = tmp; sp = tmpp; slen = tmplen;
    }

    if (Tcl_IsShared(longer)) {
	longer = Tcl_DuplicateObj(longer);
	lp = Tcl_GetByteArrayFromObj(longer, NULL);
    }

    if (repeat) {
	switch ((enum op)cd) {
	case OP_AND: for (i = 0; i < llen; i++) lp[i] &= sp[i % slen]; break;
	case OP_OR: for (i = 0; i < llen; i++) lp[i] |= sp[i % slen]; break;
	case OP_XOR: for (i = 0; i < llen; i++) lp[i] ^= sp[i % slen]; break;
	}
    } else {
	switch ((enum op)cd) {
	case OP_AND: for (i = 0; i < slen; i++) lp[i] &= sp[i]; break;
	case OP_OR: for (i = 0; i < slen; i++) lp[i] |= sp[i]; break;
	case OP_XOR: for (i = 0; i < slen; i++) lp[i] ^= sp[i]; break;
	}
    }

    Tcl_InvalidateStringRep(longer);
    Tcl_SetObjResult(interp, longer);
    return TCL_OK;
}

static int
byteInvCmd(ClientData cd, Tcl_Interp *interp,
	   int objc, Tcl_Obj *const objv[])
{
    int len, i;
    unsigned char *ptr;
    Tcl_Obj *res;
    
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "bytearray");
	return TCL_ERROR;
    }

    res = Tcl_IsShared(objv[1]) ? Tcl_DuplicateObj(objv[1]) : objv[1];
    ptr = Tcl_GetByteArrayFromObj(res, &len);
    for (i = 0; i < len; i++) ptr[i] = ~ptr[i];
    Tcl_InvalidateStringRep(res);
    Tcl_SetObjResult(interp, res);
    return TCL_OK;
}

/* [byte_dup a b] returns a duplicate of a, using b's storage if possible */
static int
byteDupCmd(ClientData cd, Tcl_Interp *interp,
	   int objc, Tcl_Obj *const objv[])
{
    int srcLen, dstLen;
    unsigned char *dst, *src;
    Tcl_Obj *res;

    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "bytearray");
	return TCL_ERROR;
    }

    src = Tcl_GetByteArrayFromObj(objv[1], &srcLen);
    dst = Tcl_GetByteArrayFromObj(objv[2], &dstLen);
    if (!Tcl_IsShared(objv[2]) && srcLen == dstLen) {
	Tcl_InvalidateStringRep(objv[2]);
	memmove(dst, src, srcLen);
	res = objv[2];
    } else {
	res = Tcl_DuplicateObj(objv[1]);
    }
    Tcl_SetObjResult(interp, res);
    return TCL_OK;
}

void
byteOpInit(Tcl_Interp *interp) {
    Tcl_CreateObjCommand(interp, "byte_and", byteOpCmd, (ClientData)OP_AND, NULL);
    Tcl_CreateObjCommand(interp, "byte_or", byteOpCmd, (ClientData)OP_OR, NULL);
    Tcl_CreateObjCommand(interp, "byte_xor", byteOpCmd, (ClientData)OP_XOR, NULL);
    Tcl_CreateObjCommand(interp, "byte_inv", byteInvCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "byte_dup", byteDupCmd, NULL, NULL);
}
