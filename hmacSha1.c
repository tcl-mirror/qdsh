#include <string.h>
#include <tcl.h>
#include <mbedtls/sha1.h>

#define BLOCK_SIZE 64

int
hmacSha1Cmd(ClientData cd, Tcl_Interp *interp,
	    int objc, Tcl_Obj *const objv[])
{
    int i, keyLen, msgLen;
    unsigned char *key, *msg;
    unsigned char keyBuf[BLOCK_SIZE], digest[20], keyHash[20];
    mbedtls_sha1_context ctx;
    
    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, NULL);
	return TCL_ERROR;
    }

    key = Tcl_GetByteArrayFromObj(objv[1], &keyLen);
    if (keyLen > BLOCK_SIZE) {
	mbedtls_sha1_starts_ret(&ctx);
	mbedtls_sha1_update_ret(&ctx, key, keyLen);
	mbedtls_sha1_finish_ret(&ctx, keyHash);
	key = keyHash;
	keyLen = 20;
    }
    msg = Tcl_GetByteArrayFromObj(objv[2], &msgLen);
    
    memset(keyBuf, 0, BLOCK_SIZE);
    memcpy(keyBuf, key, keyLen);
    for (i = 0; i < BLOCK_SIZE; i++)
	keyBuf[i] ^= 0x36;

    mbedtls_sha1_starts_ret(&ctx);
    mbedtls_sha1_update_ret(&ctx, keyBuf, BLOCK_SIZE);
    mbedtls_sha1_update_ret(&ctx, msg, msgLen);
    mbedtls_sha1_finish_ret(&ctx, digest);

    memset(keyBuf, 0, BLOCK_SIZE);
    memcpy(keyBuf, key, keyLen);
    for (i = 0; i < BLOCK_SIZE; i++)
	keyBuf[i] ^= 0x5c;

    mbedtls_sha1_starts_ret(&ctx);
    mbedtls_sha1_update_ret(&ctx, keyBuf, BLOCK_SIZE);
    mbedtls_sha1_update_ret(&ctx, digest, 20);
    mbedtls_sha1_finish_ret(&ctx, digest);

    if (!Tcl_IsShared(objv[2]) && msgLen == 20) {
	Tcl_InvalidateStringRep(objv[2]);
	memcpy(msg, digest, 20);
	Tcl_SetObjResult(interp, objv[2]);
    } else {
	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(digest, 20));
    }

    return TCL_OK;
}
