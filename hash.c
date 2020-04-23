#include <string.h>
#include <tcl.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md5.h>

#include "qdsh.h"

typedef struct {
    size_t ctxSize;
    void (*updateFunc)(void *p, unsigned char *bytes, int len);
    Tcl_Obj *(*getFunc)(void *p);
    void (*resetFunc)(void *p);
} HashType;

typedef struct {
    HashType *hashType;
    unsigned char ctx[1];
} HashInstance;

typedef enum { IN, OUT } HashDir;

typedef struct {
    Tcl_Channel chan;
    HashType *hashType;
    HashDir dir;
    int hashed;
    unsigned char ctx[1];
} HashChan;

static void sha1Update(void *p, unsigned char *bytes, int len);
static Tcl_Obj *sha1Get(void *p);
static void sha1Reset(void *p);

static HashType sha1Hash = {
    sizeof(mbedtls_sha1_context),
    sha1Update,
    sha1Get,
    sha1Reset
};

#if 0
static void md5Update(void *p, unsigned char *bytes, int len);
static Tcl_Obj *md5Get(void *p);
static void md5Reset(void *p);

static HashType md5Hash = {
    sizeof(mbedtls_md5_context),
    md5Update,
    md5Get,
    md5Reset
};

static void md5Update(void *p, unsigned char *bytes, int len)
{
    mbedtls_md5_context *ctx = p;
    mbedtls_md5_update_ret(ctx, bytes, len);
}

static Tcl_Obj *md5Get(void *p)
{
    unsigned char digest[16];
    mbedtls_md5_context *ctx = p;
    mbedtls_md5_finish_ret(ctx, digest);
    return Tcl_NewByteArrayObj(digest, 16);
}

static void md5Reset(void *p)
{
    mbedtls_md5_context *ctx = p;
    mbedtls_md5_starts_ret(ctx);
}
#endif

static void hashCtxFree(ClientData);
static int hashCtxCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
static int hashCtxInstanceCmd(ClientData, Tcl_Interp *, int, Tcl_Obj *const[]);
    
static void sha1Update(void *p, unsigned char *bytes, int len)
{
    mbedtls_sha1_context *ctx = p;
    mbedtls_sha1_update_ret(ctx, bytes, len);
}

static Tcl_Obj *sha1Get(void *p)
{
    unsigned char digest[20];
    mbedtls_sha1_context *ctx = p;
    mbedtls_sha1_finish_ret(ctx, digest);
    return Tcl_NewByteArrayObj(digest, 20);
}

static void sha1Reset(void *p)
{
    mbedtls_sha1_context *ctx = p;
    mbedtls_sha1_starts_ret(ctx);
}

static int
digestMd5Cmd(ClientData cd, Tcl_Interp *interp,
	     int objc, Tcl_Obj *const objv[])
{
    mbedtls_md5_context ctx;
    int len;
    unsigned char *bytes, *digest;
    Tcl_Obj *res;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "string");
	return TCL_ERROR;
    }

    bytes = Tcl_GetByteArrayFromObj(objv[1], &len);
    mbedtls_md5_starts_ret(&ctx);
    mbedtls_md5_update_ret(&ctx, bytes, len);
    
    Tcl_SetObjResult(interp, (res = Tcl_NewByteArrayObj(NULL, 16)));
    digest = Tcl_GetByteArrayFromObj(res, NULL);
    mbedtls_md5_finish_ret(&ctx, digest);
    return TCL_OK;
}

static int
digestSha1Cmd(ClientData cd, Tcl_Interp *interp,
	      int objc, Tcl_Obj *const objv[])
{
    mbedtls_sha1_context ctx;
    int len;
    unsigned char *bytes;
    unsigned char digest[20];
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "string");
	return TCL_ERROR;
    }

    bytes = Tcl_GetByteArrayFromObj(objv[1], &len);
    mbedtls_sha1_starts_ret(&ctx);
    mbedtls_sha1_update_ret(&ctx, bytes, len);
    mbedtls_sha1_finish_ret(&ctx, digest);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(digest, 20));
    return TCL_OK;
}


static int
digestSha256Cmd(ClientData cd, Tcl_Interp *interp,
		int objc, Tcl_Obj *const objv[])
{
    mbedtls_sha256_context ctx;
    int len;
    unsigned char *bytes;
    unsigned char digest[32];
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "data");
	return TCL_ERROR;
    }

    bytes = Tcl_GetByteArrayFromObj(objv[1], &len);
    mbedtls_sha256_starts_ret(&ctx, (int)cd);
    mbedtls_sha256_update_ret(&ctx, bytes, len);
    mbedtls_sha256_finish_ret(&ctx, digest);
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(digest, sizeof digest));
    return TCL_OK;
}

static int
sha1Cmd(ClientData cd, Tcl_Interp *interp,
	int objc, Tcl_Obj *const objv[])
{
    mbedtls_sha1_context ctx;
    int len;
    unsigned char *bytes;
    unsigned char digest[20];
    char hex[40];
    int i;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "string");
	return TCL_ERROR;
    }

    bytes = Tcl_GetByteArrayFromObj(objv[1], &len);
    mbedtls_sha1_starts_ret(&ctx);
    mbedtls_sha1_update_ret(&ctx, bytes, len);
    mbedtls_sha1_finish_ret(&ctx, digest);
    for (i = 0; i < 20; i++) {
        hex[i*2] = digest[i] >> 4;
	hex[i*2+1] = digest[i] & 0xf;
    }
    for (i = 0; i < 40; i++) {
        if (hex[i] < 10) {
	    hex[i] += '0';
	} else {
	    hex[i] += ('a'-10);
	}
    }
    Tcl_SetObjResult(interp, Tcl_NewStringObj(hex, 40));
    return TCL_OK;
}

static int
hashCtxCmd(ClientData cd, Tcl_Interp *interp,
	   int objc, Tcl_Obj *const objv[])
{
    HashInstance *hash;
    HashType *hashType = (HashType *)cd;

    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmdName");
        return TCL_ERROR;
    }

    hash = ckalloc(sizeof(HashInstance) + hashType->ctxSize - 1);
    hash->hashType = hashType;
    hashType->resetFunc(&hash->ctx);
    Tcl_CreateObjCommand(interp, Tcl_GetString(objv[1]), hashCtxInstanceCmd,
                         (ClientData)hash, hashCtxFree);
    return TCL_OK;
    
}

static int
hashCtxInstanceCmd(ClientData cd, Tcl_Interp *interp,
                   int objc, Tcl_Obj *const objv[])
{
    static const char *const options[] = {
        "update", "reset", "get", NULL
    };
    enum option {
        OPT_UPDATE, OPT_RESET, OPT_GET
    };
    int index, len;
    unsigned char *bytes;
    HashType *hashType;
    void *ctx;
    HashInstance *hash;

    hash = (HashInstance *)cd;
    hashType = hash->hashType;
    ctx = &hash->ctx;
    
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmd ?arg ...?");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], options, "option", 0,
                            &index) != TCL_OK) {
        return TCL_ERROR;
    }
    switch ((enum option)index) {
    case OPT_UPDATE:
        if (objc != 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "data");
            return TCL_ERROR;
        }
        bytes = Tcl_GetByteArrayFromObj(objv[2], &len);
        hashType->updateFunc(ctx, bytes, len);
        return TCL_OK;
    case OPT_GET:
        Tcl_SetObjResult(interp, hashType->getFunc(ctx));
        /* fall through */
    case OPT_RESET:
        hashType->resetFunc(ctx);
        return TCL_OK;
    }

    /* Not reached */
    return TCL_OK;
}

static void hashCtxFree(ClientData cd)
{
    ckfree((HashInstance *)cd);
}

/* Tcl channel type member functions */
static int HashCloseProc(ClientData, Tcl_Interp *);
static int HashInputProc(ClientData, char *, int, int *);
static int HashOutputProc(ClientData, const char *, int, int *);
static void HashWatchProc(ClientData, int);

static const Tcl_ChannelType hashChannelType = {
    "hash",
    TCL_CHANNEL_VERSION_5,
    HashCloseProc,
    HashInputProc,
    HashOutputProc,
    NULL, /* Seek proc. */
    NULL, /* Set option proc. */
    NULL, /* Get option proc. */
    HashWatchProc,
    NULL, /* Get handle proc. */
    NULL, /* close2proc. */
    NULL, /* Block mode proc. */
    NULL, /* Flush proc. */
    NULL, /* Handle proc for event notification. */
    NULL, /* Wide seek proc. */
    NULL, /* Thread action proc. */
    NULL /* Truncate proc. */
};

static int
HashCloseProc(ClientData cd, Tcl_Interp *interp)
{
    ckfree((HashChan *)cd);
    return 0;
}

static int
HashInputProc(ClientData cd, char *buf, int toRead, int *errorCodePtr)
{
    Tcl_Channel parent;
    int r;
    HashChan *state = (HashChan *)cd;

    parent = Tcl_GetStackedChannel(state->chan);
    r = Tcl_ReadRaw(parent, buf, toRead);
    if (r == -1) {
	*errorCodePtr = Tcl_GetErrno();
    } else if (state->dir == IN) {
	state->hashType->updateFunc(&state->ctx, (unsigned char *)buf, r);
	state->hashed += r;
    }
    return r;
}

static int
HashOutputProc(ClientData cd, const char *buf, int toWrite,
	       int *errorCodePtr)
{
    Tcl_Channel parent;
    int r;
    HashChan *state = (HashChan *)cd;

    parent = Tcl_GetStackedChannel(state->chan);
    r = Tcl_WriteRaw(parent, buf, toWrite);
    if (r == -1) {
	*errorCodePtr = Tcl_GetErrno();
    } else if (state->dir == OUT) {
	state->hashType->updateFunc(&state->ctx, (unsigned char *)buf, r);
	state->hashed += r;
    }
    return r;
}

static void
HashWatchProc(ClientData cd, int mask)
{
    Tcl_Channel parent;
    HashChan *state = (HashChan *)cd;

    parent = Tcl_GetStackedChannel(state->chan);
    Tcl_GetChannelType(parent)
        ->watchProc(Tcl_GetChannelInstanceData(parent), mask);
}
    
static int
hashChanGetCmd(ClientData cd, Tcl_Interp *interp,
	       int objc, Tcl_Obj *const objv[])
{
    HashChan *state;
    Tcl_Channel chan;
    
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return TCL_ERROR;
    }
    if (TclGetChannelFromObj(interp, objv[1], &chan, NULL, 0) != TCL_OK) {
        return TCL_ERROR;
    }
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != & hashChannelType) {
	return errorMsg(interp, "not a hash channel");
    }
    state = (HashChan *)Tcl_GetChannelInstanceData(chan);
    Tcl_SetObjResult(interp, state->hashType->getFunc(&state->ctx));
    state->hashType->resetFunc(&state->ctx);
    state->hashed = 0;
    return TCL_OK;
}

static int
hashChanGetBytesHashedCmd(ClientData cd, Tcl_Interp *interp,
			  int objc, Tcl_Obj *const objv[])

{
    HashChan *state;
    Tcl_Channel chan;
    
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel");
	return TCL_ERROR;
    }
    if (TclGetChannelFromObj(interp, objv[1], &chan, NULL, 0) != TCL_OK) {
        return TCL_ERROR;
    }
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != & hashChannelType) {
	return errorMsg(interp, "not a hash channel");
    }
    state = (HashChan *)Tcl_GetChannelInstanceData(chan);
    Tcl_SetObjResult(interp, Tcl_NewIntObj(state->hashed));
    return TCL_OK;
}

static int
hashPushCmd(ClientData cd, Tcl_Interp *interp,
	    int objc, Tcl_Obj *const objv[])
{
    Tcl_Channel chan;
    HashChan *state;
    HashType *hashType = (HashType *)cd;
    int mode;
    HashDir dir;

    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel direction");
	return TCL_ERROR;
    }
    if (TclGetChannelFromObj(interp, objv[1], &chan, &mode, 0) != TCL_OK) {
	return TCL_ERROR;
    }
    if (strcmp(Tcl_GetString(objv[2]), "in") == 0) {
	dir = IN;
    } else if (strcmp(Tcl_GetString(objv[2]), "out") == 0) {
	dir = OUT;
    } else {
	return errorMsg(interp, "direction must be 'in' or 'out'");
    }

    state = ckalloc(sizeof(HashChan) + hashType->ctxSize - 1);
    state->hashType = hashType;
    state->dir = dir;
    state->hashed = 0;
    state->chan = Tcl_StackChannel(interp, &hashChannelType, (ClientData)state,
				   mode, chan);
    if (state->chan == NULL) {
	return TCL_ERROR;
    }
    hashType->resetFunc(&state->ctx);
    return TCL_OK;
}

void
hashInit(Tcl_Interp *interp)
{
    /* Message digest commands -- return byte arrays */
    Tcl_CreateObjCommand(interp, "digest_md5", digestMd5Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "digest_sha1", digestSha1Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "digest_sha256", digestSha256Cmd, (ClientData)0, NULL);
    /*Tcl_CreateObjCommand(interp, "digest_sha512", digestSha256Cmd, (ClientData)1, NULL);*/
    
    Tcl_CreateObjCommand(interp, "sha1", sha1Cmd, NULL, NULL);

    /* Message digest context commands */
    Tcl_CreateObjCommand(interp, "sha1ctx", hashCtxCmd, (ClientData)&sha1Hash, hashCtxFree);
    /*Tcl_CreateObjCommand(interp, "md5ctx", hashCtxCmd, (ClientData)&md5Hash, hashCtxFree);*/

    /* Message digest channels */
    Tcl_CreateObjCommand(interp, "sha1_push", hashPushCmd, (ClientData)&sha1Hash, NULL);
    Tcl_CreateObjCommand(interp, "sha1_chan_get", hashChanGetCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "sha1_chan_get_bytes_hashed", hashChanGetBytesHashedCmd,
			 NULL, NULL);
}
