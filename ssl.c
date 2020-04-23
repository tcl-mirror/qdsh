#include <errno.h>
#include <string.h>
#include <tcl.h>

#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
/*#include <mbedtls/x509.h>*/
#include <mbedtls/sha1.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/error.h>
#include <mbedtls/net.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1.h>
#include <mbedtls/ssl_internal.h>
#include <mbedtls/sha256.h>
/*#include <mbedtls/debug.h>*/
#include <mbedtls/cipher.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>

#include "qdsh.h"

typedef enum {
    PEM_KEY, PEM_PUBKEY, PEM_CERT, PEM_CSR, PEM_CRL
} PemType;

typedef struct {
    PemType type;
    int refCount;
} Pem;

typedef struct {
    PemType type;
    int refCount;
    mbedtls_pk_context key;
} PemKey;

typedef struct {
    PemType type;
    int refCount;
    mbedtls_x509_crt cert;
} PemCert;

typedef struct {
    PemType type;
    int refCount;
    mbedtls_x509_csr csr;
} PemCsr;

typedef struct {
    PemType type;
    int refCount;
    mbedtls_x509_crl crl;
} PemCrl;

typedef struct {
    int capacity;
    int size;
    Pem **list;
} PemList;

typedef struct {
    int refCount;
    mbedtls_ssl_config config;
    mbedtls_ssl_cache_context cache;
    PemList pemList;
} Config;

typedef struct {
    mbedtls_ssl_context ssl;
    Tcl_Channel chan;
    Tcl_TimerToken timer;
    PemList pemList;
    Config *config;
} State;

static void freePemIntRep(Tcl_Obj *);
static void dupPemIntRep(Tcl_Obj *, Tcl_Obj *);
static void pemUpdateString(Tcl_Obj *);

#define GET_PEM_TYPE(x) (((Pem *)(x)->internalRep.otherValuePtr)->type)
#define GET_PEM_PTR(x) ((Pem *)((x)->internalRep.otherValuePtr))

/* BIO -- stacked channel */
static int bioRecv(void *, unsigned char *, size_t);
static int bioSend(void *, const unsigned char *, size_t);

/* Handshake BIO */
static int hsBioRecv(void *, unsigned char *, size_t);
static int hsBioSend(void *, const unsigned char *, size_t);

/* Tcl channel type member functions */
/*static int SslBlockModeProc(ClientData, int);*/
static int SslCloseProc(ClientData, Tcl_Interp *);
static int SslInputProc(ClientData, char *, int, int *);
static int SslOutputProc(ClientData, const char *, int, int *);
static int SslGetOptionProc(ClientData, Tcl_Interp *, const char *,
                            Tcl_DString *);
static void SslWatchProc(ClientData, int);
static int SslNotifyProc(ClientData, int);

static const Tcl_ChannelType sslChannelType = {
    "ssl",
    TCL_CHANNEL_VERSION_5,
    SslCloseProc,
    SslInputProc,
    SslOutputProc,
    NULL, /* Seek proc. */
    NULL, /* Set option proc. */
    SslGetOptionProc,
    SslWatchProc,
    NULL, /* Get handle proc. */
    NULL, /* close2proc. */
    /*SslBlockModeProc*/NULL, 
    NULL, /* Flush proc. */
    SslNotifyProc,
    NULL, /* Wide seek proc. */
    NULL, /* Thread action proc. */
    NULL /* Truncate proc. */
};

const static Tcl_ObjType pemObjType = {
    "pem",
    freePemIntRep,
    dupPemIntRep,
    pemUpdateString,
    NULL
};

typedef char *(*DSWriter)(Tcl_DString *, const char *);
static void confSslState(State *, DSWriter, Tcl_DString *);

static struct {
    char *optName;
    void (*fun)(State *, DSWriter, Tcl_DString *);
} optHandlers[] = {
    {"-ssl_state", confSslState},
    {NULL, NULL}
};

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static Tcl_Interp *curInterp = NULL;

static void
init(void)
{
    static int initialized = 0;
    if (!initialized) {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (unsigned char *)"qdxc", 4);
        initialized = 1;
    }
}

static Pem *
allocPem(PemType type, size_t size)
{
    Pem *pem = ckalloc(size);
    memset(pem, 0, size);
    pem->type = type;
    pem->refCount = 0;
    return pem;
}

static void
pemRetain(Pem *pem)
{
    pem->refCount++;
}

static void
pemRelease(Pem *pem)
{
    if (--pem->refCount <= 0) {
        switch (pem->type) {
        case PEM_KEY:
        case PEM_PUBKEY:
            mbedtls_pk_free(&((PemKey *)pem)->key);
            break;
        case PEM_CERT:
            mbedtls_x509_crt_free(&((PemCert *)pem)->cert);
            break;
        case PEM_CSR:
            mbedtls_x509_csr_free(&((PemCsr *)pem)->csr);
            break;
        case PEM_CRL:
            mbedtls_x509_crl_free(&((PemCrl *)pem)->crl);
            break;
        }
        ckfree(pem);
    }
}

static void
setPem(Tcl_Obj *obj, Pem *pem)
{
    freeIntRep(obj);
    obj->typePtr = &pemObjType;
    obj->internalRep.otherValuePtr = pem;
    pemRetain(pem);
}

static void
initPemList(PemList *pemList)
{
    pemList->capacity = 4;
    pemList->list = ckalloc(sizeof(Pem *) * pemList->capacity);
    pemList->size = 0;
}

static void
appendPemToList(PemList *pemList, Pem *pem)
{
    if (pemList->size >= pemList->capacity) {
        pemList->list = ckrealloc(pemList->list,
                                  sizeof(Pem *) * (pemList->capacity *= 2));
    }
    pemList->list[pemList->size++] = pem;
    pemRetain(pem);
}

static void
freePemList(PemList *pemList)
{
    int i;
    
    for (i = 0; i < pemList->size; i++) {
        pemRelease(pemList->list[i]);
    }
    ckfree(pemList->list);
}

static void
configRetain(Config *config)
{
    config->refCount++;
}

static void
configRelease(Config *config)
{
    if (--config->refCount <= 0) {
        mbedtls_ssl_cache_free(&config->cache);
	if (config->config.p_vrfy != NULL) {
	    Tcl_DecrRefCount((Tcl_Obj *)config->config.p_vrfy);
	}
	if (config->config.p_sni != NULL) {
	    Tcl_DecrRefCount((Tcl_Obj *)config->config.p_sni);
	}
        mbedtls_ssl_config_free(&config->config);
        freePemList(&config->pemList);
        ckfree(config);
    }
}

static char *
sslErrorStatic(int err)
{
    static char buf[256];
    
    mbedtls_strerror(err, buf, sizeof(buf));
    return buf;
}

static Tcl_Obj *
sslError(int err)
{
    return Tcl_NewStringObj(sslErrorStatic(err), -1);
}

static int
setError(Tcl_Interp *interp, char *prefix, int err)
{
    Tcl_Obj *msg;
    msg = prefix ? Tcl_ObjPrintf("%s - %s", prefix, sslErrorStatic(err)) :
        sslError(err);
    Tcl_SetObjResult(interp, msg);
    return TCL_ERROR;
}

static void
freePemIntRep(Tcl_Obj *obj)
{
    pemRelease(GET_PEM_PTR(obj));
}

static void
dupPemIntRep(Tcl_Obj *src, Tcl_Obj *dst)
{
    /* Disallow duplication. Just re-parse later. */
    dst->typePtr = NULL;
}

static void
pemUpdateString(Tcl_Obj *obj)
{
    Pem *pem;
    static char space[16000];

    space[0] = '\0';
    pem = GET_PEM_PTR(obj);
    switch (pem->type) {
    case PEM_PUBKEY:
        break;
    case PEM_KEY:
        mbedtls_pk_write_key_pem(&((PemKey *)pem)->key,
                                 (unsigned char *)space, sizeof space);
        break;
    case PEM_CERT:
        break;
    case PEM_CSR:
        break;
    case PEM_CRL:
        break;
    }
    obj->length = strlen(space);
    obj->bytes = ckalloc(obj->length+1);
    memcpy(obj->bytes, space, obj->length);
    obj->bytes[obj->length] = '\0';
}

static char *
certCN(mbedtls_x509_crt *cert, int *len)
{
    mbedtls_x509_name *name;
    for (name = &cert->subject; name; name = name->next) {
        if (!MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid)) {
            *len = name->val.len;
            return (char *)name->val.p;
        }
    }
    return NULL;
}

static Tcl_Obj *
certSanList(const mbedtls_x509_crt *cert)
{
    Tcl_Obj *ls;
    const mbedtls_x509_sequence *cur;

    ls = Tcl_NewObj();
    for (cur = &cert->subject_alt_names; cur; cur = cur->next) {
        Tcl_ListObjAppendElement(NULL, ls,
                                 Tcl_NewStringObj((char *)cur->buf.p, cur->buf.len));
    }
    return ls;
}

static Tcl_Obj *
certSubj(const mbedtls_x509_crt *cert)
{
    return Tcl_NewByteArrayObj(cert->subject_raw.p, cert->subject_raw.len);
}

/* Return list of: subject, SAN list, is_ca, max_pathlen, key_usage (as an integer) */
static Tcl_Obj *
certInfo(const mbedtls_x509_crt *cert)
{
    Tcl_Obj *res[5];
    
    res[0] = certSubj(cert);
    res[1] = certSanList(cert);
    res[2] = Tcl_NewIntObj(cert->ca_istrue);
    res[3] = Tcl_NewIntObj(cert->max_pathlen);
    res[4] = Tcl_NewIntObj(cert->key_usage);
    return Tcl_NewListObj(5, res);
}

static PemCert *
getCertFromObj(Tcl_Interp *interp, Tcl_Obj *obj)
{
    char *buf;
    int length, ret;
    PemCert *pem;

    if (obj->typePtr == &pemObjType && GET_PEM_TYPE(obj) == PEM_CERT) {
        return (PemCert *)GET_PEM_PTR(obj);
    }

    /* Try to parse */
    buf = Tcl_GetStringFromObj(obj, &length);
    pem = (PemCert *)allocPem(PEM_CERT, sizeof(PemCert));
    mbedtls_x509_crt_init(&pem->cert);

    /* Include final null byte in length */
    if ((ret = mbedtls_x509_crt_parse(&pem->cert, (unsigned char *)buf, length+1)) != 0) {
        ckfree(pem);
        setError(interp, "failed to parse certificate(s)", ret);
        return NULL;
    }
    setPem(obj, (Pem *)pem);
    return pem;
}

static PemKey *
getKeyFromObj(Tcl_Interp *interp, Tcl_Obj *obj)
{
    char *buf;
    int length;
    PemKey *pem;
    
    if (obj->typePtr == &pemObjType) {
        if (GET_PEM_TYPE(obj) == PEM_KEY) {
            return (PemKey *)GET_PEM_PTR(obj);
        }
        goto fail;
    }

    buf = Tcl_GetStringFromObj(obj, &length);
    pem = (PemKey *)allocPem(PEM_KEY, sizeof(PemKey));
    mbedtls_pk_init(&pem->key);

    /* Include final null byte in length */
    if (mbedtls_pk_parse_key(&pem->key, (unsigned char *)buf, length+1, NULL, -1) != 0) {
        ckfree(pem);
fail:
        errorMsg(interp, "failed to parse key");
        return NULL;
    }
    setPem(obj, (Pem *)pem);
    return pem;
}

#if 0
static PemKey *
getPubKeyFromObj(Tcl_Interp *interp, Tcl_Obj *obj)
{
    char *buf;
    int length;
    PemKey *pem;
    
    if (obj->typePtr == &pemObjType) {
        if (GET_PEM_TYPE(obj) == PEM_PUBKEY) {
            return (PemKey *)GET_PEM_PTR(obj);
        }
        goto fail;
    }

    buf = Tcl_GetStringFromObj(obj, &length);
    pem = (PemKey *)allocPem(PEM_PUBKEY, sizeof(PemKey));
    mbedtls_pk_init(&pem->key);

    /* Include final null byte in length */
    if (mbedtls_pk_parse_public_key(&pem->key, (unsigned char *)buf, length+1) != 0) {
        ckfree(pem);
fail:
        errorMsg(interp, "failed to parse key");
        return NULL;
    }
    setPem(obj, (Pem *)pem);
    return pem;
}
#endif /* 0 */

static PemCsr *
getCsrFromObj(Tcl_Interp *interp, Tcl_Obj *obj)
{
    char *buf;
    int length;
    PemCsr *pem;
    
    if (obj->typePtr == &pemObjType) {
        if (GET_PEM_TYPE(obj) == PEM_CSR) {
            return (PemCsr *)GET_PEM_PTR(obj);
        }
        goto fail;
    }

    buf = Tcl_GetStringFromObj(obj, &length);
    pem = (PemCsr *)allocPem(PEM_CSR, sizeof(PemCsr));

    /* Include final null byte in length */
    if (mbedtls_x509_csr_parse(&pem->csr, (unsigned char *)buf, length+1) != 0) {
        ckfree(pem);
fail:
        errorMsg(interp, "failed to parse csr");
        return NULL;
    }
    setPem(obj, (Pem *)pem);
    return pem;
}

static void
timerHandler(ClientData cd)
{
    State *statePtr = (State *)cd;

    statePtr->timer = NULL;
    Tcl_NotifyChannel(statePtr->chan, TCL_READABLE);
}


static int
handshakeCmd(Tcl_Interp *interp, State *state,
	     int (*fn)(mbedtls_ssl_context *),
             int objc, Tcl_Obj *const objv[])
{
    Tcl_Channel chan;
    int ret, i;
    char *errorSubcode = "OTHER";
    static struct {
        int code;
        char *result;
        Tcl_Obj *obj;
    } tab[] = {
        {0, "done", NULL},
        {MBEDTLS_ERR_SSL_WANT_READ, "readable", NULL},
        {MBEDTLS_ERR_SSL_WANT_WRITE, "writable", NULL}
    };
    
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 2, objv, "channel");
        return TCL_ERROR;
    }
    if (TclGetChannelFromObj(interp, objv[2], &chan, NULL, 0) != TCL_OK) {
	return TCL_ERROR;
    }

    mbedtls_ssl_set_bio(&state->ssl, chan, hsBioSend, hsBioRecv, NULL);
    curInterp = interp; /* For sni/verify callback */
    ret = fn(&state->ssl);
    for (i = 0; i < sizeof(tab)/sizeof(*tab); i++) {
        if (ret == tab[i].code) {
            if (tab[i].obj == NULL) {
                tab[i].obj = Tcl_NewStringObj(tab[i].result, -1);
                Tcl_IncrRefCount(tab[i].obj);
            }
            Tcl_SetObjResult(interp, tab[i].obj);
            return TCL_OK;
        }
    }
    switch (ret) {
    case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
	errorSubcode = "ALERT";
	break;
    case MBEDTLS_ERR_SSL_CONN_EOF:
	errorSubcode = "EOF";
	break;
    }
    Tcl_SetObjResult(interp, sslError(ret));
    Tcl_SetErrorCode(interp, "SSL", errorSubcode, NULL);
    return TCL_ERROR;
}

static void
deleteState(State *state)
{
    mbedtls_ssl_free(&state->ssl);
    if (state->timer) {
        Tcl_DeleteTimerHandler(state->timer);
    }
    freePemList(&state->pemList);
    configRelease(state->config);
    ckfree(state);
}

static void
handshakeDelete(ClientData cd)
{
    State *state = (State *)cd;
    if (state->chan == NULL) {
	deleteState(state);
    }
}

static int
handshakeHandler(ClientData cd, Tcl_Interp *interp,
                 int objc, Tcl_Obj *const objv[])
{
    int index;
    State *state;
    static const char *const options[] = {
	"perform", "perform_step", "set_own_cert",
	"set_internal_buffer", "stack_chan", NULL
    };
    enum option {
	OPT_PERFORM, OPT_PERFORM_STEP, OPT_SET_OWN_CERT,
	OPT_SET_INTERNAL_BUFFER, OPT_STACK_CHAN
    };
    Tcl_Channel chan;
    
    state = (State *)cd;
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmd ?arg ...?");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], options, "option", 0,
                            &index) != TCL_OK) {
        return TCL_ERROR;
    }
    switch ((enum option)index) {
    case OPT_PERFORM:
	return handshakeCmd(interp, state, mbedtls_ssl_handshake,
			    objc, objv);
    case OPT_PERFORM_STEP:
	return handshakeCmd(interp, state, mbedtls_ssl_handshake_step,
			    objc, objv);
    case OPT_SET_OWN_CERT:
	if (objc != 4) {
	    Tcl_WrongNumArgs(interp, 2, objv, "cert key");
	    return TCL_ERROR;
	} else {
	    PemCert *cert;
	    PemKey *key;
	    int ret;
	    
	    if (!(cert = getCertFromObj(interp, objv[2])) ||
		!(key = getKeyFromObj(interp, objv[3])))
		return TCL_ERROR;
	    appendPemToList(&state->pemList, (Pem *)cert);
	    appendPemToList(&state->pemList, (Pem *)key);
	    ret = mbedtls_ssl_set_hs_own_cert(&state->ssl, &cert->cert, &key->key);
	    if (ret != 0) return setError(interp, NULL, ret);
	}
	return TCL_OK;
    case OPT_SET_INTERNAL_BUFFER:
	if (objc != 3) {
	    Tcl_WrongNumArgs(interp, 2, objv, "data");
	    return TCL_ERROR;
	} else {
	    unsigned char *data;
	    int len;
	    mbedtls_ssl_context *ssl;

	    data = Tcl_GetByteArrayFromObj(objv[2], &len);
	    ssl = &state->ssl;
	    if (len > MBEDTLS_SSL_IN_BUFFER_LEN -
		(size_t)(ssl->in_hdr - ssl->in_buf)) {
		return errorMsg(interp, "data too large");
	    }
	    memcpy(state->ssl.in_hdr, data, len);
	    state->ssl.in_left = len;
	}
	return TCL_OK;
    case OPT_STACK_CHAN:
	if (objc != 3) {
	    Tcl_WrongNumArgs(interp, 2, objv, "channel");
	    return TCL_ERROR;
	}
	if (TclGetChannelFromObj(interp, objv[2], &chan, NULL, 0) != TCL_OK)
	    return TCL_ERROR;
	state->chan = Tcl_StackChannel(interp, &sslChannelType, (ClientData)state,
				       TCL_READABLE|TCL_WRITABLE, chan);
	if (state->chan == NULL)
	    return TCL_ERROR;
	mbedtls_ssl_set_bio(&state->ssl, state->chan, bioSend, bioRecv, NULL);
	return TCL_OK;
    }

    /* Not reached */
    return TCL_OK;
}

static int
newHandshakeCmd(Tcl_Interp *interp, Config *config,
		int objc, Tcl_Obj *const objv[])
{
    char *server_name = NULL, *opt;
    int i;
    mbedtls_ssl_context *ssl;
    State *state;

    if (objc < 3) {
        Tcl_WrongNumArgs(interp, 2, objv, "cmdName ?options?");
        return TCL_ERROR;
    }

    if (((objc-3) & 1) != 0) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("unpaired option", -1));
        return TCL_ERROR;
    }

    for (i = 3; i < objc; i += 2) {
        opt = Tcl_GetStringFromObj(objv[i], NULL);
        if (strcmp(opt, "-servername") == 0) {
            server_name = Tcl_GetString(objv[i+1]);
	}
    }

    state = ckalloc(sizeof(State));
    if (!ckCreateCmd(interp, Tcl_GetString(objv[2]),
		     handshakeHandler, (ClientData)state,
		     handshakeDelete)) {
	ckfree(state);
	return TCL_ERROR;
    }
    state->chan = NULL;
    state->config = config;
    configRetain(config);
    initPemList(&state->pemList);
    ssl = &state->ssl;
    mbedtls_ssl_init(ssl);
    mbedtls_ssl_setup(ssl, &config->config);
    if (config->config.endpoint == MBEDTLS_SSL_IS_CLIENT && server_name != NULL
        && server_name[0] != '\0') {
        mbedtls_ssl_set_hostname(ssl, server_name);
    }
    return TCL_OK;
}

static int
verifyCallback(void *cd, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    mbedtls_sha1_context ctx;
    unsigned char digest[20];
    Tcl_Obj *cmdObj;
    int ret = 0;
    static Tcl_Obj *ls = NULL;

    if (ls == NULL) {
	mbedtls_sha1_starts_ret(&ctx);
	mbedtls_sha1_update_ret(&ctx, crt->raw.p, crt->raw.len);
	mbedtls_sha1_finish_ret(&ctx, digest);
	ls = Tcl_NewObj();
	Tcl_ListObjAppendElement(NULL, ls, Tcl_NewByteArrayObj(digest, 20));
    } else {
	Tcl_ListObjAppendElement(NULL, ls,
	    Tcl_NewByteArrayObj(crt->serial.p, crt->serial.len));
    }

    if (depth == 0) {
	cmdObj = Tcl_DuplicateObj((Tcl_Obj *)cd);
	Tcl_ListObjAppendElement(NULL, cmdObj, ls);
	Tcl_IncrRefCount(cmdObj);
	ret = Tcl_EvalObjEx(curInterp, cmdObj, TCL_EVAL_GLOBAL|TCL_EVAL_DIRECT);
	Tcl_DecrRefCount(cmdObj);
	ls = NULL;
	if (ret != TCL_OK)
	    return MBEDTLS_ERR_X509_FATAL_ERROR;
    }

    return 0;
}

static int
sniCallback(void *cd, mbedtls_ssl_context *ctx, const unsigned char *sni,
	    size_t len)
{
    Tcl_Obj *cmdObj;

    fprintf(stderr, "sni callback called\n");
    cmdObj = Tcl_DuplicateObj((Tcl_Obj *)cd);
    Tcl_ListObjAppendElement(NULL, cmdObj, Tcl_NewByteArrayObj(sni, len));
    Tcl_IncrRefCount(cmdObj);
    Tcl_EvalObjEx(curInterp, cmdObj, TCL_EVAL_GLOBAL|TCL_EVAL_DIRECT);
    Tcl_DecrRefCount(cmdObj);
    return 0;
}


static int
sslConfigHandler(ClientData cd, Tcl_Interp *interp,
                 int objc, Tcl_Obj *const objv[])
{
    Config *config;
    int index;
    static const char *const options[] = {
	"set_auth_mode", "set_own_cert", "set_ca_chain", "new_handshake",
	"set_verify", "set_sni_callback",
	NULL
    };
    enum option {
        OPT_SET_AUTH_MODE, OPT_SET_OWN_CERT, OPT_SET_CA_CHAIN,
	OPT_NEW_HANDSHAKE, OPT_SET_VERIFY, OPT_SET_SNI_CALLBACK
    };
    PemCert *cert;
    PemKey *key;

    config = (Config *)cd;
    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmd ?arg ...?");
        return TCL_ERROR;
    }
    if (Tcl_GetIndexFromObj(interp, objv[1], options, "option", 0,
                            &index) != TCL_OK) {
        return TCL_ERROR;
    }
    switch ((enum option)index) {
    case OPT_SET_AUTH_MODE:
	if (objc != 3) {
	    Tcl_WrongNumArgs(interp, 2, objv, "mode");
	    return TCL_ERROR;
	} else {
	    char *name = Tcl_GetString(objv[2]);
	    int mode = -1;

	    if (strcmp(name, "none") == 0) {
		mode = MBEDTLS_SSL_VERIFY_NONE;
	    } else if (strcmp(name, "optional") == 0) {
		mode = MBEDTLS_SSL_VERIFY_OPTIONAL;
	    } else if (strcmp(name, "required") == 0) {
		mode = MBEDTLS_SSL_VERIFY_REQUIRED;
	    } else {
		return errorMsg(interp, "unknown auth mode");
	    }
	    mbedtls_ssl_conf_authmode(&config->config, mode);
	}
	break;
    case OPT_SET_OWN_CERT:
        if (objc != 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "cert key");
            return TCL_ERROR;
        }
        if (!(cert = getCertFromObj(interp, objv[2])) ||
            !(key = getKeyFromObj(interp, objv[3])))
            return TCL_ERROR;
        mbedtls_ssl_conf_own_cert(&config->config, &cert->cert, &key->key);
        appendPemToList(&config->pemList, (Pem *)cert);
        appendPemToList(&config->pemList, (Pem *)key);
        return TCL_OK;
    case OPT_SET_CA_CHAIN:
        if (objc != 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "certs");
            return TCL_ERROR;
        }
        if (!(cert = getCertFromObj(interp, objv[2]))) {
            return TCL_ERROR;
        }
        mbedtls_ssl_conf_ca_chain(&config->config, &cert->cert, NULL);
        appendPemToList(&config->pemList, (Pem *)cert);
        return TCL_OK;
    case OPT_SET_VERIFY:
    case OPT_SET_SNI_CALLBACK:
	if (objc != 3) {
	    Tcl_WrongNumArgs(interp, 2, objv, "callback");
	    return TCL_ERROR;
	} else {
	    int len;
	    Tcl_Obj **elts;

	    if (Tcl_ListObjGetElements(interp, objv[2], &len, &elts) != TCL_OK) {
		return TCL_ERROR;
	    }
	    if (len > 0) {
		Tcl_IncrRefCount(objv[2]);
	    }
	    if (index == OPT_SET_VERIFY) {
		if (config->config.p_vrfy != NULL) {
		    Tcl_DecrRefCount((Tcl_Obj *)config->config.p_vrfy);
		}
	    } else if (config->config.p_sni != NULL) {
		Tcl_DecrRefCount((Tcl_Obj *)config->config.p_sni);
	    }
	    if (len > 0) {
		if (index == OPT_SET_VERIFY) {
		    mbedtls_ssl_conf_verify(&config->config, verifyCallback, objv[2]);
		} else {
		    mbedtls_ssl_conf_sni(&config->config, sniCallback, objv[2]);
		}
	    } else {
		if (index == OPT_SET_VERIFY) {
		    mbedtls_ssl_conf_verify(&config->config, NULL, NULL);
		} else {
		    mbedtls_ssl_conf_sni(&config->config, NULL, NULL);
		}
	    }
	}
	return TCL_OK;
    case OPT_NEW_HANDSHAKE:
        return newHandshakeCmd(interp, config, objc, objv);
    }

    /* Not reached */
    return TCL_OK;
}

static void
deleteConfig(ClientData cd)
{
    configRelease((Config *)cd);
}

static int
newConfigCmd(ClientData cd, Tcl_Interp *interp,
             int objc, Tcl_Obj *const objv[])
{
    int i;
    int endpoint = MBEDTLS_SSL_IS_CLIENT,
        transport = MBEDTLS_SSL_TRANSPORT_STREAM,
        preset = MBEDTLS_SSL_PRESET_DEFAULT;
    Config *config;
    char *opt, *mode;

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cmd ?options");
        return TCL_ERROR;
    }

    for (i = 2; i < objc; i++) {
        opt = Tcl_GetStringFromObj(objv[i], NULL);
        if (*opt != '-') {
            break;
        }

        if (strcmp(opt, "-mode") == 0) {
            if (++i == objc)
                goto missing;
            mode = Tcl_GetStringFromObj(objv[i], NULL);
            if (strcmp(mode, "server") == 0) {
                endpoint = MBEDTLS_SSL_IS_SERVER;
            } else if (strcmp(mode, "client") != 0) {
                Tcl_SetObjResult
                    (interp, Tcl_ObjPrintf("bad mode %s, must be server or client", mode));
                return TCL_ERROR;
            }
        }
        continue;
        
missing:
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("missing value for option %s", opt));
        return TCL_ERROR;
    }

    init();
    config = ckalloc(sizeof(Config));
    config->refCount = 1; /* referenced by the command we're about to create */
    mbedtls_ssl_config_init(&config->config);
    mbedtls_ssl_cache_init(&config->cache);
    initPemList(&config->pemList);
    if (mbedtls_ssl_config_defaults(&config->config, endpoint, transport, preset) != 0) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("init failed", -1));
        return TCL_ERROR;
    }
    mbedtls_ssl_conf_rng(&config->config, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_session_cache(&config->config, &config->cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
    return ckCreateCmd(interp, Tcl_GetString(objv[1]), sslConfigHandler,
		       (ClientData)config, deleteConfig)
		       ? TCL_OK : TCL_ERROR;
}

static int
translateError(int ret, int again)
{
    int err;
    
    if (ret < 0) {
        err = Tcl_GetErrno();
        if (err == EAGAIN || err == EINTR) {
            return again;
        } else if (err == EPIPE || err == ECONNRESET) {
            return MBEDTLS_ERR_NET_CONN_RESET;
        } else {
            return MBEDTLS_ERR_NET_SEND_FAILED;
        }
    }
    return ret;
}

static int
bioRecv(void *ctx, unsigned char *buf, size_t len)
{
    Tcl_Channel chan;

    chan = Tcl_GetStackedChannel((Tcl_Channel)ctx);
    return translateError(Tcl_ReadRaw(chan, (char *)buf, len),
			  MBEDTLS_ERR_SSL_WANT_READ);
}

static int
bioSend(void *ctx, const unsigned char *buf, size_t len)
{
    Tcl_Channel chan;

    chan = Tcl_GetStackedChannel((Tcl_Channel)ctx);
    return translateError(Tcl_WriteRaw(chan, (const char *)buf, len),
			  MBEDTLS_ERR_SSL_WANT_WRITE);
}


static int
hsBioRecv(void *ctx, unsigned char *buf, size_t len)
{
    return translateError(Tcl_ReadRaw((Tcl_Channel)ctx, (char *)buf, len),
			  MBEDTLS_ERR_SSL_WANT_READ);
}

static int
hsBioSend(void *ctx, const unsigned char *buf, size_t len)
{
    return translateError(Tcl_WriteRaw((Tcl_Channel)ctx, (const char *)buf, len),
			  MBEDTLS_ERR_SSL_WANT_WRITE);
}

/*static int
SslBlockModeProc(ClientData, int)
{
    
}*/

static int
SslCloseProc(ClientData cd, Tcl_Interp *interp)
{
    State *statePtr = (State *)cd;
    mbedtls_ssl_close_notify(&statePtr->ssl);
    deleteState(statePtr);
    return 0;
}

static int
adjustReturn(int ret, State *statePtr, int *errorCodePtr)
{
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        *errorCodePtr = EAGAIN;
        return -1;
    } else if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
	*errorCodePtr = ECONNRESET;
	return -1;
    } else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
               ret == MBEDTLS_ERR_SSL_CONN_EOF) {
        return 0;
    } else if (ret < 0) {
        Tcl_SetChannelError(statePtr->chan, sslError(ret));
	*errorCodePtr = EIO;
        return -1;
    }
    
    return ret;
}

static int
SslInputProc(ClientData cd, char *buf, int toRead, int *errorCodePtr)
{
    State *statePtr = (State *)cd;
    return adjustReturn(mbedtls_ssl_read(&statePtr->ssl, (unsigned char *)buf, toRead),
                        statePtr, errorCodePtr);
}

static int
SslOutputProc(ClientData cd, const char *buf, int toWrite,
              int *errorCodePtr)
{
    State *statePtr = (State *)cd;
    return adjustReturn(mbedtls_ssl_write(&statePtr->ssl, (unsigned char *)buf, toWrite),
                        statePtr, errorCodePtr);
}

static char *
appendWrapper(Tcl_DString *ds, const char *bytes)
{
    return Tcl_DStringAppend(ds, bytes, -1);
}

static void confSslState(State *state, DSWriter fun, Tcl_DString *ds)
{
    static const char *stateNames[] = {
        "HELLO_REQUEST",
        "CLIENT_HELLO",
        "SERVER_HELLO",
        "SERVER_CERTIFICATE",
        "SERVER_KEY_EXCHANGE",
        "CERTIFICATE_REQUEST",
        "SERVER_HELLO_DONE",
        "CLIENT_CERTIFICATE",
        "CLIENT_KEY_EXCHANGE",
        "CERTIFICATE_VERIFY",
        "CLIENT_CHANGE_CIPHER_SPEC",
        "CLIENT_FINISHED",
        "SERVER_CHANGE_CIPHER_SPEC",
        "SERVER_FINISHED",
        "FLUSH_BUFFERS",
        "HANDSHAKE_WRAPUP",
        "HANDSHAKE_OVER",
        "SERVER_NEW_SESSION_TICKET",
        "SERVER_HELLO_VERIFY_REQUEST_SENT"
    };
    const char *stateName;
    int stateNum = state->ssl.state;
    
    if (stateNum < 0 || stateNum >= ((sizeof stateNames) / sizeof(char *))) {
        stateName = "<unknown>";
    } else {
        stateName = stateNames[stateNum];
    }
    fun(ds, stateName);
}

static int
SslGetOptionProc(ClientData cd, Tcl_Interp *interp,
                 const char *optionName, Tcl_DString *ds)
{
    int i;
    State *state = (State *)cd;
    
    if (optionName) {
        for (i = 0; optHandlers[i].optName; i++) {
            if (!strcmp(optionName, optHandlers[i].optName)) {
                optHandlers[i].fun(state, appendWrapper, ds);
                return TCL_OK;
            }
        }
        return Tcl_BadChannelOption(interp, optionName, "x y z");
    } else {
        for (i = 0; optHandlers[i].optName; i++) {
            Tcl_DStringAppendElement(ds, optHandlers[i].optName);
            optHandlers[i].fun(state, Tcl_DStringAppendElement, ds);
        }
    }
    return TCL_OK;
}

static void
SslWatchProc(ClientData cd, int mask)
{
    State *statePtr;
    Tcl_Channel parent;

    statePtr = (State *)cd;
    parent = Tcl_GetStackedChannel(statePtr->chan);

    Tcl_GetChannelType(parent)
        ->watchProc(Tcl_GetChannelInstanceData(parent), mask);
    
    if (statePtr->timer != NULL) {
        Tcl_DeleteTimerHandler(statePtr->timer);
        statePtr->timer = NULL;
    }
    if ((mask & TCL_READABLE) && mbedtls_ssl_get_bytes_avail(&statePtr->ssl) > 0) {
        statePtr->timer = Tcl_CreateTimerHandler(0, timerHandler, (ClientData)statePtr);
    }
}

static int
SslNotifyProc(ClientData cd, int mask) {
    State *statePtr = (State *)cd;

    if ((mask & TCL_READABLE) && statePtr->timer != NULL) {
        Tcl_DeleteTimerHandler(statePtr->timer);
        statePtr->timer = NULL;
    }
        
    return mask;
}

static int
certCNCmd(ClientData cd, Tcl_Interp *interp,
          int objc, Tcl_Obj *const objv[])
{
    char *cn;
    int len;
    PemCert *pem;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "cert");
        return TCL_ERROR;
    }
    if (!(pem = getCertFromObj(interp, objv[1])))
        return TCL_ERROR;
    cn = certCN(&pem->cert, &len);
    if (cn)
        Tcl_SetObjResult(interp, Tcl_NewStringObj(cn, len));
    return TCL_OK;
}
/*
 * TODO: provide options.
 */
static int
genKeyCmd(ClientData cd, Tcl_Interp *interp,
          int objc, Tcl_Obj *const objv[])
{
    int ret;
    PemKey *pem;
    Tcl_Obj *obj;

    init();
    pem = (PemKey *)allocPem(PEM_KEY, sizeof(PemKey));
    if ((ret = mbedtls_pk_setup(&pem->key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0) {
        return setError(interp, "failed to allocate key", ret);
    }
    if ((ret = mbedtls_rsa_gen_key((mbedtls_rsa_context *)pem->key.pk_ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537)) != 0) {
	pemRelease((Pem *)pem);
        return setError(interp, "failed to generate key", ret);
    }
    obj = Tcl_NewObj();
    Tcl_InvalidateStringRep(obj);
    setPem(obj, (Pem *)pem);
    Tcl_SetObjResult(interp, obj);
    return TCL_OK;
}

/* TODO: maybe don't leak memory on error? Seems like a hassle. */
static int
genCertCmd(ClientData cd, Tcl_Interp *interp,
           int objc, Tcl_Obj *const objv[])
{
    int i, j, index, selfSigned = 0, ret = 0, isCa = 0, maxPathLen = -1,
        keyUsage = 0, nsCertType = 0, numElts;
    Tcl_Obj *issuerObj = NULL, *csrObj = NULL, *subjectKeyObj = NULL,
        *issuerKeyObj = NULL, *serialObj = NULL, *sanRawObj = NULL;
    Tcl_Obj **elts;
    mbedtls_x509write_cert crt;
    mbedtls_pk_context *subjectKey = NULL, *issuerKey = NULL;
    mbedtls_x509_crt *issuerCrt = NULL;
    mbedtls_mpi serial;
    static char issuerName[256], subjectName[256];
    static unsigned char certBuf[16*1024];
    char *notBefore = "20010101000000";
    char *notAfter = "20301231235959";
    static const char *const options[] = {
        "-csr",
        "-subject_key", "-subject_password", "-subject_name",
        "-issuer_cert", "-issuer_name", "-self_signed",
        "-issuer_key", "-issuer_password", "-serial",
        "-not_before", "-not_after", "-is_ca",
        "-max_pathlen", "-key_usage", "-ns_cert_type",
        "-san_raw",
        NULL
    };
    enum option {
        OPT_CSR,
        OPT_SUBJECT_KEY, OPT_SUBJECT_PASSWORD, OPT_SUBJECT_NAME,
        OPT_ISSUER_CERT, OPT_ISSUER_NAME, OPT_SELF_SIGNED,
        OPT_ISSUER_KEY, OPT_ISSUER_PASSWORD, OPT_SERIAL,
        OPT_NOT_BEFORE, OPT_NOT_AFTER, OPT_IS_CA,
        OPT_MAX_PATHLEN, OPT_KEY_USAGE, OPT_NS_CERT_TYPE,
        OPT_SAN_RAW
    };
    
    if ((objc&1) == 0) {
        Tcl_WrongNumArgs(interp, 1, objv, "param value ...");
        return TCL_ERROR;
    }
    memset(issuerName, 0, sizeof issuerName);
    memset(subjectName, 0, sizeof subjectName);
    for (i = 1; i < objc; i += 2) {
        if (Tcl_GetIndexFromObj(interp, objv[i], options, "option", 0,
                                &index) != TCL_OK) {
            return TCL_ERROR;
        }
        switch ((enum option)index) {
        case OPT_CSR:
            csrObj = objv[i+1];
            break;
        case OPT_SUBJECT_KEY:
            subjectKeyObj = objv[i+1];
            break;
        case OPT_SUBJECT_PASSWORD:
            /*subjectPasswordObj = objv[i+1];*/
            break;
        case OPT_ISSUER_CERT:
            issuerObj = objv[i+1];
            break;
        case OPT_ISSUER_NAME: {
            int len;
            char *p = Tcl_GetStringFromObj(objv[i+1], &len);
            if (len >= sizeof issuerName) len = (sizeof issuerName)-1;
            memcpy(issuerName, p, len);
            break;
        }
        case OPT_SELF_SIGNED:
            selfSigned = 1;
            break;
        case OPT_ISSUER_KEY:
            issuerKeyObj = objv[i+1];
            break;
        case OPT_ISSUER_PASSWORD:
            break;
        case OPT_SERIAL:
            serialObj = objv[i+1];
            break;
        case OPT_NOT_BEFORE:
            notBefore = Tcl_GetString(objv[i+1]);
            break;
        case OPT_NOT_AFTER:
            notAfter = Tcl_GetString(objv[i+1]);
            break;
        case OPT_IS_CA:
            if (Tcl_GetIntFromObj(interp, objv[i+1], &isCa) != TCL_OK)
                return TCL_ERROR;
            break;
        case OPT_MAX_PATHLEN:
            if (Tcl_GetIntFromObj(interp, objv[i+1], &maxPathLen) != TCL_OK)
                return TCL_ERROR;
            break;
        case OPT_KEY_USAGE:
            if (Tcl_GetIntFromObj(interp, objv[i+1], &keyUsage) == TCL_OK)
                break;
            if (Tcl_ListObjGetElements(interp, objv[i+1], &numElts, &elts) != TCL_OK)
                return TCL_ERROR;
            for (j = 0; j < numElts; j++) {
                char *opt = Tcl_GetString(elts[j]);
                if (!strcmp(opt, "digital_signature"))
                    keyUsage |= MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
                else if (!strcmp(opt, "non_repudiation"))
                    keyUsage |= MBEDTLS_X509_KU_NON_REPUDIATION;
                else if (!strcmp(opt, "key_encipherment"))
                    keyUsage |= MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
                else if (!strcmp(opt, "data_encipherment"))
                    keyUsage |= MBEDTLS_X509_KU_DATA_ENCIPHERMENT;
                else if (!strcmp(opt, "key_agreement"))
                    keyUsage |= MBEDTLS_X509_KU_KEY_AGREEMENT;
                else if (!strcmp(opt, "key_cert_sign"))
                    keyUsage |= MBEDTLS_X509_KU_KEY_CERT_SIGN;
                else if (!strcmp(opt, "crl_sign"))
                    keyUsage |= MBEDTLS_X509_KU_CRL_SIGN;
                else
                    return errorMsg(interp, "unknown key usage");
            }
            break;
        case OPT_NS_CERT_TYPE:
            if (Tcl_ListObjGetElements(interp, objv[i+1], &numElts, &elts) != TCL_OK)
                return TCL_ERROR;
            for (j = 0; j < numElts; j++) {
                char *opt = Tcl_GetString(elts[j]);
                if (!strcmp(opt, "ssl_client"))
                    nsCertType |= MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT;
                else if (!strcmp(opt, "ssl_server"))
                    nsCertType |= MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER;
                else if (!strcmp(opt, "email"))
                    nsCertType |= MBEDTLS_X509_NS_CERT_TYPE_EMAIL;
                else if (!strcmp(opt, "object_signing"))
                    nsCertType |= MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING;
                else if (!strcmp(opt, "ssl_ca"))
                    nsCertType |= MBEDTLS_X509_NS_CERT_TYPE_SSL_CA;
                else if (!strcmp(opt, "email_ca"))
                    nsCertType |= MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA;
                else if (!strcmp(opt, "object_signing_ca"))
                    nsCertType |= MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA;
                else
                    return errorMsg(interp, "unknown Netscape certificate type");
            }
            break;
        case OPT_SUBJECT_NAME: {
            int len;
            char *p = Tcl_GetStringFromObj(objv[i+1], &len);
            if (len >= sizeof subjectName) len = sizeof subjectName-1;
            memcpy(subjectName, p, len);
            break;
        }
        case OPT_SAN_RAW:
            sanRawObj = objv[i+1];
            break;
        default:
            break;
        }
    }
    init();
    if (selfSigned) {
        PemKey *pem;
        if (!issuerKeyObj)
            return errorMsg(interp, "missing issuer key");
        if (!(pem = getKeyFromObj(interp, issuerKeyObj)))
            return TCL_ERROR;
        memcpy(subjectName, issuerName, sizeof subjectName);
        subjectKey = &pem->key;
    } else {
        if (issuerObj) {
            PemCert *pem = getCertFromObj(interp, issuerObj);
            if (!pem)
                return TCL_ERROR;
            if (mbedtls_x509_dn_gets(issuerName, sizeof(issuerName),
                                     &pem->cert.subject) < 0) {
                return errorMsg(interp, "could not get issuer name from cert");
            }
        }
        if (csrObj) {
            PemCsr *pem = getCsrFromObj(interp, csrObj);
            if (!pem)
                return TCL_ERROR;
            if (mbedtls_x509_dn_gets(subjectName, sizeof(subjectName),
                                     &pem->csr.subject) < 0) {
                return errorMsg(interp, "could not get issuer name from cert");
            }
            subjectKey = &pem->csr.pk;
        } else {
            if (subjectKeyObj) {
                PemKey *pem = getKeyFromObj(interp, subjectKeyObj);
                if (!pem)
                    return TCL_ERROR;
                subjectKey = &pem->key;
            } else {
                return errorMsg(interp, "missing subject key");
            }
        }
            
    }

    if (issuerKeyObj) {
        PemKey *pem = getKeyFromObj(interp, issuerKeyObj);
        if (!pem)
            return TCL_ERROR;
        issuerKey = &pem->key;
    } else {
        return errorMsg(interp, "missing issuer key");
    }

    if (issuerCrt &&
        (!mbedtls_pk_can_do(&issuerCrt->pk, MBEDTLS_PK_RSA) ||
         mbedtls_mpi_cmp_mpi(&mbedtls_pk_rsa(issuerCrt->pk)->N,
                             &mbedtls_pk_rsa(*issuerKey)->N) != 0 ||
         mbedtls_mpi_cmp_mpi(&mbedtls_pk_rsa(issuerCrt->pk)->E,
                             &mbedtls_pk_rsa(*issuerKey)->E) != 0)) {
        return errorMsg(interp, "issuer key does not match issuer certificate");
    }
    
    mbedtls_x509write_crt_init(&crt);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, subjectKey);
    mbedtls_x509write_crt_set_issuer_key(&crt, issuerKey);
    if (mbedtls_x509write_crt_set_subject_name(&crt, subjectName) != 0)
	goto error;
    if (mbedtls_x509write_crt_set_issuer_name(&crt, issuerName) != 0)
	goto error;
    if (!serialObj)
        return errorMsg(interp, "missing serial");
    mbedtls_mpi_init(&serial);
    if (mbedtls_mpi_read_string(&serial, 10, Tcl_GetString(serialObj)) != 0 ||
	mbedtls_x509write_crt_set_serial(&crt, &serial) != 0 ||
	mbedtls_x509write_crt_set_validity(&crt, notBefore, notAfter) != 0 ||
	mbedtls_x509write_crt_set_basic_constraints(&crt, isCa, maxPathLen) != 0)
	goto error;
    if (nsCertType) {
	if (mbedtls_x509write_crt_set_ns_cert_type(&crt, nsCertType) != 0)
	    goto error;
    }
    if (keyUsage) {
        if (mbedtls_x509write_crt_set_key_usage(&crt, keyUsage) != 0)
	    goto error;
    }
    if (mbedtls_x509write_crt_set_subject_key_identifier(&crt) != 0 ||
	mbedtls_x509write_crt_set_authority_key_identifier(&crt) != 0)
	goto error;
    if (sanRawObj) {
        int len;
        unsigned char *data = Tcl_GetByteArrayFromObj(sanRawObj, &len);
        if (mbedtls_x509write_crt_set_extension(&crt, MBEDTLS_OID_SUBJECT_ALT_NAME,
						MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),
						0, data, len) != 0)
	    goto error;
    }
    memset(certBuf, 0, sizeof certBuf);
    ret = mbedtls_x509write_crt_pem(&crt, certBuf, sizeof certBuf, mbedtls_ctr_drbg_random,
                                    &ctr_drbg);
    if (ret != 0 || certBuf[sizeof certBuf - 1] != '\0')
        return setError(interp, "failed to write out certificate", ret);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_mpi_free(&serial);
    Tcl_SetObjResult(interp, Tcl_NewStringObj((char *)certBuf, -1));
    return TCL_OK;
error:
    return setError(interp, "failed to set cert parameters", ret);
}

static State *
getStateFromChanObj(Tcl_Interp *interp, Tcl_Obj *obj)
{
    Tcl_Channel chan;
    
    if (TclGetChannelFromObj(interp, obj, &chan, NULL, 0) != TCL_OK)
        return NULL;
    
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != &sslChannelType) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("channel %s is not an ssl channel",
                                               Tcl_GetChannelName(chan)));
        return NULL;
    }
    return (State *)Tcl_GetChannelInstanceData(chan);
}

static int
peerInfoCmd(ClientData cd, Tcl_Interp *interp,
            int objc, Tcl_Obj *const objv[])
{
    State *state;
    typedef Tcl_Obj *(*Fun)(const mbedtls_x509_crt *);

    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "channel");
        return TCL_ERROR;
    }
    if (!(state = getStateFromChanObj(interp, objv[1])))
        return TCL_ERROR;

    Tcl_SetObjResult(interp, ((Fun)cd)(mbedtls_ssl_get_peer_cert(&state->ssl)));
    return TCL_OK;
}

static int
peerCertCmd(ClientData cd, Tcl_Interp *interp,
            int objc, Tcl_Obj *const objv[])
{
    State *state;
    mbedtls_x509_buf buf;

    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "channel");
        return TCL_ERROR;
    }
    if (!(state = getStateFromChanObj(interp, objv[1])))
        return TCL_ERROR;

    buf = mbedtls_ssl_get_peer_cert(&state->ssl)->raw;
    Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(buf.p, buf.len));
    return TCL_OK;
}

static int
signRsaSha256Cmd(ClientData cd, Tcl_Interp *interp,
		 int objc, Tcl_Obj *const objv[])
{
    unsigned char digest[32], *bytes;
    int len;
    mbedtls_sha256_context ctx;
    PemKey *pem;
    Tcl_Obj *res;

    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "key data");
	return TCL_ERROR;
    }
    if ((pem = getKeyFromObj(interp, objv[1])) == NULL)
	return TCL_ERROR;
    if (!mbedtls_pk_can_do(&pem->key, MBEDTLS_PK_RSA))
	return errorMsg(interp, "not an RSA key");
    bytes = Tcl_GetByteArrayFromObj(objv[2], &len);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, bytes, len);
    mbedtls_sha256_finish_ret(&ctx, digest);
    Tcl_SetObjResult(interp, (res = Tcl_NewByteArrayObj(NULL, mbedtls_pk_rsa(pem->key)->len)));
    mbedtls_rsa_pkcs1_sign(mbedtls_pk_rsa(pem->key), NULL, NULL, MBEDTLS_RSA_PRIVATE,
			   MBEDTLS_MD_SHA256, -1, digest, Tcl_GetByteArrayFromObj(res, NULL));
    return TCL_OK;
}

#define GCM_TAG_LEN 16
static int
gcmCmd(ClientData cd, Tcl_Interp *interp,
       int objc, Tcl_Obj *const objv[])
{
    unsigned char *key, *input, *nonce, *add, *tag, *output;
    int keyLen, inputLen, nonceLen, addLen, ret, crypt, diff, i;
    Tcl_Obj *res;
    
    static mbedtls_gcm_context ctx;
    static Tcl_Obj *lastKey = NULL;
    static unsigned char tagBuf[GCM_TAG_LEN];

    crypt = (int)cd;
    if (objc != 5) {
	Tcl_WrongNumArgs(interp, 1, objv, "key input nonce additional_data");
	return TCL_ERROR;
    }

    if (objv[1] != lastKey) {
	key = Tcl_GetByteArrayFromObj(objv[1], &keyLen);
	if (!(keyLen == 16 || keyLen == 24 || keyLen == 32))
	    return errorMsg(interp, "incorrect key length");
	
	if (lastKey != NULL) {
	    Tcl_DecrRefCount(lastKey);
	    mbedtls_gcm_free(&ctx);
	}
	
	mbedtls_gcm_init(&ctx);
	mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, keyLen*8);
	lastKey = objv[1];
	Tcl_IncrRefCount(lastKey);
    }

    input = Tcl_GetByteArrayFromObj(objv[2], &inputLen);
    nonce = Tcl_GetByteArrayFromObj(objv[3], &nonceLen);
    add = Tcl_GetByteArrayFromObj(objv[4], &addLen);

    if (!crypt && inputLen < GCM_TAG_LEN)
	return errorMsg(interp, "ciphertext too short");
    
    res = Tcl_NewByteArrayObj(NULL, crypt ? inputLen + GCM_TAG_LEN : inputLen - GCM_TAG_LEN);
    output = Tcl_GetByteArrayFromObj(res, NULL);

    ret = mbedtls_gcm_crypt_and_tag(&ctx, crypt ? MBEDTLS_GCM_ENCRYPT : MBEDTLS_GCM_DECRYPT,
				    crypt ? inputLen : inputLen - GCM_TAG_LEN,
				    nonce, nonceLen, add, addLen, input, output,
				    GCM_TAG_LEN, crypt ? output + inputLen : tagBuf);
    if (ret != 0) {
	Tcl_DecrRefCount(res);
	return setError(interp, NULL, ret);
    }

    if (!crypt) {
	tag = input + inputLen - GCM_TAG_LEN;

	/* Grabbed from mbedtls_gcm_auth_decrypt */
	for (diff = 0, i = 0; i < GCM_TAG_LEN; i++)
	    diff |= tag[i] ^ tagBuf[i];

	if (diff != 0) {
	    mbedtls_platform_zeroize(output, inputLen);
	    Tcl_DecrRefCount(res);
	    return errorMsg(interp, "message authentication failed");
	}
    }

    Tcl_SetObjResult(interp, res);
    return TCL_OK;
}

void
sslInit(Tcl_Interp *interp)
{
    Tcl_CreateObjCommand(interp, "ssl::new_config", newConfigCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "ssl::gen_key", genKeyCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "ssl::gen_cert", genCertCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "ssl::cert_cn", certCNCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "ssl::peer_info", peerInfoCmd, (ClientData)certInfo,
			 NULL);
    Tcl_CreateObjCommand(interp, "ssl::peer_subj", peerInfoCmd, (ClientData)certSubj,
			 NULL);
    Tcl_CreateObjCommand(interp, "ssl::peer_cert", peerCertCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "ssl::sign_rsa_sha256", signRsaSha256Cmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "ssl::aes_gcm_encrypt", gcmCmd, (ClientData)1, NULL);
    Tcl_CreateObjCommand(interp, "ssl::aes_gcm_decrypt", gcmCmd, (ClientData)0, NULL);
}
