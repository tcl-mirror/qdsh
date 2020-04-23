#include <tcl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pwd.h> /* for peername */
#include <string.h> /* strcmp */

#include "qdsh.h"
#include "libancillary/ancillary.h"

//#include <sys/ioctl.h>

static int closeProc(ClientData cd, Tcl_Interp *interp);
static int close2Proc(ClientData cd, Tcl_Interp *interp, int flags);
static int inputProc(ClientData cd, char *buf, int bufSize, int *errorCodePtr);
static int outputProc(ClientData cd, const char *buf, int toWrite, int *errorCodePtr);
static int blockModeProc(ClientData cd, int mode);
static int getOptionProc(ClientData cd, Tcl_Interp *interp,
			 const char *optionName, Tcl_DString *dsPtr);
static void wrapNotify(ClientData cd, int mask);
static void watchProc(ClientData cd, int mask);
static int getHandleProc(ClientData cd, int direction, ClientData *handlePtr);
static void acceptHandler(ClientData cd, int mask);
static int listenObjCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);
static int connectObjCmd(ClientData cd, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]);

static Tcl_ChannelType unixSocketChannelType = {
    "unix",
    TCL_CHANNEL_VERSION_5,
    closeProc,
    inputProc,
    outputProc,
    NULL,
    NULL,
    getOptionProc,
    watchProc,
    getHandleProc,
    close2Proc,
    blockModeProc,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

typedef struct UnixSocketState {
    Tcl_Interp *interp;
    Tcl_Channel	channel;
    char name[64];
    int	fd;
    int interest;
    Tcl_Obj *acceptHandler;
    Tcl_Obj *path;
} UnixSocketState;

static int
closeProc(ClientData cd, Tcl_Interp *interp)
{
    int error;
    UnixSocketState *con = (UnixSocketState *)cd;

    Tcl_DeleteFileHandler(con->fd);

    if (con->acceptHandler != NULL) {
	Tcl_DecrRefCount(con->acceptHandler);
    }
    if (con->path != NULL) {
	Tcl_DecrRefCount(con->path);
    }

    error = close(con->fd);
    ckfree((char *)con);
    return error;
}

static int
inputProc(ClientData cd,
	  char *buf,
	  int bufSize,
	  int *errorCodePtr)
{
    UnixSocketState *con = (UnixSocketState *)cd;
    int got;
    
    got = read(con->fd, buf, bufSize);

    if (got == -1)
	*errorCodePtr = errno;

    return got;
}

static int
outputProc(ClientData cd,
	   const char *buf,
	   int toWrite,
	   int *errorCodePtr)
{
    int wrote;
    UnixSocketState *con = (UnixSocketState *)cd;

    wrote = send(con->fd, buf, (size_t)toWrite, 0);
    if (wrote == -1)
	*errorCodePtr = errno;

    return wrote;
}

static int
close2Proc(ClientData cd, Tcl_Interp *interp, int flags)
{
    UnixSocketState *con = (UnixSocketState *)cd;
    int errorCode = 0;
    int sd;

    switch(flags) {
    case TCL_CLOSE_READ:
        sd = SHUT_RD;
        break;
    case TCL_CLOSE_WRITE:
        sd = SHUT_WR;
        break;
    default:
        if (interp) {
            Tcl_SetObjResult(interp, Tcl_NewStringObj(
                    "unix socket close2proc called bidirectionally", -1));
        }
        return TCL_ERROR;
    }
    if (shutdown(con->fd, sd) < 0) {
	errorCode = errno;
    }

    return errorCode;
}

static int
blockModeProc(ClientData cd, int mode)
{
    UnixSocketState *con = (UnixSocketState *)cd;
    int flags, err;

    flags = 0;
    err = fcntl(con->fd, F_GETFL, &flags);
    if (err == -1) {
	return errno;
    }

#ifdef O_DELAY
    flags &= ~O_NDELAY;
#endif
    
    if (mode == TCL_MODE_BLOCKING) {
	flags &= ~O_NONBLOCK;
    } else {
	flags |= O_NONBLOCK;
    }

    err = fcntl(con->fd, F_SETFL, flags);
    if (err == -1) {
	return Tcl_GetErrno();
    }
    
    /*
      ioctl(con->fd, FIONBIO, 1);
    */
    
    return 0;
}

static int
getOptionProc(ClientData cd, Tcl_Interp *interp,
	      const char *optionName, Tcl_DString *dsPtr)
{
#ifdef __linux__
    UnixSocketState *con = (UnixSocketState *)cd;
    struct ucred cr;
    struct passwd *pw;
    socklen_t len;
    char uid[10];
#endif
    
    if (optionName != NULL && strcmp(optionName, "-peername") == 0) {
#ifdef __linux__
	len = sizeof(cr);
	if (getsockopt(con->fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) < 0) {
	    Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_PosixError(interp), -1));
	    return TCL_ERROR;
	}
	errno = 0;
	pw = getpwuid(cr.uid);
	if (pw == NULL) {
	    if (errno == 0) {
		snprintf(uid, sizeof(uid), "%d", cr.uid);
		Tcl_DStringAppendElement(dsPtr, uid);
		return TCL_OK;
	    } else {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_PosixError(interp), -1));
		return TCL_ERROR;
	    }
	}
	Tcl_DStringAppendElement(dsPtr, pw->pw_name);
	return TCL_OK;
#else
	return errorMsg(interp, "peername not supported on this platform");
#endif
    }

    if (optionName != NULL && optionName[0] != '\0') {
	return Tcl_BadChannelOption(interp, optionName, "peername");
    }

    return TCL_OK;
}

static void
wrapNotify(ClientData cd, int mask)
{
    UnixSocketState *con = (UnixSocketState *)cd;
    int newmask = mask & con->interest;

    if (newmask == 0) {
	if (errno == 0) {
	    return;
	}
	newmask = TCL_WRITABLE;
    }
    Tcl_NotifyChannel(con->channel, newmask);
}

static void
watchProc(ClientData cd, int mask)
{
    UnixSocketState *con = (UnixSocketState *)cd;

    if (con->acceptHandler != NULL) {
	/* Don't let Tcl script watch server sockets */
	return;
    }
    
    if (mask) {
	con->interest = mask;
	Tcl_CreateFileHandler(con->fd, mask|TCL_READABLE,
			      (Tcl_FileProc *)wrapNotify,
			      (ClientData)con);
    } else {
	Tcl_DeleteFileHandler(con->fd);
    }
}

static int
getHandleProc(ClientData cd,
	      int direction,
	      ClientData *handlePtr)
{
    UnixSocketState *con = (UnixSocketState *)cd;

    *handlePtr = (ClientData)(intptr_t)con->fd;
    return TCL_OK;
}

static void
acceptHandler(ClientData cd, int mask)
{
    UnixSocketState *state = (UnixSocketState *)cd;
    struct sockaddr_un client_addr;
    int client_sockfd;
    int res;
    socklen_t client_len;
    char channel_name[64];
    Tcl_Obj *handler;
    Tcl_Channel channel;
    UnixSocketState *con;

    client_len = sizeof(client_addr);
    client_sockfd = accept(state->fd,
			   (struct sockaddr *)&client_addr, &client_len);
    if (client_sockfd < 0) {
	return;
    }
    fcntl(client_sockfd, F_SETFD, FD_CLOEXEC);
    
    con = (UnixSocketState *)ckalloc(sizeof(UnixSocketState));
    sprintf(channel_name, "unix_socket%d", client_sockfd);
    channel = Tcl_CreateChannel(&unixSocketChannelType, channel_name,
				(ClientData)con, (TCL_READABLE | TCL_WRITABLE));
    
    con->interp = NULL;
    memcpy(con->name, channel_name, 64);
    con->channel = channel;
    con->fd = client_sockfd;
    con->acceptHandler = NULL;
    con->path = NULL;

    Tcl_RegisterChannel(state->interp, channel);
    handler = Tcl_DuplicateObj(state->acceptHandler);
    if (Tcl_ListObjAppendElement(state->interp, handler, Tcl_NewStringObj(channel_name, -1)) != TCL_OK) {
	Tcl_BackgroundError(state->interp);
	close(con->fd);
	ckfree((char *)con);
	return;
    }

    Tcl_IncrRefCount(handler);
    res = Tcl_EvalObjEx(state->interp, handler, TCL_EVAL_GLOBAL);
    Tcl_DecrRefCount(handler);
    
    if (res != TCL_OK)
	Tcl_BackgroundError(state->interp);
}

static int
listenObjCmd(ClientData cd,
	     Tcl_Interp *interp,
	     int objc,
	     Tcl_Obj *const objv[])
{
    int server_sockfd;
    int server_len;
    struct sockaddr_un server_addr;
    char *path;
    int path_len;
    UnixSocketState *state;
    char channel_name[64];
    Tcl_Channel channel;

    if (objc != 3) {
	Tcl_WrongNumArgs(interp, 1, objv, "path handler");
	return TCL_ERROR;
    }
	
    path = Tcl_GetStringFromObj(objv[1], &path_len);
    if (path_len > 107) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("path cannot exceed 107 characters", -1));
	return TCL_ERROR;
    }

    server_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sockfd < 0) {
	goto error;
    }
    fcntl(server_sockfd, F_SETFD, FD_CLOEXEC);
    
    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, path);
    server_len = sizeof(server_addr);		// should this be SUN_LEN()?
    if (bind(server_sockfd, (struct sockaddr *)&server_addr, server_len) < 0) {
	goto error;
    }
    if (listen(server_sockfd, 100) < 0) {
	goto error;
    }

    state = (UnixSocketState *)ckalloc(sizeof(UnixSocketState));
    sprintf(channel_name, "unix_socket%d", server_sockfd);
    channel = Tcl_CreateChannel(&unixSocketChannelType, channel_name,
				(ClientData)state, 0);
    
    state->interp = interp;
    state->fd = server_sockfd;
    state->channel = channel;
    memcpy(state->name, channel_name, 64);
    state->acceptHandler = objv[2];
    state->path = objv[1];
    Tcl_IncrRefCount(state->acceptHandler);
    Tcl_IncrRefCount(state->path);

    Tcl_RegisterChannel(interp, channel);
    Tcl_CreateFileHandler(state->fd, TCL_READABLE, acceptHandler,
			  (ClientData)state);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(channel_name, -1));
    return TCL_OK;

 error:
    Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_PosixError(interp), -1));
    return TCL_ERROR;
}

static int
connectObjCmd(ClientData cd,
	      Tcl_Interp *interp,
	      int objc,
	      Tcl_Obj *const objv[])
{
    Tcl_Channel channel;
    int fd;
    char channel_name[64];
    char *path;
    int path_len;
    int res;
    struct sockaddr_un addr;
    int sockaddr_len;
    UnixSocketState *con;

    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "path");
	return TCL_ERROR;
    }

    path = Tcl_GetStringFromObj(objv[1], &path_len);
    if (path_len > 107) {
	Tcl_SetObjResult(interp, Tcl_NewStringObj("path cannot exceed 107 characters", -1));
	return TCL_ERROR;
    }
    
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
	goto error;
    }

    fcntl(fd, F_SETFD, FD_CLOEXEC);

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    sockaddr_len = sizeof(addr);
    res = connect(fd, (struct sockaddr *)&addr, sockaddr_len);
    if (res < 0) {
	goto error;
    }

    con = (UnixSocketState *)ckalloc(sizeof(UnixSocketState));
    sprintf(channel_name, "unix_socket%d", fd);
    channel = Tcl_CreateChannel(&unixSocketChannelType, channel_name,
				(ClientData)con, (TCL_READABLE | TCL_WRITABLE));
    con->interp = NULL;
    con->channel = channel;
    memcpy(con->name, channel_name, 64);
    con->fd = fd;
    con->acceptHandler = NULL;
    con->path = objv[1];
    Tcl_IncrRefCount(con->path);
    Tcl_RegisterChannel(interp, channel);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(channel_name, -1));
    return TCL_OK;

 error:
    Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_PosixError(interp), -1));
    return TCL_ERROR;
}

static int
getFdFromSock(Tcl_Interp *interp, Tcl_Obj *obj)
{
    Tcl_Channel chan;
    UnixSocketState *state;
    
    if (TclGetChannelFromObj(interp, obj, &chan, NULL, 0) != TCL_OK)
        return -1;
    
    chan = Tcl_GetTopChannel(chan);
    if (Tcl_GetChannelType(chan) != &unixSocketChannelType ||
	((state = (UnixSocketState *)Tcl_GetChannelInstanceData(chan))->acceptHandler)) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("channel %s is not a unix domain socket",
                                               Tcl_GetChannelName(chan)));
        return -1;
    }
    return state->fd;
}

static int
getFdFromObj(Tcl_Interp *interp, Tcl_Obj *obj, int *ret)
{
    Tcl_Channel chan;
    
    if (TclGetChannelFromObj(interp, obj, &chan, NULL, 0) != TCL_OK ||
        Tcl_GetChannelHandle(chan, Tcl_GetChannelMode(chan), (ClientData *)ret) != TCL_OK) {
        return TCL_ERROR;
    }
    return TCL_OK;
}

/* untested */
static int
sendFdObjCmd(ClientData cd, Tcl_Interp *interp, int objc,
             Tcl_Obj *const objv[]) {
    int sock, fd;
    
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "unix_domain_socket fd");
        return TCL_ERROR;
    }
    if ((sock = getFdFromSock(interp, objv[1])) < 0 ||
        getFdFromObj(interp, objv[2], &fd) != TCL_OK) {
        return TCL_ERROR;
    }
    if (ancil_send_fd(sock, fd) == -1) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("send_fd: %s", Tcl_PosixError(interp)));
        return TCL_ERROR;
    }
    return TCL_OK;
}

/* untested */
static int
recvFdObjCmd(ClientData cd, Tcl_Interp *interp, int objc,
             Tcl_Obj *const objv[]) {
    int sock, fd, modeObjc, mode, i;
    Tcl_Channel chan;
    Tcl_Obj **modeObjv;
    char *modeStr;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "unix_domain_socket mode");
        return TCL_ERROR;
    }
    if ((sock = getFdFromSock(interp, objv[1])) < 0 ||
        Tcl_ListObjGetElements(interp, objv[2], &modeObjc, &modeObjv) != TCL_OK) {
        return TCL_ERROR;
    }
    mode = 0;
    for (i = 0; i < modeObjc; i++) {
        modeStr = Tcl_GetString(modeObjv[i]);
        if (strcmp(modeStr, "readable") == 0) {
            mode |= TCL_READABLE;
        } else if (strcmp(modeStr, "writable") == 0) {
            mode |= TCL_WRITABLE;
        } else {
            Tcl_SetObjResult(interp, Tcl_ObjPrintf("no such mode %s", modeStr));
            return TCL_ERROR;
        }
    }
    if (ancil_recv_fd(sock, &fd) == -1) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("recv_fd: %s", Tcl_PosixError(interp)));
        return TCL_ERROR;
    }
    chan = Tcl_MakeFileChannel((ClientData)(intptr_t)fd, mode);
    Tcl_RegisterChannel(interp, chan);
    Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_GetChannelName(chan), -1));
    return TCL_OK;
}

void
unixSocketInit(Tcl_Interp *interp)
{
    Tcl_CreateObjCommand(interp, "unix_socket::listen", listenObjCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "unix_socket::connect", connectObjCmd, NULL, NULL);

    /* untested */
    Tcl_CreateObjCommand(interp, "unix_socket::send_fd", sendFdObjCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "unix_socket::recv_fd", recvFdObjCmd, NULL, NULL);
}
