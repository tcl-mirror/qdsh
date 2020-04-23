#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h> /* getsockopt */
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <grp.h>

#include <tcl.h>

#include "qdsh.h"

const Tcl_ObjType posixConst = {
    "posixConst", NULL, NULL, NULL, NULL
};

static int
getIntOrConst(Tcl_Interp *interp, Tcl_Obj *obj, int *ret)
{
    int val, i;
    char *str;
    static struct {
	char *name;
	int val;
    } names[] = {
#define DEF(name) { #name, name }
	DEF(IPPROTO_IP),
	DEF(IPPROTO_TCP),
	DEF(TCP_NODELAY),
#ifdef __linux__
	DEF(TCP_CORK),
#elif defined(__FreeBSD__)
        DEF(TCP_NOPOUSH),
#endif
#undef DEF
	{ NULL, -1 }
    };
    
    if (obj->typePtr == &posixConst) {
	*ret = (int)obj->internalRep.longValue;
	return TCL_OK;
    }

    if (Tcl_GetIntFromObj(NULL, obj, &val) != TCL_OK) {
	str = Tcl_GetString(obj);
	for (i = 0; names[i].name != NULL; i++) {
	    if (strcmp(str, names[i].name) == 0) {
		val = names[i].val;
		goto found;
	    }
	}
	if (interp != NULL)
	    Tcl_SetObjResult(interp, Tcl_ObjPrintf("Not a POSIX constant: %s", str));
	return TCL_ERROR;
    }
    
found:
    freeIntRep(obj);
    obj->typePtr = &posixConst;
    obj->internalRep.longValue = (long)val;
    *ret = val;
    return TCL_OK;
}

static int
constCmd(ClientData cd, Tcl_Interp *interp, int objc,
              Tcl_Obj *const objv[])
{
    int val;
    
    if (objc != 2) {
	Tcl_WrongNumArgs(interp, 1, objv, "constant");
	return TCL_ERROR;
    }
    if (getIntOrConst(NULL, objv[1], &val) == TCL_OK)
	Tcl_SetObjResult(interp, Tcl_NewIntObj(val));
    return TCL_OK;
}

static int
stdErr(Tcl_Interp *interp, char *prefix)
{
    Tcl_SetObjResult(interp, Tcl_ObjPrintf("%s: %s", prefix, Tcl_PosixError(interp)));
    return TCL_ERROR;
}

static Tcl_Obj *
makePasswd(struct passwd *pw)
{
    static char *fields[] = {
        "name", "password", "uid", "gid", "gecos", "homedir", "shell"
    };
#define NUM_PW_FIELDS ((sizeof fields)/sizeof(char *))
    static Tcl_Obj *ls[NUM_PW_FIELDS*2] = {0};
    int i;
    
    if (ls[0] == NULL) {
        for (i = 0; i < NUM_PW_FIELDS; i++) {
            ls[i*2] = Tcl_NewStringObj(fields[i], -1);
            Tcl_IncrRefCount(ls[i*2]);
        }
    }
    ls[1] = Tcl_NewStringObj(pw->pw_name, -1);
    ls[3] = Tcl_NewStringObj(pw->pw_passwd, -1);
    ls[5] = Tcl_NewLongObj(pw->pw_uid);
    ls[7] = Tcl_NewLongObj(pw->pw_gid);
    ls[9] = Tcl_NewStringObj(pw->pw_gecos, -1);
    ls[11] = Tcl_NewStringObj(pw->pw_dir, -1);
    ls[13] = Tcl_NewStringObj(pw->pw_shell, -1);
    
    return Tcl_NewListObj(NUM_PW_FIELDS*2, ls);
#undef NUM_PW_FIELDS
}
 
static Tcl_Obj *
makeGroup(struct group *gr)
{
    static char *fields[] = {
        "name", "password", "gid", "members"
    };
#define NUM_GR_FIELDS ((sizeof fields)/sizeof(char *))
    static Tcl_Obj *ls[NUM_GR_FIELDS*2] = {0};
    int i;
    
    if (ls[0] == NULL) {
        for (i = 0; i < NUM_GR_FIELDS; i++) {
            ls[i*2] = Tcl_NewStringObj(fields[i], -1);
            Tcl_IncrRefCount(ls[i*2]);
        }
    }

    
    ls[1] = Tcl_NewStringObj(gr->gr_name, -1);
    ls[3] = Tcl_NewStringObj(gr->gr_passwd, -1);
    ls[5] = Tcl_NewLongObj(gr->gr_gid);
    
    for (i = 0; gr->gr_mem[i] != NULL; i++) {
        /* do nothing */
    }
    ls[7] = Tcl_NewListObj(i, NULL);
    for (i = 0; gr->gr_mem[i] != NULL; i++) {
        Tcl_ListObjAppendElement(NULL, ls[7], Tcl_NewStringObj(gr->gr_mem[i], -1));
    }
    
    return Tcl_NewListObj(NUM_GR_FIELDS*2, ls);
#undef NUM_GR_FIELDS
}

static int
getpwnamCmd(ClientData cd, Tcl_Interp *interp, int objc,
            Tcl_Obj *const objv[])
{
    char *username;
    struct passwd *pw;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "username");
        return TCL_ERROR;
    }

    username = Tcl_GetString(objv[1]);
    pw = getpwnam(username);
    if (pw == NULL) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("couldn't look up user %s: %s",
                                               username, Tcl_PosixError(interp)));
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, makePasswd(pw));
    return TCL_OK;
}

static int
getpwuidCmd(ClientData cd, Tcl_Interp *interp, int objc,
            Tcl_Obj *const objv[])
{
    struct passwd *pw;
    long uid;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "uid");
        return TCL_ERROR;
    }

    if (Tcl_GetLongFromObj(interp, objv[1], &uid) != TCL_OK) {
        return TCL_ERROR;
    }

    pw = getpwuid((uid_t)uid);
    if (pw == NULL) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("couldn't look up uid %ld: %s",
                                               uid, Tcl_PosixError(interp)));
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, makePasswd(pw));
    return TCL_OK;
}

static int
getgrnamCmd(ClientData cd, Tcl_Interp *interp, int objc,
            Tcl_Obj *const objv[])
{
    char *group;
    struct group *gr;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "group");
        return TCL_ERROR;
    }

    group = Tcl_GetString(objv[1]);
    gr = getgrnam(group);
    if (gr == NULL) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("couldn't look up group %s: %s",
                                               group, Tcl_PosixError(interp)));
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, makeGroup(gr));
    return TCL_OK;
}

static int
getgrgidCmd(ClientData cd, Tcl_Interp *interp, int objc,
            Tcl_Obj *const objv[])
{
    struct group *gr;
    long gid;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "group");
        return TCL_ERROR;
    }

    if (Tcl_GetLongFromObj(interp, objv[1], &gid) != TCL_OK) {
        return TCL_ERROR;
    }

    gr = getgrgid((gid_t)gid);
    if (gr == NULL) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("couldn't look up group %ld: %s",
                                               gid, Tcl_PosixError(interp)));
        return TCL_ERROR;
    }
    
    Tcl_SetObjResult(interp, makeGroup(gr));
    return TCL_OK;
}

static int
setuidCmd(ClientData cd, Tcl_Interp *interp, int objc,
          Tcl_Obj *const objv[])
{
    int ret;
    long uid;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "uid");
        return TCL_ERROR;
    }

    if (Tcl_GetLongFromObj(interp, objv[1], &uid) != TCL_OK) {
        return TCL_ERROR;
    }
    
    ret = setuid((uid_t)uid);
    if (ret == -1) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("failed to setuid to %ld: %s",
                                               uid, Tcl_PosixError(interp)));
        return TCL_ERROR;
    }
    return TCL_OK;
}

/* Note: also does setgroups */
static int
setgidCmd(ClientData cd, Tcl_Interp *interp, int objc,
          Tcl_Obj *const objv[])
{
    long gid;
    gid_t ggid;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "gid");
        return TCL_ERROR;
    }

    if (Tcl_GetLongFromObj(interp, objv[1], &gid) != TCL_OK) {
        return TCL_ERROR;
    }

    ggid = (gid_t)gid;
    if (setgroups(1, &ggid) == -1 || setgid(ggid) == -1) {
        Tcl_SetObjResult(interp, Tcl_ObjPrintf("failed to set group to %ld: %s",
                                               gid, Tcl_PosixError(interp)));
        return TCL_ERROR;
    }
    return TCL_OK;
}

static int
getuidCmd(ClientData cd, Tcl_Interp *interp, int objc,
          Tcl_Obj *const objv[])
{
    if (objc != 1) {
        Tcl_WrongNumArgs(interp, 1, objv, NULL);
        return TCL_ERROR;
    }
    Tcl_SetObjResult(interp, Tcl_NewLongObj(getuid()));
    return TCL_OK;
}

static int
getsockoptCmd(ClientData cd, Tcl_Interp *interp, int objc,
              Tcl_Obj *const objv[])
{
    Tcl_Channel chan;
    int fd, ret, lvl, optname, optlen;
    socklen_t len, orig_len;
    Tcl_Obj *buf;
    
    if (objc != 5) {
        Tcl_WrongNumArgs(interp, 1, objv, "channel level optname optlen");
        return TCL_ERROR;
    }
    
    if (TclGetChannelFromObj(interp, objv[1], &chan, NULL, 0) != TCL_OK ||
        Tcl_GetChannelHandle(chan, Tcl_GetChannelMode(chan), (ClientData *)&fd) != TCL_OK ||
        getIntOrConst(interp, objv[2], &lvl) != TCL_OK ||
        getIntOrConst(interp, objv[3], &optname) != TCL_OK ||
        Tcl_GetIntFromObj(interp, objv[4], &optlen) != TCL_OK) {
        return TCL_ERROR;
    }

    orig_len = len = optlen;
    buf = Tcl_NewByteArrayObj(NULL, len);
    ret = getsockopt(fd, lvl, optname, Tcl_GetByteArrayFromObj(buf, NULL), &len);
    if (ret == -1) {
        Tcl_DecrRefCount(buf);
        return stdErr(interp, "getsockopt");
    }
    if (len != orig_len) {
        (void)Tcl_SetByteArrayLength(buf, len);
    }
    Tcl_SetObjResult(interp, buf);
    return TCL_OK;
}

static int
setIntSockOptCmd(ClientData cd, Tcl_Interp *interp, int objc,
		 Tcl_Obj *const objv[])
{
    Tcl_Channel chan;
    int fd, level, optname, value;
    
    if (objc != 5) {
	Tcl_WrongNumArgs(interp, 1, objv, "channel level optname value");
	return TCL_ERROR;
    }

    if (TclGetChannelFromObj(interp, objv[1], &chan, NULL, 0) != TCL_OK ||
	Tcl_GetChannelHandle(chan, Tcl_GetChannelMode(chan), (ClientData *)&fd) != TCL_OK ||
	getIntOrConst(interp, objv[2], &level) != TCL_OK ||
	getIntOrConst(interp, objv[3], &optname) != TCL_OK ||
	Tcl_GetIntFromObj(interp, objv[4], &value) != TCL_OK) {
	return TCL_ERROR;
    }
    
    if (setsockopt(fd, level, optname, &value, sizeof(int)) == -1) {
	return stdErr(interp, "setsockopt");
    }
    return TCL_OK;
}
  
static int
forkCmd(ClientData cd, Tcl_Interp *interp, int objc,
        Tcl_Obj *const objv[])
{
    pid_t pid = fork();
    if (pid == -1) {
        return stdErr(interp, "fork");
    }
    Tcl_SetObjResult(interp, Tcl_NewLongObj((long)pid));
    return TCL_OK;
}

static int
chrootCmd(ClientData cd, Tcl_Interp *interp, int objc,
          Tcl_Obj *const objv[])
{
    int ret;

    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "path");
        return TCL_ERROR;
    }
    ret = chroot(Tcl_GetString(objv[1]));
    if (ret == -1) {
        return stdErr(interp, "chroot");
    }
    return TCL_OK;
}

static int
execvpCmd(ClientData cd, Tcl_Interp *interp, int objc,
          Tcl_Obj *const objv[])
{
    int argLen, i;
    char *path, **argv;
    Tcl_Obj **argList;
    
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "path argv");
        return TCL_ERROR;
    }
    path = Tcl_GetString(objv[1]);
    if (Tcl_ListObjGetElements(interp, objv[2], &argLen, &argList) != TCL_OK) {
        return TCL_ERROR;
    }
    argv = ckalloc(sizeof(char *) * (argLen+1));
    for (i = 0; i < argLen; i++) {
        argv[i] = Tcl_GetString(argList[i]);
    }
    argv[i] = NULL;
    execvp(path, argv);
    return stdErr(interp, "execv");
}

static int
fsyncCmd(ClientData cd, Tcl_Interp *interp, int objc,
          Tcl_Obj *const objv[])
{
    Tcl_Channel chan;
    int fd;
    
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "chan");
        return TCL_ERROR;
    }
    
    if (TclGetChannelFromObj(interp, objv[1], &chan, NULL, 0) != TCL_OK ||
        Tcl_GetChannelHandle(chan, Tcl_GetChannelMode(chan), (ClientData *)&fd) != TCL_OK) {
        return TCL_ERROR;
    }
    if (fsync(fd) == -1) {
        return stdErr(interp, "fsync");
    }
    return TCL_OK;
}
  
void
posixInit(Tcl_Interp *interp)
{
    Tcl_CreateObjCommand(interp, "posix::getpwnam", getpwnamCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::getpwuid", getpwuidCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::getgrnam", getgrnamCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::getgrgid", getgrgidCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::setuid", setuidCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::setgid", setgidCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::getuid", getuidCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::getsockopt", getsockoptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::setsockopt/int", setIntSockOptCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::fork", forkCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::chroot", chrootCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::execvp", execvpCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::fsync", fsyncCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "posix::const", constCmd, NULL, NULL);
}
