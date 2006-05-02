/* 
 * The contents of this file are subject to the Mozilla Public License
 * Version 1.1(the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis,WITHOUT WARRANTY OF ANY KIND,either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Alternatively,the contents of this file may be used under the terms
 * of the GNU General Public License(the "GPL"),in which case the
 * provisions of GPL are applicable instead of those above.  If you wish
 * to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the
 * License,indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by the GPL.
 * If you do not delete the provisions above,a recipient may use your
 * version of this file under either the License or the GPL.
 *
 * Author Vlad Seryakov vlad@crystalballinc.com
 * 
 */

/*
 * nssyslogd.c -- Syslog module
 *
 *
 * Authors
 *
 *     Vlad Seryakov vlad@crystalballinc.com
 */

#include "ns.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef struct _syslogFile {
    struct _syslogFile *nextPtr;
    char *name;
    char *file;
    char *rollfmt;
    int fd;
    int maxbackup;
    int maxlines;
    int curlines;
    unsigned long writtenlines;
    Ns_Mutex lock;
    Ns_DString buffer;
} SyslogFile;

typedef struct _server {
    char *name;
    char *proc;
    char *path;
    char *address;
    int port;
    int rollhour;
    int udp_sock;
    int unix_sock;
    short errors;
    Ns_Mutex mutex;
    Ns_DString buffer;
    SyslogFile *files;
    int opened;
    int facility;
    int options;
    char ident[32];
} Server;

static struct {
    int type;
    char *name;
} SyslogFacilities[] = {
    {
    0, "kern"}, {
    1, "user"}, {
    2, "mail"}, {
    3, "daemon"}, {
    4, "auth"}, {
    5, "intern"}, {
    6, "print"}, {
    7, "news"}, {
    8, "uucp"}, {
    9, "clock"}, {
    10, "security"}, {
    11, "ftp"}, {
    12, "ntp"}, {
    13, "audit"}, {
    14, "alert"}, {
    15, "clock"}, {
    16, "local0"}, {
    17, "local1"}, {
    18, "local2"}, {
    19, "local3"}, {
    20, "local4"}, {
    21, "local5"}, {
    22, "local6"}, {
    23, "local7"}, {
    0, 0}
};

static struct {
    int type;
    char *name;
} SyslogSeverities[] = {
    {
    0, "emergency"}, {
    1, "alert"}, {
    2, "critical"}, {
    3, "error"}, {
    4, "warning"}, {
    5, "notice"}, {
    6, "info"}, {
    7, "debug"}, {
    0, 0}
};

static Ns_SockProc SyslogProc;
static int SyslogInterpInit(Tcl_Interp * interp, void *arg);
static int SyslogCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static SyslogFile *SyslogFind(Server * srvPtr, const char *name);
static int SyslogOpen(SyslogFile * logPtr);
static int SyslogClose(SyslogFile * logPtr);
static int SyslogFlush(SyslogFile * logPtr, Ns_DString * dsPtr);
static int SyslogRoll(SyslogFile * logPtr);
static void SyslogWrite(SyslogFile * logPtr, char *str);
static void SyslogFree(SyslogFile * logPtr);
static void SyslogCallback(int (proc) (SyslogFile *), void *arg, char *desc);
static void SyslogCloseCallback(Ns_Time * toPtr, void *arg);
static void SyslogRollCallback(void *arg);

NS_EXPORT int Ns_ModuleVersion = 1;

/*
 *----------------------------------------------------------------------
 *
 * Ns_ModuleInit --
 *
 *	Load the config parameters, setup the structures, and
 *	listen on the trap port.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	Server will listen for SNMP traps on specified address and port.
 *
 *----------------------------------------------------------------------
 */

NS_EXPORT int Ns_ModuleInit(char *server, char *module)
{
    char *path;
    SOCKET sock;
    Server *srvPtr;

    path = Ns_ConfigGetPath(server, module, NULL);
    srvPtr = (Server *) ns_calloc(1, sizeof(Server));
    srvPtr->name = server;

    srvPtr->proc = Ns_ConfigGetValue(path, "proc");
    srvPtr->rollhour = Ns_ConfigIntRange(path, "rollhour", 0, 0, 23);
    srvPtr->address = Ns_ConfigGetValue(path, "address");
    srvPtr->port = Ns_ConfigIntRange(path, "port", 514, 1, 65535);
    if (!(srvPtr->path = Ns_ConfigGetValue(path, "path"))) {
        srvPtr->path = "/dev/log";
    }
    srvPtr->options = LOG_PID;
    srvPtr->facility = LOG_USER;

    /* Configure Syslog listener */
    if (srvPtr->address) {
        if ((sock = Ns_SockListenUdp(srvPtr->address, srvPtr->port)) == -1) {
            Ns_Log(Error, "nssyslogd: couldn't create socket: %s:%d: %s", srvPtr->address, srvPtr->port, strerror(errno));
        } else {
            srvPtr->udp_sock = sock;
            Ns_SockCallback(sock, SyslogProc, srvPtr, NS_SOCK_READ | NS_SOCK_EXIT | NS_SOCK_EXCEPTION);
            Ns_Log(Notice, "nssyslogd: listening on %s:%d %s", srvPtr->address, srvPtr->port,
                   srvPtr->proc ? srvPtr->proc : "");
        }
    }
    if ((sock = Ns_SockListenUnix(srvPtr->path, 0, 0666)) == -1) {
        Ns_Log(Error, "nssyslogd: couldn't create socket: %s: %s", srvPtr->path, strerror(errno));
    } else {
        srvPtr->unix_sock = sock;
        Ns_SockCallback(sock, SyslogProc, srvPtr, NS_SOCK_READ | NS_SOCK_EXIT | NS_SOCK_EXCEPTION);
        Ns_Log(Notice, "nssyslogd: listening on %s %s", srvPtr->path, srvPtr->proc ? srvPtr->proc : "");
    }
    Ns_DStringInit(&srvPtr->buffer);
    Ns_RegisterAtShutdown(SyslogCloseCallback, srvPtr);
    Ns_ScheduleDaily((Ns_SchedProc *) SyslogRollCallback, srvPtr, 0, srvPtr->rollhour, 0, NULL);
    Ns_TclRegisterTrace(server, SyslogInterpInit, srvPtr, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SyslogInterpInit --
 *
 *      Add ns_snmp commands to interp.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
static int SyslogInterpInit(Tcl_Interp * interp, void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_syslogd", SyslogCmd, arg, NULL);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SyslogProc --
 *
 *	Socket callback to receive syslog events
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *  	None
 *
 *----------------------------------------------------------------------
 */

static int SyslogProc(SOCKET sock, void *arg, int why)
{
    struct sockaddr_in sa;
    Server *server = (Server *) arg;
    int i, rc, len, priority = -1, iFacility = 0, iSeverity = 0;
    char buf[1024], *ptr, *res = 0, *sFacility = "none", *sSeverity = "none";
    socklen_t salen = sizeof(struct sockaddr_in);

    if (why != NS_SOCK_READ) {
        close(sock);
        return NS_FALSE;
    }

    if (sock == server->udp_sock) {
        if ((len = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr *) &sa, &salen)) <= 0) {
            if (server->errors >= 0 && server->errors++ < 10) {
                Ns_Log(Error, "SyslogProc: %d: recvfrom error: %s", sock, strerror(errno));
            }
            return NS_TRUE;
        }
    } else {
        if ((len = recv(sock, buf, sizeof(buf) - 1, 0)) <= 0) {
            if (server->errors >= 0 && server->errors++ < 10) {
                Ns_Log(Error, "SyslogProc: %d: recv error: %s", sock, strerror(errno));
            }
            return NS_TRUE;
        }
        sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    }
    buf[len] = 0;
    ptr = buf;
    /* Parse priority */
    if (*ptr == '<') {
        priority = atoi(++ptr);
        while (isdigit(*ptr)) {
            ptr++;
        }
        if (*ptr != '>') {
            return NS_TRUE;
        }
        ptr++;
    }
    iFacility = priority / 8;
    iSeverity = priority - iFacility * 8;
    /* Parse timestamp: Mon dd hh:mm:ss */
    while (*ptr && !isspace(*ptr++));
    while (*ptr && !isspace(*ptr++));
    while (*ptr && !isspace(*ptr++));
    /* Bad line, ignore it */
    if (!*ptr) {
        return NS_TRUE;
    }
    /* Format the message */
    for (i = 0; SyslogFacilities[i].name; i++) {
        if (iFacility == SyslogFacilities[i].type) {
            sFacility = SyslogFacilities[i].name;
            break;
        }
    }
    for (i = 0; SyslogSeverities[i].name; i++) {
        if (iFacility == SyslogSeverities[i].type) {
            sFacility = SyslogSeverities[i].name;
            break;
        }
    }
    if (server->proc) {
        Tcl_Interp *interp = Ns_TclAllocateInterp(server->name);
        if (interp) {
            rc = Tcl_VarEval(interp, server->proc, " ", ns_inet_ntoa(sa.sin_addr), " ", sSeverity, " ", sFacility, " {", ptr,
                             "}", NULL);
            if (rc != TCL_OK) {
                Ns_TclLogError(interp);
            } else {
                res = (char *) Tcl_GetStringResult(interp);
                if (res && *res) {
                    rc = TCL_ERROR;
                }
            }
            Ns_TclDeAllocateInterp(interp);
            if (rc != TCL_OK) {
                return NS_TRUE;
            }
        }
    }
    Ns_Log(Notice, "%s/%s: %s", sSeverity, sFacility, ptr);
    return NS_TRUE;
}

/*
 *----------------------------------------------------------------------
 *
 * SysLogObjCmd --
 *
 *      Implement the ns_syslog command.
 *
 * Results:
 *      Standard Tcl result.
 *
 * Side effects:
 *      Depends on command.
 *
 *----------------------------------------------------------------------
 */

static int SyslogCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[])
{
    Server *srvPtr = (Server *) arg;
    char *str;
    int i, j, severity, status, cmd;
    Tcl_Obj *path;
    SyslogFile *logPtr;

    enum {
        cmdWrite, cmdCreate, cmdRoll, cmdList, cmdStat, cmdFlush, cmdSend
    };
    static CONST char *subcmd[] = {
        "write", "create", "roll", "list", "stat", "flush", "send",
        NULL
    };

    if (objc < 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "option ?arg ...?");
        return TCL_ERROR;
    }
    status = Tcl_GetIndexFromObj(interp, objv[1], subcmd, "option", 0, &cmd);
    if (status != TCL_OK) {
        return TCL_ERROR;
    }

    switch (cmd) {
    case cmdCreate:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name file ?-maxbackup num? ?-maxlines num? ?-rollfmt str?");
            return TCL_ERROR;
        }
        logPtr = (SyslogFile *) ns_calloc(1, sizeof(SyslogFile));
        Ns_DStringInit(&logPtr->buffer);
        logPtr->name = ns_strdup(Tcl_GetString(objv[2]));
        logPtr->file = ns_strdup(Tcl_GetString(objv[3]));
        logPtr->maxbackup = 7;
        logPtr->maxlines = 2;
        for (i = 4; i < objc - 1; i = i + 2) {
            if (!strcmp(Tcl_GetString(objv[i]), "-maxbackup")) {
                Tcl_GetIntFromObj(interp, objv[i + 1], &logPtr->maxbackup);
            } else if (!strcmp(Tcl_GetString(objv[i]), "-maxlines")) {
                Tcl_GetIntFromObj(interp, objv[i + 1], &logPtr->maxlines);
            } else if (!strcmp(Tcl_GetString(objv[i]), "-rollftm")) {
                logPtr->rollfmt = ns_strdup(Tcl_GetString(objv[i + 1]));
            }
        }
        if (SyslogOpen(logPtr) != NS_OK) {
            SyslogFree(logPtr);
            return TCL_ERROR;
        }
        Ns_MutexLock(&srvPtr->mutex);
        logPtr->nextPtr = srvPtr->files;
        srvPtr->files = logPtr;
        Ns_MutexUnlock(&srvPtr->mutex);
        break;

    case cmdList:
        Ns_MutexLock(&srvPtr->mutex);
        for (logPtr = srvPtr->files; logPtr; logPtr = logPtr->nextPtr) {
            Tcl_AppendResult(interp, logPtr->name, " ", 0);
        }
        Ns_MutexUnlock(&srvPtr->mutex);
        break;

    case cmdStat:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name");
            return TCL_ERROR;
        }
        logPtr = SyslogFind(srvPtr, Tcl_GetString(objv[2]));
        if (logPtr) {
            Ns_DString ds;
            Ns_DStringInit(&ds);
            Ns_MutexLock(&logPtr->lock);
            Ns_DStringPrintf(&ds, "%s %s %d %d {%s} %lu", logPtr->name, logPtr->file,
                             logPtr->maxbackup, logPtr->maxlines,
                             logPtr->rollfmt ? logPtr->rollfmt : "", logPtr->writtenlines);
            Ns_MutexUnlock(&logPtr->lock);
            Tcl_AppendResult(interp, ds.string, 0);
            Ns_DStringFree(&ds);
        }
        break;

    case cmdWrite:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name args");
            return TCL_ERROR;
        }
        logPtr = SyslogFind(srvPtr, Tcl_GetString(objv[2]));
        if (!logPtr) {
            break;
        }
        SyslogWrite(logPtr, Tcl_GetString(objv[3]));
        break;

    case cmdFlush:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name args");
            return TCL_ERROR;
        }
        logPtr = SyslogFind(srvPtr, Tcl_GetString(objv[2]));
        if (!logPtr) {
            break;
        }
        SyslogWrite(logPtr, 0);
        break;

    case cmdRoll:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name");
            return TCL_ERROR;
        }
        logPtr = SyslogFind(srvPtr, Tcl_GetString(objv[2]));
        if (!logPtr) {
            break;
        }
        Ns_MutexLock(&logPtr->lock);
        if (objc == 2) {
            status = SyslogRoll(logPtr);
        } else if (objc > 2) {
            str = Tcl_GetString(objv[2]);
            if (Tcl_FSAccess(objv[2], F_OK) == 0) {
                status = Ns_RollFile(str, logPtr->maxbackup);
            } else {
                path = Tcl_NewStringObj(logPtr->file, -1);
                Tcl_IncrRefCount(path);
                status = Tcl_FSRenameFile(path, objv[2]);
                Tcl_DecrRefCount(path);
                if (status != 0) {
                    status = NS_ERROR;
                } else {
                    SyslogFlush(logPtr, &logPtr->buffer);
                    status = SyslogOpen(logPtr);
                }
            }
        }
        if (status != NS_OK) {
            Tcl_AppendResult(interp, "could not roll \"", logPtr->file, "\": ", Tcl_PosixError(interp), NULL);
        }
        Ns_MutexUnlock(&logPtr->lock);
        if (status != NS_OK) {
            return TCL_ERROR;
        }
        break;

    case cmdSend:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, " ?-facility num? ?-options num? ?-ident str? severity message");
            return TCL_ERROR;
        }
        Ns_MutexLock(&srvPtr->mutex);
        for (i = 4; i < objc - 1; i = i + 2) {
            if (!strcmp(Tcl_GetString(objv[i]), "-facility")) {
                for (j = 0; SyslogFacilities[j].name; j++) {
                    if (!strcasecmp(Tcl_GetString(objv[i + 1]), SyslogFacilities[j].name)) {
                        Ns_MutexLock(&srvPtr->mutex);
                        srvPtr->facility = SyslogFacilities[j].type;
                        Ns_MutexUnlock(&srvPtr->mutex);
                        break;
                    }
                }
                closelog();
                srvPtr->opened = 0;
                i += 2;
                continue;
            }
            if (!strcmp(Tcl_GetString(objv[i]), "-options")) {
                srvPtr->options = 0;
                if (strstr(Tcl_GetString(objv[i + 1]), "CONS")) {
                    srvPtr->options |= LOG_CONS;
                }
                if (strstr(Tcl_GetString(objv[i + 1]), "NDELAY")) {
                    srvPtr->options |= LOG_NDELAY;
                }
                if (strstr(Tcl_GetString(objv[i + 1]), "PERROR")) {
                    srvPtr->options |= LOG_PERROR;
                }
                if (strstr(Tcl_GetString(objv[i + 1]), "PID")) {
                    srvPtr->options |= LOG_PID;
                }
                if (strstr(Tcl_GetString(objv[i + 1]), "ODELAY")) {
                    srvPtr->options |= LOG_ODELAY;
                }
                if (strstr(Tcl_GetString(objv[i + 1]), "NOWAIT")) {
                    srvPtr->options |= LOG_NOWAIT;
                }
                closelog();
                srvPtr->opened = 0;
                i += 2;
                continue;
            }
            if (!strcmp(Tcl_GetString(objv[i]), "-ident")) {
                memset(srvPtr->ident, 0, sizeof(srvPtr->ident));
                strncpy(srvPtr->ident, Tcl_GetString(objv[i + 1]), sizeof(srvPtr->ident) - 1);
                closelog();
                srvPtr->opened = 0;
                i += 2;
                continue;
            }
            break;
        }
        severity = LOG_INFO;
        if (i < objc) {
            for (j = 0; SyslogSeverities[j].name; j++) {
                if (!strcasecmp(Tcl_GetString(objv[i + 1]), SyslogSeverities[j].name)) {
                    severity = SyslogSeverities[j].type;
                    break;
                }
            }
            i++;
        }
        if (i < objc) {
            if (!srvPtr->opened) {
                openlog(srvPtr->ident, srvPtr->options, srvPtr->facility);
                srvPtr->opened = 1;
            }
            syslog(severity, Tcl_GetString(objv[i]));
        }
        Ns_MutexUnlock(&srvPtr->mutex);
        break;
    }
    return TCL_OK;
}

static SyslogFile *SyslogFind(Server * srvPtr, const char *name)
{
    SyslogFile *logPtr;

    for (logPtr = srvPtr->files; logPtr; logPtr = logPtr->nextPtr) {
        if (!strcasecmp(name, logPtr->name)) {
            break;
        }
    }
    return logPtr;
}


static int SyslogOpen(SyslogFile * logPtr)
{
    int fd;

    fd = open(logPtr->file, O_APPEND | O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        Ns_Log(Error, "nssyslog: error '%s' opening '%s'", strerror(errno), logPtr->file);
        return NS_ERROR;
    }
    if (logPtr->fd > 0) {
        close(logPtr->fd);
    }
    logPtr->fd = fd;
    Ns_Log(Notice, "nssyslog: opened '%s'", logPtr->file);

    return NS_OK;
}

static int SyslogClose(SyslogFile * logPtr)
{
    int status = NS_OK;

    if (logPtr->fd > 0) {
        status = SyslogFlush(logPtr, &logPtr->buffer);
        close(logPtr->fd);
        logPtr->fd = -1;
        Ns_DStringFree(&logPtr->buffer);
        Ns_Log(Notice, "nssyslog: closed '%s'", logPtr->file);
    }

    return status;
}

static void SyslogFree(SyslogFile * logPtr)
{
    if (logPtr) {
        close(logPtr->fd);
        Ns_DStringFree(&logPtr->buffer);
        ns_free(logPtr->name);
        ns_free(logPtr->file);
        ns_free(logPtr->rollfmt);
        ns_free(logPtr);
    }
}

static int SyslogFlush(SyslogFile * logPtr, Ns_DString * dsPtr)
{
    int len = dsPtr->length;
    char *buf = dsPtr->string;

    if (len > 0) {
        if (logPtr->fd > 0 && write(logPtr->fd, buf, len) != len) {
            Ns_Log(Error, "nssyslog: %s: logging disabled: write() failed: '%s'", logPtr->name, strerror(errno));
            close(logPtr->fd);
            logPtr->fd = -1;
        }
        Ns_DStringTrunc(dsPtr, 0);
    }
    return (logPtr->fd == -1) ? NS_ERROR : NS_OK;
}

static int SyslogRoll(SyslogFile * logPtr)
{
    int status;
    Tcl_Obj *path, *newpath;

    SyslogClose(logPtr);
    path = Tcl_NewStringObj(logPtr->file, -1);
    Tcl_IncrRefCount(path);
    status = Tcl_FSAccess(path, F_OK);

    if (status == 0) {

        /*
         * We are already logging to some file
         */

        if (logPtr->rollfmt == NULL) {
            status = Ns_RollFile(logPtr->file, logPtr->maxbackup);
        } else {
            time_t now = time(0);
            char timeBuf[512];
            Ns_DString ds;
            struct tm *ptm = ns_localtime(&now);

            strftime(timeBuf, sizeof(timeBuf) - 1, logPtr->rollfmt, ptm);
            Ns_DStringInit(&ds);
            Ns_DStringVarAppend(&ds, logPtr->file, ".", timeBuf, NULL);
            newpath = Tcl_NewStringObj(ds.string, -1);
            Tcl_IncrRefCount(newpath);
            status = Tcl_FSAccess(newpath, F_OK);
            if (status == 0) {
                status = Ns_RollFile(ds.string, logPtr->maxbackup);
            } else if (Tcl_GetErrno() != ENOENT) {
                Ns_Log(Error, "nssyslog: access(%s, F_OK) failed: '%s'", ds.string, strerror(Tcl_GetErrno()));
                status = NS_ERROR;
            }
            if (status == NS_OK && Tcl_FSRenameFile(path, newpath)) {
                Ns_Log(Error, "nssyslog: rename(%s,%s) failed: '%s'", logPtr->file, ds.string, strerror(Tcl_GetErrno()));
                status = NS_ERROR;
            }
            Tcl_DecrRefCount(newpath);
            Ns_DStringFree(&ds);
            if (status == NS_OK) {
                status = Ns_PurgeFiles(logPtr->file, logPtr->maxbackup);
            }
        }
    }
    Tcl_DecrRefCount(path);
    return (status == NS_OK) ? SyslogOpen(logPtr) : NS_ERROR;
}

static void SyslogCallback(int (proc) (SyslogFile *), void *arg, char *desc)
{
    int status;
    SyslogFile *logPtr = (SyslogFile *) arg;

    Ns_MutexLock(&logPtr->lock);
    status = (*proc) (logPtr);
    Ns_MutexUnlock(&logPtr->lock);

    if (status != NS_OK) {
        Ns_Log(Error, "nssyslog: failed: %s '%s': '%s'", desc, logPtr->file, strerror(Tcl_GetErrno()));
    }
}

static void SyslogCloseCallback(Ns_Time * toPtr, void *arg)
{
    Server *srvPtr = (Server *) arg;
    SyslogFile *logPtr;

    for (logPtr = srvPtr->files; logPtr; logPtr = logPtr->nextPtr) {
        SyslogCallback(SyslogClose, logPtr, "close");
    }
}

static void SyslogRollCallback(void *arg)
{
    Server *srvPtr = (Server *) arg;
    SyslogFile *logPtr;

    for (logPtr = srvPtr->files; logPtr; logPtr = logPtr->nextPtr) {
        SyslogCallback(SyslogRoll, logPtr, "roll");
    }
}

static void SyslogWrite(SyslogFile * logPtr, char *str)
{
    Ns_MutexLock(&logPtr->lock);
    if (str) {
        Ns_DStringAppend(&logPtr->buffer, str);
        Ns_DStringAppend(&logPtr->buffer, "\n");
        logPtr->curlines++;
    }
    if (!str || logPtr->curlines > logPtr->maxlines) {
        SyslogFlush(logPtr, &logPtr->buffer);
        logPtr->writtenlines += logPtr->curlines;
        logPtr->curlines = 0;
    }
    Ns_MutexUnlock(&logPtr->lock);
}
