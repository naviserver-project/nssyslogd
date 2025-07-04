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
    unsigned long maxlines;
    unsigned long curlines;
    unsigned long writtenlines;
    Ns_Mutex lock;
    Tcl_DString buffer;
    struct {
      char *string;
      char flags[LOG_NFACILITIES][LOG_DEBUG];
    } map;
} SyslogFile;

typedef struct _syslogConfig {
    Ns_Mutex mutex;
    Tcl_DString buffer;
    SyslogFile *files;
    short maps;
} SyslogConfig;

typedef struct _syslogServer {
    unsigned short port;
    const char *name;
    const char *proc;
    const char *address;
    int rollhour;
    int sock;
    int unixmode;
    bool drivermode;
    bool globalmode;
    short errors;
    SyslogConfig *config;
} SyslogServer;

typedef struct _syslogRequest {
    SyslogServer *server;
    size_t size;
    char *line;
    char *buffer;
    char *timestamp;
    struct sockaddr_storage sa;
    struct {
      unsigned int code;
      const char *name;
    } facility;
    struct {
      unsigned int code;
      const char *name;
    } severity;
} SyslogRequest;

typedef struct _syslogTls {
    int      sock;                /* fd for log */
    unsigned short port;                /* port for remote syslog */
    int      connected;           /* have done connect */
    int      options;             /* status bits, set by openlog() */
    char     *tag;                /* string to tag the entry with */
    const char *path;             /* path to socket or hostname */
    int      facility;            /* default facility code */
    int      severity;            /* default severity code */
} SyslogTls;

static Ns_ObjvTable syslogFacilities[] = {
    { "kern",     LOG_KERN },
    { "user",     LOG_USER },
    { "mail",     LOG_MAIL },
    { "daemon",   LOG_DAEMON },
    { "auth",     LOG_AUTH },
    { "intern",   LOG_SYSLOG },
    { "print",    LOG_LPR },
    { "news",     LOG_NEWS },
    { "uucp",     LOG_UUCP },
    { "clock",    LOG_CRON },
    { "security", LOG_AUTHPRIV },
    { "authpriv", LOG_AUTHPRIV },
    { "ftp",      LOG_FTP },
    { "local0",   LOG_LOCAL0 },
    { "local1",   LOG_LOCAL1 },
    { "local2",   LOG_LOCAL2 },
    { "local3",   LOG_LOCAL3 },
    { "local4",   LOG_LOCAL4 },
    { "local5",   LOG_LOCAL5 },
    { "local6",   LOG_LOCAL6 },
    { "local7",   LOG_LOCAL7 },
    { NULL,       0 }
};

static Ns_ObjvTable syslogSeverities[] = {
    { "emergency", LOG_EMERG },
    { "alert",     LOG_ALERT },
    { "critical",  LOG_CRIT },
    { "error",     LOG_ERR },
    { "warning",   LOG_WARNING },
    { "notice",    LOG_NOTICE },
    { "info",      LOG_INFO },
    { "debug",     LOG_DEBUG },
    { NULL,        0 }
};

static Ns_ObjvTable syslogOptions[] = {
    { "CONS",   LOG_CONS },
    { "NDELAY", LOG_NDELAY },
    { "PERROR", LOG_PERROR },
    { "PID",    LOG_PID },
    { "ODELAY", LOG_ODELAY },
    { "NOWAIT", LOG_NOWAIT },
    { NULL,     0 }
};

/*
 * Local functions defined in this file.
 */

static Ns_DriverListenProc Listen;
static Ns_DriverAcceptProc Accept;
static Ns_DriverRecvProc Recv;
static Ns_DriverSendProc Send;
static Ns_DriverSendFileProc SendFile;
static Ns_DriverKeepProc Keep;
static Ns_DriverCloseProc Close;
static Ns_DriverRequestProc Request;

static SyslogTls *SyslogGetTls(void);
static void SyslogFreeTls(void *arg);
static void SyslogInit(const char *path, const char *tag, int options, int facility);
static void SyslogShutdown(void);
static void SyslogSend(int severity, const char *fmt, ...);
static void SyslogSendV(int severity, const char *fmt, va_list ap);
static int SyslogCmd(ClientData arg, Tcl_Interp * interp, int objc, Tcl_Obj * CONST objv[]);
static SyslogFile *SyslogFind(SyslogServer * srvPtr, const char *name);
static SyslogFile *SyslogFindMap(SyslogServer * srvPtr, unsigned int facility, unsigned int priority);
static int SyslogOpen(SyslogFile * logPtr);
static int SyslogClose(SyslogFile * logPtr);
static int SyslogFlush(SyslogFile * logPtr, Tcl_DString * dsPtr);
static int SyslogRoll(SyslogFile * logPtr);
static void SyslogWrite(SyslogFile * logPtr, char *line, char *timestamp);
static void SyslogFree(SyslogFile * logPtr);
static void SyslogCallback(int (proc) (SyslogFile *), void *arg, char *desc);
static void SyslogCloseCallback(Ns_Time * toPtr, void *arg);
static void SyslogRollCallback(void *arg);
static int SyslogRequestProcess(SyslogRequest *req);
static ssize_t SyslogRequestRead(SyslogServer *server, NS_SOCKET sock, char *buffer, size_t size, struct sockaddr *saPtr);
static SyslogRequest *SyslogRequestCreate(SyslogServer *server, NS_SOCKET sock, char *buffer, size_t size, struct sockaddr *saPtr);


NS_EXPORT Ns_ModuleInitProc Ns_ModuleInit;
static Ns_TclTraceProc SyslogInterpInit;
static Ns_SockProc SyslogSockProc;

static Ns_Tls logTls;
static Ns_Tls reqTls;
static unsigned int maxFacility = 0u;
static SyslogConfig *globalConfig = NULL;

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

NS_EXPORT Ns_ReturnCode Ns_ModuleInit(const char *server, const char *module)
{
    const char *path;
    SyslogServer *srvPtr;
    Ns_DriverInitData init = {0};
    static int first = 0;

    if (!first) {
        for (first = 0; syslogFacilities[first].key; first++) {
             maxFacility = MAX(maxFacility, syslogFacilities[first].value);
        }
        Ns_TlsAlloc(&logTls, SyslogFreeTls);
        Ns_TlsAlloc(&reqTls, NULL);
        first = 1;
    }

    path = Ns_ConfigGetPath(server, module, NULL);
    srvPtr = (SyslogServer *) ns_calloc(1, sizeof(SyslogServer));
    srvPtr->name = server;
    srvPtr->port = (unsigned short)Ns_ConfigIntRange(path, "port", 514, 1, 65535);
    srvPtr->proc = Ns_ConfigGetValue(path, "proc");
    srvPtr->rollhour = Ns_ConfigIntRange(path, "rollhour", 0, 0, 23);
    srvPtr->address = Ns_ConfigGetValue(path, "address");
    Ns_ConfigGetBool(path, "drivermode", &srvPtr->drivermode);
    Ns_ConfigGetBool(path, "globalmode", &srvPtr->globalmode);
    if (srvPtr->address == NULL) {
        srvPtr->address = "/dev/log";
    }
    if (Ns_PathIsAbsolute(srvPtr->address)) {
        srvPtr->unixmode = 1;
    }

    /* Configure Syslog listener */
    if (srvPtr->drivermode) {
        init.version = NS_DRIVER_VERSION_2;
        init.name = "nssyslogd";
        init.listenProc = Listen;
        init.acceptProc = Accept;
        init.recvProc = Recv;
        init.sendProc = Send;
        init.sendFileProc = SendFile;
        init.keepProc = Keep;
        init.requestProc = Request;
        init.closeProc = Close;
        init.opts = NS_DRIVER_ASYNC|NS_DRIVER_NOPARSE;
        init.arg = srvPtr;
        init.path = path;

        if (Ns_DriverInit(server, module, &init) != NS_OK) {
            Ns_Log(Error, "%s: driver init failed", module);
            ns_free(srvPtr);
            return NS_ERROR;
        }

    } else {
        if (srvPtr->unixmode) {
            srvPtr->sock = Ns_SockListenUnix(srvPtr->address, 0, 0666);
        } else {
            srvPtr->sock = Ns_SockListenUdp(srvPtr->address, srvPtr->port, NS_FALSE);
        }
        if (srvPtr->sock == -1) {
            Ns_Log(Error, "nssyslogd: couldn't create socket: %s:%d: %s", srvPtr->address, srvPtr->port, strerror(errno));
            ns_free(srvPtr);
            return NS_ERROR;
        }
        Ns_SockCallback(srvPtr->sock, SyslogSockProc, srvPtr, NS_SOCK_READ | NS_SOCK_EXIT | NS_SOCK_EXCEPTION);
        Ns_Log(Notice, "%s: listening on %s:%d with proc <%s>", module, srvPtr->address, srvPtr->port,
                   srvPtr->proc ? srvPtr->proc : "");
    }

    /*
     *  In global mode all modules are linked to the same files and buffers
     *  which will allow multiple servers listening on different ports, like
     *  Unix and UDP to re-use the same configuration.
     */

    if (!srvPtr->globalmode || !globalConfig) {
        srvPtr->config = ns_calloc(1, sizeof(SyslogConfig));
        Tcl_DStringInit(&srvPtr->config->buffer);
    }
    if (!globalConfig) {
        globalConfig = srvPtr->config;
    }
    if (srvPtr->globalmode) {
        srvPtr->config = globalConfig;
    }

    Ns_RegisterAtShutdown((Ns_ShutdownProc*)SyslogCloseCallback, srvPtr);
    Ns_ScheduleDaily((Ns_SchedProc *) SyslogRollCallback, srvPtr, 0, srvPtr->rollhour, 0, NULL);
    Ns_TclRegisterTrace(server, SyslogInterpInit, srvPtr, NS_TCL_TRACE_CREATE);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * Listen --
 *
 *      Open a listening socket in non-blocking mode.
 *
 * Results:
 *      The open socket or NS_INVALID_SOCKET on error.
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static NS_SOCKET Listen(Ns_Driver *driver, CONST char *address, unsigned short port, int backlog, bool reusePort)
{
    NS_SOCKET sock;
    SyslogServer *srvPtr = (SyslogServer*)driver->arg;

    if (srvPtr->unixmode) {
        sock = Ns_SockListenUnix(srvPtr->address, 0, 0666);
    } else {
        sock = Ns_SockListenUdp(srvPtr->address, srvPtr->port, NS_FALSE);
    }
    if (sock != NS_INVALID_SOCKET) {
        (void) Ns_SockSetNonBlocking(sock);
    }
    return sock;
}


/*
 *----------------------------------------------------------------------
 *
 * Accept --
 *
 *      Accept a new socket in non-blocking mode.
 *
 * Results:
 *      NS_DRIVER_ACCEPT_DATA  - socket accepted, data present
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static NS_DRIVER_ACCEPT_STATUS
Accept(Ns_Sock *sock, NS_SOCKET listensock, struct sockaddr *sockaddrPtr, socklen_t *socklenPtr)
{
    sock->sock = listensock;
    return NS_DRIVER_ACCEPT_DATA;
}


/*
 *----------------------------------------------------------------------
 *
 * Recv --
 *
 *      Receive data into given buffers.
 *
 * Results:
 *      Total number of bytes received or -1 on error or timeout.
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static ssize_t Recv(Ns_Sock *sock, struct iovec *bufs, int nbufs, Ns_Time *timeoutPtr, unsigned int flags)
{
    socklen_t len = sizeof(sock->sa);

    return recvfrom(sock->sock, bufs->iov_base, bufs->iov_len - 1, 0, (struct sockaddr*)&sock->sa, &len);
}


/*
 *----------------------------------------------------------------------
 *
 * Send --
 *
 *      Send data from given buffers.
 *
 * Results:
 *      Total number of bytes sent or -1 on error or timeout.
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static ssize_t Send(Ns_Sock *sock, const struct iovec *bufs, int nbufs,
#if NS_MAJOR_VERSION < 5
                    const Ns_Time *timeoutPtr,
#endif
                    unsigned int flags)
{
    return -1;
}


/*
 *----------------------------------------------------------------------
 *
 * SendFile --
 *
 *      Send given file buffers directly to socket.
 *
 * Results:
 *      Total number of bytes sent or -1 on error or timeout.
 *
 * Side effects:
 *      May block once for driver sendwait timeout seconds if first
 *      attempt would block.
 *      May block 1 or more times due to disk IO.
 *
 *----------------------------------------------------------------------
 */

static ssize_t SendFile(Ns_Sock *sock, Ns_FileVec *bufs, int nbufs,
#if NS_MAJOR_VERSION < 5
                        Ns_Time *timeoutPtr,
#endif
                        unsigned int flags)
{
    return -1;
}


/*
 *----------------------------------------------------------------------
 *
 * Keep --
 *
 *      No keepalives
 *
 * Results:
 *      NS_FALSE, always.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */

static bool Keep(Ns_Sock *sock)
{
    return NS_FALSE;
}

/*
 *----------------------------------------------------------------------
 *
 * Request --
 *
 *	Request callback for processing syslog connections
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static int Request(void *arg, Ns_Conn *conn)
{
    Tcl_DString *ds;
    Ns_Sock *sockPtr;
    SyslogRequest *req;
    struct sockaddr_storage sa;
    SyslogServer *server = (SyslogServer*)arg;

    ds = Ns_ConnSockContent(conn);
    sockPtr = Ns_ConnSockPtr(conn);
    sa = sockPtr->sa;

    req = SyslogRequestCreate(server, sockPtr->sock, ds->string, (size_t)ds->length, (struct sockaddr *)&sa);
    if (req != NULL) {
        SyslogRequestProcess(req);
        ns_free(req);
    }
    return NS_FILTER_BREAK;
}


/*
 *----------------------------------------------------------------------
 *
 * Close --
 *
 *      Close the connection socket.
 *
 * Results:
 *      None.
 *
 * Side effects:
 *      Does not close UDP socket
 *
 *----------------------------------------------------------------------
 */

static void Close(Ns_Sock *sock)
{
    sock->sock = -1;
}

/*
 *----------------------------------------------------------------------
 *
 * SyslogInterpInit --
 *
 *      Add ns_snmp commands to interp.
 *
 * Results:
 *      Ns_ReturnCode.
 *
 * Side effects:
 *      None.
 *
 *----------------------------------------------------------------------
 */
static Ns_ReturnCode SyslogInterpInit(Tcl_Interp * interp, const void *arg)
{
    Tcl_CreateObjCommand(interp, "ns_syslogd", SyslogCmd, (ClientData)arg, NULL);
    return NS_OK;
}

/*
 *----------------------------------------------------------------------
 *
 * SyslogSockProc --
 *
 *	Socket callback to receive syslog events
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static bool SyslogSockProc(NS_SOCKET sock, void *arg, unsigned int why)
{
    SyslogServer *server = (SyslogServer*)arg;
    struct sockaddr_storage sa;
    SyslogRequest *req;
    char buffer[2048];
    ssize_t len;

    if (why != NS_SOCK_READ) {
        ns_sockclose(sock);
        return NS_FALSE;
    }
    len = SyslogRequestRead(server, sock, buffer, sizeof(buffer), (struct sockaddr *)&sa);
    req = SyslogRequestCreate(server, sock, buffer, (size_t)len, (struct sockaddr *)&sa);
    if (req != NULL) {
        SyslogRequestProcess(req);
        ns_free(req);
    }
    return NS_TRUE;
}

/*
 *----------------------------------------------------------------------
 *
 * SyslogRequestCreate --
 *
 *	Create request structure
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static SyslogRequest *SyslogRequestCreate(SyslogServer *server, NS_SOCKET sock, char *buffer, size_t size, struct sockaddr *saPtr)
{
    if (buffer != NULL && size > 0) {
        SyslogRequest *req = ns_calloc(1, sizeof(SyslogRequest));
        req->server = server;
        req->buffer = buffer;
        req->size = size;
        req->sa = *(struct sockaddr_storage *)saPtr;
        req->severity.name = "none";
        req->facility.name = "none";
        return req;
    }
    return NULL;
}

/*
 *----------------------------------------------------------------------
 *
 * SyslogRequestRead --
 *
 *	Read syslog data from the socket
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static ssize_t SyslogRequestRead(SyslogServer *server, NS_SOCKET sock, char *buffer, size_t size, struct sockaddr *saPtr)
{
    ssize_t len;
    socklen_t salen = sizeof(struct sockaddr_in);

    if (server->unixmode) {
        ns_inet_pton(saPtr, NS_IP_LOOPBACK);
        len = recv(sock, buffer, size - 1, 0);
    } else {
        len = recvfrom(sock, buffer, size - 1, 0, saPtr, (socklen_t*)&salen);
    }
    if (len <= 0) {
        if (errno && server->errors >= 0 && server->errors++ < 10) {
            Ns_Log(Error, "SyslogRequestRead: %d: %s recv error: %d bytes, %s",
                   sock, server->unixmode ? "tcp" : "udp", (int)len, strerror(errno));
        }
        return NS_ERROR;
    }
    buffer[len] = 0;
    return len;
}

/*
 *----------------------------------------------------------------------
 *
 * SyslogRequestProcess --
 *
 *	Perform actual syslogging
 *
 * Results:
 *	NS_TRUE
 *
 * Side effects:
 *      None
 *
 *----------------------------------------------------------------------
 */

static int SyslogRequestProcess(SyslogRequest *req)
{
    SyslogServer *srvPtr = req->server;
    int rc, priority = -1;
    size_t i;

    req->line = req->buffer;
    /* Parse priority */
    if (*req->line == '<') {
        priority = atoi(++req->line);
        while (isdigit(*req->line)) {
            req->line++;
        }
        if (*req->line != '>') {
            return NS_TRUE;
        }
        req->line++;
    }
    req->facility.code = ((unsigned int)LOG_FAC(priority)) << 3;
    req->severity.code = LOG_PRI(priority);
    /* Parse timestamp: Mon dd hh:mm:ss */
    req->timestamp = req->line;
    while (*req->line && !isspace(*req->line++));
    while (*req->line && !isspace(*req->line++));
    while (*req->line && !isspace(*req->line++));
    /* Bad line, ignore it */
    if (!*req->line) {
        return NS_TRUE;
    }
    for (i = strlen(req->line) - 1u; i > 0 && isspace(req->line[i]); i--) {
        req->line[i] = 0;
    }
    /* Format the message */
    for (i = 0u; syslogFacilities[i].key; i++) {
        if (req->facility.code == syslogFacilities[i].value) {
            req->facility.name = syslogFacilities[i].key;
            break;
        }
    }
    for (i = 0u; syslogSeverities[i].key; i++) {
        if (req->severity.code == syslogSeverities[i].value) {
            req->severity.name = syslogSeverities[i].key;
            break;
        }
    }

    /*
     *  Global syslog script is enabled, call it and let him write the actual lines,
     *  if it returns nothing, then just write the line into our nsd.log
     */

    if (srvPtr->proc) {
        Tcl_Interp *interp = Ns_TclAllocateInterp(srvPtr->name);
        if (interp) {
            Ns_TlsSet(&reqTls, req);
            rc = Tcl_EvalEx(interp, srvPtr->proc, -1, 0);
            if (rc != TCL_OK) {
                (void) Ns_TclLogErrorInfo(interp, "\n(context: syslogd eval)");
            } else {
                char *res = (char *) Tcl_GetStringResult(interp);
                if (res && *res) {
                    rc = TCL_ERROR;
                }
            }
            Ns_TlsSet(&reqTls, NULL);
            Ns_TclDeAllocateInterp(interp);
            if (rc != TCL_OK) {
                return NS_TRUE;
            }
        }
    } else

    /*
     * If automatic mapping is configured on the server, find the log file by facility.severity
     * and write line there
     */

    if (srvPtr->config->maps) {
        SyslogFile *logPtr = SyslogFindMap(srvPtr, req->facility.code, req->severity.code);
        if (logPtr) {
            Ns_MutexLock(&logPtr->lock);
            SyslogWrite(logPtr, req->line, req->timestamp);
            Ns_MutexUnlock(&logPtr->lock);
            return NS_TRUE;
        }
    }
    Ns_Log(Notice, "%s/%s: %s", req->facility.name, req->severity.name, req->line);
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
    SyslogServer *srvPtr = (SyslogServer *) arg;
    SyslogRequest *req;
    SyslogFile *logPtr;
    char *str = NULL;
    Tcl_Obj *strPtr;
    int i, j, status, cmd;

    enum {
        cmdWrite, cmdCreate, cmdRoll, cmdList, cmdStat, cmdFlush, cmdSend, cmdReq
    };
    static CONST char *subcmd[] = {
        "write", "create", "roll", "list", "stat", "flush", "send", "req",
        NULL
    };
    enum {
        reqArray, reqLine, reqFullLine, reqPeeraddr, reqFacility, reqSeverity
    };
    static CONST char *reqcmd[] = {
        "array", "line", "peeraddr", "facility", "severity",
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
    case cmdCreate: {
        SyslogFile *logPtr = (SyslogFile *) ns_calloc(1, sizeof(SyslogFile));

        Ns_ObjvSpec crOpts[] = {
            {"-maxbackup", Ns_ObjvInt,    &logPtr->maxbackup,  NULL},
            {"-maxlines",  Ns_ObjvInt,    &logPtr->maxlines,   NULL},
            {"-rollfmt",   Ns_ObjvString, &logPtr->rollfmt,    NULL},
            {"-map",       Ns_ObjvString, &str,                NULL},
            {"--",         Ns_ObjvBreak,  NULL,    NULL},
            {NULL, NULL, NULL, NULL}
        };
        Ns_ObjvSpec crArgs[] = {
            {"name",       Ns_ObjvString, &logPtr->name,      NULL},
            {"file",       Ns_ObjvString, &logPtr->file,      NULL},
            {NULL, NULL, NULL, NULL}
        };

        logPtr->maxlines = 2;
        logPtr->maxbackup = 7;

        if (Ns_ParseObjv(crOpts, crArgs, interp, 2, objc, objv) != NS_OK) {
            ns_free(logPtr);
            return TCL_ERROR;
        }
        if (str != NULL) {
            CONST char **argv;
            char *fname, *sname;
            int argc, ok;
            int fmax, fcode, scode;

            /*
             *  map is a list of facility[.severity] codes that apply to this
             *  log, server will match them and write automatically.
             *  Format is: facility or facility.severity
             *    where severity can be none or actual severity name, without
             *          it all lines with given facility will be matched for all
             *          severity codes, without facility, severity applies to all
             *
             *     -map { daemon mail.alert local6 local7.none .info }
             */

            if (Tcl_SplitList(NULL, str, &argc, &argv) != TCL_OK) {
                Ns_Log(Error,"nssyslog: %s: invalid map parameter: %s", logPtr->name, logPtr->map.string);
                ns_free(logPtr);
                return TCL_ERROR;
            }
            for (i = 0; i < argc; i++) {
                 ok = 1;
                 fmax = fcode = scode = -1;
                 fname = (char*)argv[i];
                 sname = strchr(fname, '.');

                 /*
                  * Split facility.severity
                  */

                 if (sname != NULL) {

                     /*
                      * Use all syslog facilities
                      */

                     if (sname == fname) {
                         fname = NULL;
                         fcode = 0;
                         fmax = (int)maxFacility;
                     }
                     *sname++ = 0;
                     if (!strcasecmp(sname, "none")) {
                         ok = 0;
                         scode = LOG_DEBUG;
                     }
                 } else {
                     scode = LOG_DEBUG;
                 }

                 for (j = 0; fname && syslogFacilities[j].key; j++) {
                     if (!strcasecmp(fname, syslogFacilities[j].key)) {
                         fmax = fcode = (int)syslogFacilities[j].value;
                         fmax++;
                         break;
                     }
                 }
                 for (j = 0; sname && syslogSeverities[j].key; j++) {
                     if (!strcasecmp(sname, syslogSeverities[j].key)) {
                         scode = (int)syslogSeverities[j].value;
                         break;
                     }
                 }

                 if ((fname && fcode == -1) || (sname && scode == -1)) {
                     Ns_Log(Error, "nssyslog: %s: invalid facility.priority: %s.%s", logPtr->name, fname, sname);
                     continue;
                 }

                 /*
                  * Assign all facilities and severities in the mapping table
                  */
                 srvPtr->config->maps++;

                 while (fcode <= fmax) {
                     for (j = 0; j <= scode; j++) {
                         logPtr->map.flags[fcode][j] = (char)ok;
                     }
                     fcode++;
                 }
            }
            Tcl_Free((char *)argv);
        }

        Tcl_DStringInit(&logPtr->buffer);
        logPtr->name = ns_strdup(logPtr->name);
        logPtr->file = ns_strdup(logPtr->file);
        logPtr->rollfmt = ns_strcopy(logPtr->rollfmt);
        if (SyslogOpen(logPtr) != NS_OK) {
            SyslogFree(logPtr);
            return TCL_ERROR;
        }
        Ns_MutexLock(&srvPtr->config->mutex);
        logPtr->nextPtr = srvPtr->config->files;
        srvPtr->config->files = logPtr;
        Ns_MutexUnlock(&srvPtr->config->mutex);
        break;
     }

    case cmdList:
        Ns_MutexLock(&srvPtr->config->mutex);
        for (logPtr = srvPtr->config->files; logPtr; logPtr = logPtr->nextPtr) {
            Tcl_AppendResult(interp, logPtr->name, " {", NULL);
            for (i = 0; i < LOG_NFACILITIES; i++) {
                for (j = 0; j < LOG_DEBUG; j++) {
                    if (logPtr->map.flags[i][j])
                        Tcl_AppendResult(interp, syslogFacilities[i].key, "/", syslogSeverities[j].key, " ", NULL);
                }
            }
            Tcl_AppendResult(interp, "} ", NULL);
        }
        Ns_MutexUnlock(&srvPtr->config->mutex);
        break;

    case cmdStat:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name");
            return TCL_ERROR;
        }
        logPtr = SyslogFind(srvPtr, Tcl_GetString(objv[2]));
        if (logPtr) {
            Tcl_DString ds;
            Tcl_DStringInit(&ds);
            Ns_MutexLock(&logPtr->lock);
            Ns_DStringPrintf(&ds, "%s %s %d %lu {%s} %lu", logPtr->name, logPtr->file,
                             logPtr->maxbackup, logPtr->maxlines,
                             logPtr->rollfmt ? logPtr->rollfmt : "", logPtr->writtenlines);
            Ns_MutexUnlock(&logPtr->lock);
            Tcl_AppendResult(interp, ds.string, 0);
            Tcl_DStringFree(&ds);
        }
        break;

    case cmdWrite:
        if (objc < 4) {
            Tcl_WrongNumArgs(interp, 2, objv, "name line ?timestamp?");
            return TCL_ERROR;
        }
        logPtr = SyslogFind(srvPtr, Tcl_GetString(objv[2]));
        if (!logPtr) {
            break;
        }
        Ns_MutexLock(&logPtr->lock);
        SyslogWrite(logPtr, Tcl_GetString(objv[3]), objc > 4 ? Tcl_GetString(objv[4]) : NULL);
        Ns_MutexUnlock(&logPtr->lock);
        break;

    case cmdFlush:
        if (objc < 3) {
            Tcl_WrongNumArgs(interp, 2, objv, "name args");
            return TCL_ERROR;
        }
        logPtr = SyslogFind(srvPtr, Tcl_GetString(objv[2]));
        if (!logPtr) {
            break;
        }
        Ns_MutexLock(&logPtr->lock);
        SyslogWrite(logPtr, 0, 0);
        Ns_MutexUnlock(&logPtr->lock);
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
                strPtr = Tcl_NewStringObj(logPtr->file, -1);
                Tcl_IncrRefCount(strPtr);
                status = Tcl_FSRenameFile(strPtr, objv[2]);
                Tcl_DecrRefCount(strPtr);
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

    case cmdSend: {
        char *host = NULL, *tag = NULL;
        int severity = -1, options = 0, facility = -1;
        Ns_ObjvSpec sndOpts[] = {
            {"-host",      Ns_ObjvString, &host,      NULL},
            {"-tag",       Ns_ObjvString, &tag,       NULL},
            {"-facility",  Ns_ObjvIndex,  &facility,  syslogFacilities},
            {"-severity",  Ns_ObjvIndex,  &severity,  syslogSeverities},
            {"-options",   Ns_ObjvFlags,  &options,   syslogOptions},
            {"--",         Ns_ObjvBreak,  NULL,       NULL},
            {NULL, NULL, NULL, NULL}
        };
        Ns_ObjvSpec sndArgs[] = {
            {"str",         Ns_ObjvString, &str,       NULL},
            {NULL, NULL, NULL, NULL}
        };
        if (Ns_ParseObjv(sndOpts, sndArgs, interp, 2, objc, objv) != NS_OK) {
            return TCL_ERROR;
        }
        SyslogInit(host, tag, options, facility);
        SyslogSend(severity, str);
        break;
      }

    case cmdReq:
        req = Ns_TlsGet(&reqTls);
        if (req == NULL) {
            break;
        }
        if (objc > 2) {
            if (Tcl_GetIndexFromObj(interp, objv[2], reqcmd, "option", 0, &cmd) != TCL_OK) {
                return TCL_ERROR;
            }
        }
        strPtr = Tcl_NewObj();
        switch (cmd) {
        case reqArray:
            Tcl_ListObjAppendElement(interp, strPtr, Tcl_NewStringObj(ns_inet_ntoa((struct sockaddr *)&req->sa), -1));
            Tcl_ListObjAppendElement(interp, strPtr, Tcl_NewStringObj(req->facility.name, -1));
            Tcl_ListObjAppendElement(interp, strPtr, Tcl_NewStringObj(req->severity.name, -1));
            Tcl_ListObjAppendElement(interp, strPtr, Tcl_NewStringObj(req->line, -1));
            break;

        case reqPeeraddr:
            Tcl_SetStringObj(strPtr, ns_inet_ntoa((struct sockaddr *)&req->sa), -1);
            break;

        case reqFacility:
            Tcl_SetStringObj(strPtr, req->facility.name, -1);
            break;

        case reqSeverity:
            Tcl_SetStringObj(strPtr, req->severity.name, -1);
            break;

        case reqLine:
        default:
            Tcl_SetStringObj(strPtr, req->line, -1);
            break;
        }
        Tcl_SetObjResult(interp, strPtr);
        break;
    }
    return TCL_OK;
}

static SyslogFile *SyslogFind(SyslogServer * srvPtr, const char *name)
{
    SyslogFile *logPtr;

    Ns_MutexLock(&srvPtr->config->mutex);
    for (logPtr = srvPtr->config->files; logPtr; logPtr = logPtr->nextPtr) {
        if (!strcasecmp(name, logPtr->name)) {
            break;
        }
    }
    Ns_MutexUnlock(&srvPtr->config->mutex);
    return logPtr;
}

static SyslogFile *SyslogFindMap(SyslogServer * srvPtr, unsigned int facility, unsigned int severity)
{
    SyslogFile *logPtr;

    if (facility > maxFacility || severity > LOG_DEBUG) {
        return NULL;
    }

    Ns_MutexLock(&srvPtr->config->mutex);
    for (logPtr = srvPtr->config->files; logPtr; logPtr = logPtr->nextPtr) {
        if (logPtr->map.flags[facility][severity]) {
            break;
        }
    }
    Ns_MutexUnlock(&srvPtr->config->mutex);
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
        ns_sockclose(logPtr->fd);
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
        ns_sockclose(logPtr->fd);
        logPtr->fd = -1;
        Tcl_DStringFree(&logPtr->buffer);
        Ns_Log(Notice, "nssyslog: closed '%s'", logPtr->file);
    }

    return status;
}

static void SyslogFree(SyslogFile * logPtr)
{
    if (logPtr) {
        ns_sockclose(logPtr->fd);
        Tcl_DStringFree(&logPtr->buffer);
        ns_free(logPtr->name);
        ns_free(logPtr->file);
        ns_free(logPtr->rollfmt);
        ns_free(logPtr);
    }
}

static int SyslogFlush(SyslogFile * logPtr, Tcl_DString * dsPtr)
{
    int len = dsPtr->length;
    char *buf = dsPtr->string;

    if (len > 0) {
        if (logPtr->fd > 0 && write(logPtr->fd, buf, (size_t)len) != len) {
            Ns_Log(Error, "nssyslog: %s: logging disabled: write() failed: '%s'", logPtr->name, strerror(errno));
            ns_sockclose(logPtr->fd);
            logPtr->fd = -1;
        }
        Tcl_DStringSetLength(dsPtr, 0);
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
            Tcl_DString ds;
            struct tm *ptm = ns_localtime(&now);

            strftime(timeBuf, sizeof(timeBuf) - 1, logPtr->rollfmt, ptm);
            Tcl_DStringInit(&ds);
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
            Tcl_DStringFree(&ds);
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
    SyslogServer *srvPtr = (SyslogServer *) arg;
    SyslogFile *logPtr;

    for (logPtr = srvPtr->config->files; logPtr; logPtr = logPtr->nextPtr) {
        SyslogCallback(SyslogClose, logPtr, "close");
    }
}

static void SyslogRollCallback(void *arg)
{
    SyslogServer *srvPtr = (SyslogServer *) arg;
    SyslogFile *logPtr;

    for (logPtr = srvPtr->config->files; logPtr; logPtr = logPtr->nextPtr) {
        SyslogCallback(SyslogRoll, logPtr, "roll");
    }
}

static void SyslogWrite(SyslogFile * logPtr, char *line, char *timestamp)
{
    if (timestamp) {
        Tcl_DStringAppend(&logPtr->buffer, timestamp, TCL_INDEX_NONE);
        Tcl_DStringAppend(&logPtr->buffer, " ", TCL_INDEX_NONE);
    }
    if (line) {
        Tcl_DStringAppend(&logPtr->buffer, line, TCL_INDEX_NONE);
        Tcl_DStringAppend(&logPtr->buffer, "\n", TCL_INDEX_NONE);
        logPtr->curlines++;
    }
    if (!line || logPtr->curlines > logPtr->maxlines) {
        SyslogFlush(logPtr, &logPtr->buffer);
        logPtr->writtenlines += logPtr->curlines;
        logPtr->curlines = 0;
    }
}

static SyslogTls *SyslogGetTls(void)
{
    SyslogTls *log = Ns_TlsGet(&logTls);

    if (log == NULL) {
        log = ns_calloc(1, sizeof(SyslogTls));
        log->sock = -1;
        log->severity = LOG_INFO;
        log->facility = LOG_USER;
        log->tag = ns_strdup("nsd");
        log->path = ns_strdup("/dev/log");
        log->port = 514;
        Ns_TlsSet(&logTls, log);
    }
    return log;
}

static void SyslogFreeTls(void *arg)
{
    SyslogTls *log = (SyslogTls*)arg;

    ns_free(log->tag);
    ns_free((char *)log->path);
    ns_free(log);
}

static void SyslogInit(const char *path, const char *tag, int options, int facility)
{
    SyslogTls *log = SyslogGetTls();
    int changed = 0;

    if (path != NULL && strcmp(path, log->path)) {
        ns_free((char *)log->path);
        log->path = ns_strdup(path);
        changed = 1;
    }
    if (tag != NULL && strcmp(tag, log->tag)) {
        ns_free(log->tag);
        log->tag = ns_strdup(tag);
        changed = 1;
    }
    if (options && options != log->options) {
        log->options = options;
        changed = 1;
    }
    if (facility != -1 && facility != log->facility) {
        log->facility = facility;
        changed = 1;
    }
    if (changed) {
        SyslogShutdown();
    }

    if (log->sock == -1) {
        if (Ns_PathIsAbsolute(log->path)) {
            struct sockaddr un;

            un.sa_family = AF_UNIX;
            strncpy(un.sa_data, log->path, sizeof(un.sa_data));
            if (log->options & LOG_NDELAY) {
                log->sock = socket(AF_UNIX, SOCK_DGRAM, 0);
            }
            if (log->sock != -1 && !log->connected &&
                connect(log->sock, &un, (socklen_t)(sizeof(un.sa_family)+strlen(un.sa_data))) != -1) {
                log->connected = 1;
            }
        } else {
            struct NS_SOCKADDR_STORAGE sa;
            struct sockaddr           *saPtr = (struct sockaddr *)&sa;
            char *ptr = strchr(log->path, ':');

            if (ptr != NULL) {
                *ptr++ = 0;
                log->port = (unsigned short)strtol(ptr, NULL, 10);
            }
            if (Ns_GetSockAddr(saPtr, log->path, log->port) == NS_OK) {
                if (log->options & LOG_NDELAY) {
                    log->sock = socket(AF_INET, SOCK_DGRAM, 0);
                }
            }
            if (log->sock != -1 && !log->connected &&
                (connect(log->sock, saPtr, Ns_SockaddrGetSockLen(saPtr)) != -1)) {
                log->connected = 1;
            }
        }
    }
}

static void SyslogShutdown(void)
{
    SyslogTls *log = SyslogGetTls();

    if (log->sock != -1) {
        ns_sockclose(log->sock);
    }
    log->sock = -1;
    log->connected = 0;
}

static void SyslogSend(int severity, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    SyslogSendV(severity, fmt, ap);
    va_end(ap);
}

static void SyslogSendV(int severity, const char *fmt, va_list ap)
{
    SyslogTls *log = SyslogGetTls();
    time_t now = time(NULL);
    int fd, saved_errno = errno;
    size_t cnt;
    char tbuf[2048], fmt2[1024], *p = tbuf, *stdp = NULL, ch, *t1, *t2;

    if (severity == -1) {
        severity = log->severity;
    }
    /* see if we should just throw out this message */
    if ((LOG_MASK(LOG_PRI(severity)) == 0) || (severity &~ (LOG_PRIMASK|LOG_FACMASK))) {
        return;
    }
    if (log->sock < 0 || !log->connected) {
        SyslogInit(NULL, NULL, log->options | LOG_NDELAY, -1);
    }

    /* set default facility if none specified */
    if ((severity & LOG_FACMASK) == 0) {
        severity |= log->facility;
    }

    /* build the message */
    p += sprintf(tbuf, "<%d>%.15s ", severity, ctime(&now) + 4);
    if (log->options & LOG_PERROR) {
        stdp = p;
    }
    if (log->tag) {
        strcpy(p, log->tag);
        for (; *p; ++p);
    }
    if (log->options & LOG_PID) {
        sprintf(p, "[%d]", getpid());
        for (; *p; ++p);
    }
    if (log->tag) {
        *p++ = ':';
        *p++ = ' ';
    }
    /* substitute error message for %m */
    for (t1 = fmt2; (ch = *fmt) != '\0' && t1 < fmt2 + sizeof(fmt2); ++fmt) {
        if (ch == '%' && fmt[1] == 'm') {
            ++fmt;
            for (t2 = strerror(saved_errno); (*t1 = *t2++); ++t1);
        } else {
            *t1++ = ch;
        }
    }
    *t1 = '\0';
    vsprintf(p, fmt2, ap);
    cnt = strlen(tbuf);

    /* output to stderr if requested */
    if (log->options & LOG_PERROR) {
        struct iovec iov[2];
        struct iovec *v = iov;

        v->iov_base = stdp;
        v->iov_len = cnt - (size_t)(stdp - tbuf);
        ++v;
        v->iov_base = "\n";
        v->iov_len = 1;
        writev(2, iov, 2);
    }
    write(log->sock, tbuf, cnt + 1);

    /* output to the console if requested */
    if (log->options & LOG_CONS) {
        if ((fd = open("/dev/console", O_WRONLY|O_NOCTTY, 0)) < 0) {
            return;
        }
        strcat(tbuf, "\r\n");
        cnt += 2;
        p = index(tbuf, '>') + 1;
        write(fd, p, cnt - (size_t)(p - tbuf));
        ns_sockclose(fd);
    }
}

/*
 * Local Variables:
 * mode: c
 * c-basic-offset: 4
 * fill-column: 78
 * indent-tabs-mode: nil
 * End:
 */
