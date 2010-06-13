/*
 * $Id: fcgi.h,v 1.45 2004/01/07 01:56:00 robs Exp $
 */

#ifndef FCGI_H
#define FCGI_H

#if defined(DEBUG) && ! defined(NDEBUG)
#define ASSERT(a) ap_assert(a)
#else
#define ASSERT(a) ((void) 0)
#endif


/* Apache header files */
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_log.h"
#include "util_script.h"
#include "util_md5.h"


#include <sys/stat.h>
#include "ap_compat.h"
#include "apr_strings.h"


#ifndef S_ISDIR
#define S_ISDIR(m)      (((m)&(S_IFMT)) == (S_IFDIR))
#endif

#if (defined(HAVE_WRITEV) && !HAVE_WRITEV && !defined(NO_WRITEV))
#define NO_WRITEV
#endif


#ifndef NO_WRITEV
#include <sys/uio.h>
#endif

#include <sys/un.h>

/* FastCGI header files */
#include "mod_fastcgi.h"
/* @@@ This should go away when fcgi_protocol is re-written */
#include "fcgi_protocol.h"

typedef struct {
    int size;               /* size of entire buffer */
    int length;             /* number of bytes in current buffer */
    char *begin;            /* begining of valid data */
    char *end;              /* end of valid data */
    char data[1];           /* buffer data */
} Buffer;

/*
 * fcgi_server holds info for each AppClass specified in this
 * Web server's configuration.
 */
typedef struct _FastCgiServerInfo {
    int flush;
    char *fs_path;                  /* pathname of executable */
    apr_array_header_t *pass_headers;     /* names of headers to pass in the env */
    u_int idle_timeout;             /* fs idle secs allowed before aborting */
    u_int appConnectTimeout;        /* timeout (sec) for connect() requests */
    u_int numProcesses;             /* max allowed processes of this class,
                                     * or for dynamic apps, the number of
                                     * processes actually running */
    time_t startTime;               /* the time the application was started */
    time_t restartTime;             /* most recent time when the process
                                     * manager started a process in this
                                     * class. */
    u_int numFailures;              /* num restarts due to exit failure */
    int bad;                        /* is [not] having start problems */
    struct sockaddr *socket_addr;   /* Socket Address of FCGI app server class */
    int socket_addr_len;            /* Length of socket */
    const char *socket_path;        /* Name used to create a socket */
    const char *host;               /* Hostname for externally managed
                                     * FastCGI application processes */
    unsigned short port;            /* Port number either for externally
                                     * managed FastCGI applications or for
                                     * server managed FastCGI applications,
                                     * where server became application mngr. */
    struct _FcgiProcessInfo *procs; /* Pointer to array of
                                     * processes belonging to this class. */
    int keepConnection;             /* = 1 = maintain connection to app. */
    uid_t uid;                      /* uid this app should run as (suexec) */
    gid_t gid;                      /* gid this app should run as (suexec) */
    /* Dynamic FastCGI apps configuration parameters */
    u_long totalConnTime;           /* microseconds spent by the web server
                                     * waiting while fastcgi app performs
                                     * request processing since the last
                                     * dynamicUpdateInterval */
    u_long smoothConnTime;          /* exponentially decayed values of the
                                     * connection times. */
    u_long totalQueueTime;          /* microseconds spent by the web server
                                     * waiting to connect to the fastcgi app
                                     * since the last dynamicUpdateInterval. */
    struct _FastCgiServerInfo *next;
} fcgi_server;


/*
 * fcgi_request holds the state of a particular FastCGI request.
 */
typedef struct {
    int fd;                         /* connection to FastCGI server */
    int gotHeader;                  /* TRUE if reading content bytes */
    unsigned char packetType;       /* type of packet */
    int dataLen;                    /* length of data bytes */
    int paddingLen;                 /* record padding after content */
    fcgi_server *fs;                /* FastCGI server info */
    const char *fs_path;         /* fcgi_server path */
    Buffer *serverInputBuffer;   /* input buffer from FastCgi server */
    Buffer *serverOutputBuffer;  /* output buffer to FastCgi server */
    Buffer *clientInputBuffer;   /* client input buffer */
    Buffer *clientOutputBuffer;  /* client output buffer */
    int expectingClientContent;     /* >0 => more content, <=0 => no more */
    apr_array_header_t *header;
    char *fs_stderr;
    int fs_stderr_len;
    int parseHeader;                /* TRUE iff parsing response headers */
    request_rec *r;
    int readingEndRequestBody;
    FCGI_EndRequestBody endRequestBody;
    Buffer *erBufPtr;
    int exitStatus;
    int exitStatusSet;
    unsigned int requestId;
    int eofSent;
    struct timeval startTime;       /* dynamic app's connect() attempt start time */
    struct timeval queueTime;       /* dynamic app's connect() complete time */
    struct timeval completeTime;    /* dynamic app's connection close() time */
    int keepReadingFromFcgiApp;     /* still more to read from fcgi app? */
} fcgi_request;

/* Values of parseHeader field */
#define SCAN_CGI_READING_HEADERS 1
#define SCAN_CGI_FINISHED        0
#define SCAN_CGI_BAD_HEADER     -1
#define SCAN_CGI_INT_REDIRECT   -2
#define SCAN_CGI_SRV_REDIRECT   -3

#define FCGI_OK     0
#define FCGI_FAILED 1

#define FCGI_LOG_EMERG          __FILE__,__LINE__,APLOG_EMERG,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_ALERT          __FILE__,__LINE__,APLOG_ALERT,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_CRIT           __FILE__,__LINE__,APLOG_CRIT,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_ERR            __FILE__,__LINE__,APLOG_ERR,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_WARN           __FILE__,__LINE__,APLOG_WARNING,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_NOTICE         __FILE__,__LINE__,APLOG_NOTICE,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_INFO           __FILE__,__LINE__,APLOG_INFO,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_DEBUG          __FILE__,__LINE__,APLOG_DEBUG,APR_FROM_OS_ERROR(errno)

#define FCGI_LOG_EMERG_ERRNO    __FILE__,__LINE__,APLOG_EMERG,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_ALERT_ERRNO    __FILE__,__LINE__,APLOG_ALERT,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_CRIT_ERRNO     __FILE__,__LINE__,APLOG_CRIT,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_ERR_ERRNO      __FILE__,__LINE__,APLOG_ERR,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_WARN_ERRNO     __FILE__,__LINE__,APLOG_WARNING,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_NOTICE_ERRNO   __FILE__,__LINE__,APLOG_NOTICE,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_INFO_ERRNO     __FILE__,__LINE__,APLOG_INFO,APR_FROM_OS_ERROR(errno)
#define FCGI_LOG_DEBUG_ERRNO    __FILE__,__LINE__,APLOG_DEBUG,APR_FROM_OS_ERROR(errno)

#define FCGI_LOG_EMERG_NOERRNO    __FILE__,__LINE__,APLOG_EMERG,0
#define FCGI_LOG_ALERT_NOERRNO    __FILE__,__LINE__,APLOG_ALERT,0
#define FCGI_LOG_CRIT_NOERRNO     __FILE__,__LINE__,APLOG_CRIT,0
#define FCGI_LOG_ERR_NOERRNO      __FILE__,__LINE__,APLOG_ERR,0
#define FCGI_LOG_WARN_NOERRNO     __FILE__,__LINE__,APLOG_WARNING,0
#define FCGI_LOG_NOTICE_NOERRNO   __FILE__,__LINE__,APLOG_NOTICE,0
#define FCGI_LOG_INFO_NOERRNO     __FILE__,__LINE__,APLOG_INFO,0
#define FCGI_LOG_DEBUG_NOERRNO    __FILE__,__LINE__,APLOG_DEBUG,0

/*
 * Holds the status of the sending of the environment.
 * A quick hack to dump the static vars for the NT port.
 */
typedef struct {
    enum { PREP, HEADER, NAME, VALUE } pass;
    char **envp;
    int headerLen, nameLen, valueLen, totalLen;
    char *equalPtr;
    unsigned char headerBuff[8];
} env_status;

/*
 * fcgi_config.c
 */
const char *fcgi_config_new_external_server(cmd_parms *cmd, void *dummy, const char *arg);
apr_status_t fcgi_config_reset_globals(void * dummy);

/*
 * fcgi_protocol.c
 */
void fcgi_protocol_queue_begin_request(fcgi_request *fr);
void fcgi_protocol_queue_client_buffer(fcgi_request *fr);
int fcgi_protocol_queue_env(request_rec *r, fcgi_request *fr);
int fcgi_protocol_dequeue(apr_pool_t *p, fcgi_request *fr);

/*
 * fcgi_buf.c
 */
#define BufferLength(b)     ((b)->length)
#define BufferFree(b)       ((b)->size - (b)->length)

void fcgi_buf_reset(Buffer *bufPtr);
Buffer *fcgi_buf_new(apr_pool_t *p, int size);

typedef int SOCKET;

int fcgi_buf_socket_recv(Buffer *b, SOCKET socket);
int fcgi_buf_socket_send(Buffer *b, SOCKET socket);

void fcgi_buf_added(Buffer * const b, const unsigned int len);
void fcgi_buf_removed(Buffer * const b, unsigned int len);
void fcgi_buf_get_block_info(Buffer *bufPtr, char **beginPtr, int *countPtr);
void fcgi_buf_toss(Buffer *bufPtr, int count);
void fcgi_buf_get_free_block_info(Buffer *bufPtr, char **endPtr, int *countPtr);
void fcgi_buf_add_update(Buffer *bufPtr, int count);
int fcgi_buf_add_block(Buffer *bufPtr, char *data, int datalen);
int fcgi_buf_add_string(Buffer *bufPtr, char *str);
int fcgi_buf_get_to_block(Buffer *bufPtr, char *data, int datalen);
void fcgi_buf_get_to_buf(Buffer *toPtr, Buffer *fromPtr, int len);
void fcgi_buf_get_to_array(Buffer *buf, apr_array_header_t *arr, int len);

/*
 * fcgi_util.c
 */

const char *fcgi_util_socket_make_domain_addr(apr_pool_t *p, struct sockaddr_un **socket_addr,
    int *socket_addr_len, const char *socket_path);
const char *fcgi_util_socket_make_inet_addr(apr_pool_t *p, struct sockaddr_in **socket_addr,
    int *socket_addr_len, const char *host, unsigned short port);
fcgi_server *fcgi_util_fs_get_by_id(const char *ePath);
fcgi_server *fcgi_util_fs_new(apr_pool_t *p);
void fcgi_util_fs_add(fcgi_server *s);

/*
 * Globals
 */

extern fcgi_server *fcgi_servers;

extern module MODULE_VAR_EXPORT fastcgi_module;

#endif  /* FCGI_H */
