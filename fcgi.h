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
	int size;     /* size of entire buffer */
	int length;   /* number of bytes in current buffer */
	char *begin;  /* begining of valid data */
	char *end;    /* end of valid data */
	char data[1]; /* buffer data */
} fcgi_buf_t;

/*
 * fcgi_request holds the state of a particular FastCGI request.
 */
typedef struct {
	const char *server;                /* server name as given in httpd.conf */
	fastcgi_pass_cfg *cfg;             /* pointer to per-dir config for convenience */

	struct sockaddr *socket_addr;      /* socket address of the FastCGI application */
	int socket_addr_len;               /* length of socket struct */
	int socket_fd;                     /* socket descriptor to FastCGI server */

	int gotHeader;                     /* TRUE if reading content bytes */
	unsigned char packetType;          /* type of packet */
	int dataLen;                       /* length of data bytes */
	int paddingLen;                    /* record padding after content */

	fcgi_buf_t *server_input_buffer;   /* input buffer from FastCgi server */
	fcgi_buf_t *server_output_buffer;  /* output buffer to FastCgi server */
	fcgi_buf_t *client_input_buffer;   /* client input buffer */
	fcgi_buf_t *client_output_buffer;  /* client output buffer */

	int expectingClientContent;     /* >0 => more content, <=0 => no more */
	apr_array_header_t *header;
	char *stderr;
	int stderr_len;
	int parseHeader;                /* TRUE iff parsing response headers */
	request_rec *r;
	int readingEndRequestBody;
	FCGI_EndRequestBody endRequestBody;
	fcgi_buf_t *erBufPtr;
	int exitStatus;
	int exitStatusSet;
	unsigned int requestId;
	int eofSent;
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
 * fcgi_protocol.c
 */
void fcgi_protocol_queue_begin_request(fcgi_request *fr);
void fcgi_protocol_queue_client_buffer(fcgi_request *fr);
int fcgi_protocol_queue_env(request_rec *r, fcgi_request *fr);
int fcgi_protocol_dequeue(apr_pool_t *p, fcgi_request *fr);

/*
 * fcgi_buf.c
 */
#define fcgi_buf_length(b)     ((b)->length)
#define fcgi_buf_free(b)       ((b)->size - (b)->length)

void fcgi_buf_reset(fcgi_buf_t *bufPtr);
fcgi_buf_t *fcgi_buf_new(apr_pool_t *p, int size);

int fcgi_buf_socket_recv(fcgi_buf_t *b, int fd);
int fcgi_buf_socket_send(fcgi_buf_t *b, int fd);

void fcgi_buf_added(fcgi_buf_t * const b, const unsigned int len);
void fcgi_buf_removed(fcgi_buf_t * const b, unsigned int len);
void fcgi_buf_get_block_info(fcgi_buf_t *bufPtr, char **beginPtr, int *countPtr);
void fcgi_buf_toss(fcgi_buf_t *bufPtr, int count);
void fcgi_buf_get_free_block_info(fcgi_buf_t *bufPtr, char **endPtr, int *countPtr);
void fcgi_buf_add_update(fcgi_buf_t *bufPtr, int count);
int fcgi_buf_add_block(fcgi_buf_t *bufPtr, char *data, int datalen);
int fcgi_buf_add_string(fcgi_buf_t *bufPtr, char *str);
int fcgi_buf_get_to_block(fcgi_buf_t *bufPtr, char *data, int datalen);
void fcgi_buf_get_to_buf(fcgi_buf_t *toPtr, fcgi_buf_t *fromPtr, int len);
void fcgi_buf_get_to_array(fcgi_buf_t *buf, apr_array_header_t *arr, int len);

/*
 * fcgi_util.c
 */

const char *fcgi_util_socket_make_addr(apr_pool_t *p, fcgi_request *fr, const char *server);

/*
 * Globals
 */

extern module MODULE_VAR_EXPORT fastcgi_module;

#endif  /* FCGI_H */
