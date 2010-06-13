/*
 * mod_fastcgi.c --
 *
 *      Apache server module for FastCGI.
 *
 *  $Id: mod_fastcgi.c,v 1.156 2004/01/07 01:56:00 robs Exp $
 *
 *  Copyright (c) 1995-1996 Open Market, Inc.
 *
 *  See the file "LICENSE.TERMS" for information on usage and redistribution
 *  of this file, and for a DISCLAIMER OF ALL WARRANTIES.
 *
 *
 *  Patches for Apache-1.1 provided by
 *  Ralf S. Engelschall
 *  <rse@en.muc.de>
 *
 *  Patches for Linux provided by
 *  Scott Langley
 *  <langles@vote-smart.org>
 *
 *  Patches for suexec handling by
 *  Brian Grossman <brian@SoftHome.net> and
 *  Rob Saccoccio <robs@ipass.net>
 */

/*
 * Module design notes.
 *
 * 1. Restart cleanup.
 *
 *   mod_fastcgi spawns several processes: one process manager process
 *   and several application processes.  None of these processes
 *   handle SIGHUP, so they just go away when the Web server performs
 *   a restart (as Apache does every time it starts.)
 *
 *   In order to allow the process manager to properly cleanup the
 *   running fastcgi processes (without being disturbed by Apache),
 *   an intermediate process was introduced.  The diagram is as follows;
 *
 *   ApacheWS --> MiddleProc --> ProcMgr --> FCGI processes
 *
 *   On a restart, ApacheWS sends a SIGKILL to MiddleProc and then
 *   collects it via waitpid().  The ProcMgr periodically checks for
 *   its parent (via getppid()) and if it does not have one, as in
 *   case when MiddleProc has terminated, ProcMgr issues a SIGTERM
 *   to all FCGI processes, waitpid()s on them and then exits, so it
 *   can be collected by init(1).  Doing it any other way (short of
 *   changing Apache API), results either in inconsistent results or
 *   in generation of zombie processes.
 *
 *   XXX: How does Apache 1.2 implement "gentle" restart
 *   that does not disrupt current connections?  How does
 *   gentle restart interact with restart cleanup?
 *
 * 2. Request timeouts.
 *
 *   Earlier versions of this module used ap_soft_timeout() rather than
 *   ap_hard_timeout() and ate FastCGI server output until it completed.
 *   This precluded the FastCGI server from having to implement a
 *   SIGPIPE handler, but meant hanging the application longer than
 *   necessary.  SIGPIPE handler now must be installed in ALL FastCGI
 *   applications.  The handler should abort further processing and go
 *   back into the accept() loop.
 *
 *   Although using ap_soft_timeout() is better than ap_hard_timeout()
 *   we have to be more careful about SIGINT handling and subsequent
 *   processing, so, for now, make it hard.
 */


#include "fcgi.h"


#include <unistd.h>

#if APR_HAVE_CTYPE_H
#include <ctype.h>
#endif

#include "unixd.h"


#ifndef timersub
#define	timersub(a, b, result)                              \
do {                                                  \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;           \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;        \
    if ((result)->tv_usec < 0) {                            \
        --(result)->tv_sec;                                 \
        (result)->tv_usec += 1000000;                       \
    }                                                       \
} while (0)
#endif

/*
 * Global variables
 */

fcgi_server *fcgi_servers = NULL;         /* AppClasses */

u_int dynamicAppConnectTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;

/*
 *----------------------------------------------------------------------
 *
 * init_module
 *
 *      An Apache module initializer, called by the Apache core
 *      after reading the server config.
 *
 *      Start the process manager no matter what, since there may be a
 *      request for dynamic FastCGI applications without any being
 *      configured as static applications.  Also, check for the existence
 *      and create if necessary a subdirectory into which all dynamic
 *      sockets will go.
 *
 *----------------------------------------------------------------------
 */
static apr_status_t init_module(apr_pool_t * p, apr_pool_t * plog,
                          apr_pool_t * tp, server_rec * s)
{
    const char *err;

    /* Register to reset to default values when the config pool is cleaned */
    ap_register_cleanup(p, NULL, fcgi_config_reset_globals, ap_null_cleanup);

    ap_add_version_component(p, "mod_fastcgi/" MOD_FASTCGI_VERSION);

    return APR_SUCCESS;
}


/*
 *----------------------------------------------------------------------
 *
 * get_header_line --
 *
 *      Terminate a line:  scan to the next newline, scan back to the
 *      first non-space character and store a terminating zero.  Return
 *      the next character past the end of the newline.
 *
 *      If the end of the string is reached, ASSERT!
 *
 *      If the FIRST character(s) in the line are '\n' or "\r\n", the
 *      first character is replaced with a NULL and next character
 *      past the newline is returned.  NOTE: this condition supercedes
 *      the processing of RFC-822 continuation lines.
 *
 *      If continuation is set to 'TRUE', then it parses a (possible)
 *      sequence of RFC-822 continuation lines.
 *
 * Results:
 *      As above.
 *
 * Side effects:
 *      Termination byte stored in string.
 *
 *----------------------------------------------------------------------
 */
static char *get_header_line(char *start, int continuation)
{
    char *p = start;
    char *end = start;

    if(p[0] == '\r'  &&  p[1] == '\n') { /* If EOL in 1st 2 chars */
        p++;                              /*   point to \n and stop */
    } else if(*p != '\n') {
        if(continuation) {
            while(*p != '\0') {
                if(*p == '\n' && p[1] != ' ' && p[1] != '\t')
                    break;
                p++;
            }
        } else {
            while(*p != '\0' && *p != '\n') {
                p++;
            }
        }
    }

    ASSERT(*p != '\0');
    end = p;
    end++;

    /*
     * Trim any trailing whitespace.
     */
    while(isspace((unsigned char)p[-1]) && p > start) {
        p--;
    }

    *p = '\0';
    return end;
}


static int set_nonblocking(const fcgi_request * fr, int nonblocking)
{
    int nb_flag = 0;
    int fd_flags = fcntl(fr->fd, F_GETFL, 0);

    if (fd_flags < 0) return -1;

#if defined(O_NONBLOCK)
    nb_flag = O_NONBLOCK;
#elif defined(O_NDELAY)
    nb_flag = O_NDELAY;
#elif defined(FNDELAY)
    nb_flag = FNDELAY;
#else
#error "TODO - don't read from app until all data from client is posted."
#endif

    fd_flags = (nonblocking) ? (fd_flags | nb_flag) : (fd_flags & ~nb_flag);

    return fcntl(fr->fd, F_SETFL, fd_flags);
}


/*******************************************************************************
 * Close the connection to the FastCGI server.  This is normally called by
 * do_work(), but may also be called as in request pool cleanup.
 */
static void close_connection_to_fs(fcgi_request *fr)
{

    if (fr->fd >= 0)
    {
        struct linger linger = {0, 0};
        set_nonblocking(fr, FALSE);
        /* abort the connection entirely */
        setsockopt(fr->fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
        close(fr->fd);
        fr->fd = -1;
    }
}


/*
 *----------------------------------------------------------------------
 *
 * process_headers --
 *
 *      Call with r->parseHeader == SCAN_CGI_READING_HEADERS
 *      and initial script output in fr->header.
 *
 *      If the initial script output does not include the header
 *      terminator ("\r\n\r\n") process_headers returns with no side
 *      effects, to be called again when more script output
 *      has been appended to fr->header.
 *
 *      If the initial script output includes the header terminator,
 *      process_headers parses the headers and determines whether or
 *      not the remaining script output will be sent to the client.
 *      If so, process_headers sends the HTTP response headers to the
 *      client and copies any non-header script output to the output
 *      buffer reqOutbuf.
 *
 * Results:
 *      none.
 *
 * Side effects:
 *      May set r->parseHeader to:
 *        SCAN_CGI_FINISHED -- headers parsed, returning script response
 *        SCAN_CGI_BAD_HEADER -- malformed header from script
 *        SCAN_CGI_INT_REDIRECT -- handler should perform internal redirect
 *        SCAN_CGI_SRV_REDIRECT -- handler should return REDIRECT
 *
 *----------------------------------------------------------------------
 */

static const char *process_headers(request_rec *r, fcgi_request *fr)
{
    char *p, *next, *name, *value;
    int len, flag;
    int hasContentType, hasStatus, hasLocation;

    ASSERT(fr->parseHeader == SCAN_CGI_READING_HEADERS);

    if (fr->header == NULL)
        return NULL;

    /*
     * Do we have the entire header?  Scan for the blank line that
     * terminates the header.
     */
    p = (char *)fr->header->elts;
    len = fr->header->nelts;
    flag = 0;
    while(len-- && flag < 2) {
        switch(*p) {
            case '\r':
                break;
            case '\n':
                flag++;
                break;
            case '\0':
            case '\v':
            case '\f':
                name = "Invalid Character";
                goto BadHeader;
            default:
                flag = 0;
                break;
        }
        p++;
    }

    /* Return (to be called later when we have more data)
     * if we don't have an entire header. */
    if (flag < 2)
        return NULL;

    /*
     * Parse all the headers.
     */
    fr->parseHeader = SCAN_CGI_FINISHED;
    hasContentType = hasStatus = hasLocation = FALSE;
    next = (char *)fr->header->elts;
    for(;;) {
        next = get_header_line(name = next, TRUE);
        if (*name == '\0') {
            break;
        }
        if ((p = strchr(name, ':')) == NULL) {
            goto BadHeader;
        }
        value = p + 1;
        while (p != name && isspace((unsigned char)*(p - 1))) {
            p--;
        }
        if (p == name) {
            goto BadHeader;
        }
        *p = '\0';
        if (strpbrk(name, " \t") != NULL) {
            *p = ' ';
            goto BadHeader;
        }
        while (isspace((unsigned char)*value)) {
            value++;
        }

        if (strcasecmp(name, "Status") == 0) {
            int statusValue = strtol(value, NULL, 10);

            if (hasStatus) {
                goto DuplicateNotAllowed;
            }
            if (statusValue < 0) {
                fr->parseHeader = SCAN_CGI_BAD_HEADER;
                return ap_psprintf(r->pool, "invalid Status '%s'", value);
            }
            hasStatus = TRUE;
            r->status = statusValue;
            r->status_line = ap_pstrdup(r->pool, value);
            continue;
        }

        if (strcasecmp(name, "Content-type") == 0) {
            if (hasContentType) {
                goto DuplicateNotAllowed;
            }
            hasContentType = TRUE;
            r->content_type = ap_pstrdup(r->pool, value);
            continue;
        }

        if (strcasecmp(name, "Location") == 0) {
            if (hasLocation) {
                goto DuplicateNotAllowed;
            }
            hasLocation = TRUE;
            ap_table_set(r->headers_out, "Location", value);
            continue;
        }

        /* If the script wants them merged, it can do it */
        ap_table_add(r->err_headers_out, name, value);
        continue;
    }

    /*
     * Who responds, this handler or Apache?
     */
    if (hasLocation) {
        const char *location = ap_table_get(r->headers_out, "Location");
        /*
         * Based on internal redirect handling in mod_cgi.c...
         *
         * If a script wants to produce its own Redirect
         * body, it now has to explicitly *say* "Status: 302"
         */
        if (r->status == 200) {
            if(location[0] == '/') {
                /*
                 * Location is an relative path.  This handler will
                 * consume all script output, then have Apache perform an
                 * internal redirect.
                 */
                fr->parseHeader = SCAN_CGI_INT_REDIRECT;
                return NULL;
            } else {
                /*
                 * Location is an absolute URL.  If the script didn't
                 * produce a Content-type header, this handler will
                 * consume all script output and then have Apache generate
                 * its standard redirect response.  Otherwise this handler
                 * will transmit the script's response.
                 */
                fr->parseHeader = SCAN_CGI_SRV_REDIRECT;
                return NULL;
            }
        }
    }
    /*
     * We're responding.  Send headers, buffer excess script output.
     */
    ap_send_http_header(r);

    if (r->header_only) {
        /* we've got all we want from the server */
        close_connection_to_fs(fr);
        fr->exitStatusSet = 1;
        fcgi_buf_reset(fr->clientOutputBuffer);
        fcgi_buf_reset(fr->serverOutputBuffer);
        return NULL;
    }

    len = fr->header->nelts - (next - fr->header->elts);

    ASSERT(len >= 0);
    ASSERT(BufferLength(fr->clientOutputBuffer) == 0);

    if (BufferFree(fr->clientOutputBuffer) < len) {
        fr->clientOutputBuffer = fcgi_buf_new(r->pool, len);
    }

    ASSERT(BufferFree(fr->clientOutputBuffer) >= len);

    if (len > 0) {
        int sent;
        sent = fcgi_buf_add_block(fr->clientOutputBuffer, next, len);
        ASSERT(sent == len);
    }

    return NULL;

BadHeader:
    /* Log first line of a multi-line header */
    if ((p = strpbrk(name, "\r\n")) != NULL)
        *p = '\0';
    fr->parseHeader = SCAN_CGI_BAD_HEADER;
    return ap_psprintf(r->pool, "malformed header '%s'", name);

DuplicateNotAllowed:
    fr->parseHeader = SCAN_CGI_BAD_HEADER;
    return ap_psprintf(r->pool, "duplicate header '%s'", name);
}

/*
 * Read from the client filling both the FastCGI server buffer and the
 * client buffer with the hopes of buffering the client data before
 * making the connect() to the FastCGI server.  This prevents slow
 * clients from keeping the FastCGI server in processing longer than is
 * necessary.
 */
static int read_from_client_n_queue(fcgi_request *fr)
{
    char *end;
    int count;
    long int countRead;

    while (BufferFree(fr->clientInputBuffer) > 0 || BufferFree(fr->serverOutputBuffer) > 0) {
        fcgi_protocol_queue_client_buffer(fr);

        if (fr->expectingClientContent <= 0)
            return OK;

        fcgi_buf_get_free_block_info(fr->clientInputBuffer, &end, &count);
        if (count == 0)
            return OK;

        if ((countRead = ap_get_client_block(fr->r, end, count)) < 0)
        {
            /* set the header scan state to done to prevent logging an error
             * - hokey approach - probably should be using a unique value */
            fr->parseHeader = SCAN_CGI_FINISHED;
            return -1;
        }

        if (countRead == 0) {
            fr->expectingClientContent = 0;
        }
        else {
            fcgi_buf_add_update(fr->clientInputBuffer, countRead);
        }
    }
    return OK;
}

static int write_to_client(fcgi_request *fr)
{
    char *begin;
    int count;
    int rv;
    apr_bucket * bkt;
    apr_bucket_brigade * bde;
    apr_bucket_alloc_t * const bkt_alloc = fr->r->connection->bucket_alloc;

    fcgi_buf_get_block_info(fr->clientOutputBuffer, &begin, &count);
    if (count == 0)
        return OK;

    /* If fewer than count bytes are written, an error occured.
     * ap_bwrite() typically forces a flushed write to the client, this
     * effectively results in a block (and short packets) - it should
     * be fixed, but I didn't win much support for the idea on new-httpd.
     * So, without patching Apache, the best way to deal with this is
     * to size the fcgi_bufs to hold all of the script output (within
     * reason) so the script can be released from having to wait around
     * for the transmission to the client to complete. */


    bde = apr_brigade_create(fr->r->pool, bkt_alloc);
    bkt = apr_bucket_transient_create(begin, count, bkt_alloc);
    APR_BRIGADE_INSERT_TAIL(bde, bkt);

    if (fr->fs->flush)
    {
        bkt = apr_bucket_flush_create(bkt_alloc);
        APR_BRIGADE_INSERT_TAIL(bde, bkt);
    }

    rv = ap_pass_brigade(fr->r->output_filters, bde);


    if (rv || fr->r->connection->aborted) {
        ap_log_rerror(FCGI_LOG_INFO_NOERRNO, fr->r,
            "FastCGI: client stopped connection before send body completed");
        return -1;
    }


    fcgi_buf_toss(fr->clientOutputBuffer, count);
    return OK;
}

static void send_request_complete(fcgi_request *fr)
{
    if (fr->completeTime.tv_sec)
    {
        struct timeval qtime, rtime;

        timersub(&fr->queueTime, &fr->startTime, &qtime);
        timersub(&fr->completeTime, &fr->queueTime, &rtime);
    }
}


/*******************************************************************************
 * Connect to the FastCGI server.
 */
static int open_connection_to_fs(fcgi_request *fr)
{
    struct timeval  tval;
    fd_set          write_fds, read_fds;
    int             status;
    request_rec * const r = fr->r;
    pool * const rp = r->pool;
    const char *socket_path = NULL;
    struct sockaddr *socket_addr = NULL;
    int socket_addr_len = 0;
    const char *err = NULL;

    /* Create the connection point */
    socket_addr = fr->fs->socket_addr;
    socket_addr_len = fr->fs->socket_addr_len;

    /* Create the socket */
    fr->fd = socket(socket_addr->sa_family, SOCK_STREAM, 0);

    if (fr->fd < 0) {
        ap_log_rerror(FCGI_LOG_ERR_ERRNO, r,
            "FastCGI: failed to connect to server \"%s\": "
            "socket() failed", fr->fs_path);
        return FCGI_FAILED;
    }

    if (fr->fd >= FD_SETSIZE) {
        ap_log_rerror(FCGI_LOG_ERR, r,
            "FastCGI: failed to connect to server \"%s\": "
            "socket file descriptor (%u) is larger than "
            "FD_SETSIZE (%u), you probably need to rebuild Apache with a "
            "larger FD_SETSIZE", fr->fs_path, fr->fd, FD_SETSIZE);
        return FCGI_FAILED;
    }

    /* If appConnectTimeout is non-zero, setup do a non-blocking connect */
    if (fr->fs->appConnectTimeout) {
        set_nonblocking(fr, TRUE);
    }

    /* Connect */
    if (connect(fr->fd, (struct sockaddr *)socket_addr, socket_addr_len) == 0)
        goto ConnectionComplete;

    if (errno != EINPROGRESS) {
        ap_log_rerror(FCGI_LOG_ERR, r,
            "FastCGI: failed to connect to server \"%s\": "
            "connect() failed", fr->fs_path);
        return FCGI_FAILED;
    }


    /* The connect() is non-blocking */

    errno = 0;

    tval.tv_sec = fr->fs->appConnectTimeout;
    tval.tv_usec = 0;
    FD_ZERO(&write_fds);
    FD_SET(fr->fd, &write_fds);
    read_fds = write_fds;

    status = ap_select((fr->fd+1), &read_fds, &write_fds, NULL, &tval);

    if (status == 0) {
        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
            "FastCGI: failed to connect to server \"%s\": "
            "connect() timed out (appConnTimeout=%dsec)",
            fr->fs_path, dynamicAppConnectTimeout);
        return FCGI_FAILED;
    }

    if (status < 0) {
        ap_log_rerror(FCGI_LOG_ERR_ERRNO, r,
            "FastCGI: failed to connect to server \"%s\": "
            "select() failed", fr->fs_path);
        return FCGI_FAILED;
    }

    if (FD_ISSET(fr->fd, &write_fds) || FD_ISSET(fr->fd, &read_fds)) {
        int error = 0;
        apr_socklen_t len = sizeof(error);

        if (getsockopt(fr->fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0) {
            /* Solaris pending error */
            ap_log_rerror(FCGI_LOG_ERR_ERRNO, r,
                "FastCGI: failed to connect to server \"%s\": "
                "select() failed (Solaris pending error)", fr->fs_path);
            return FCGI_FAILED;
        }

        if (error != 0) {
            /* Berkeley-derived pending error */
            errno = error;
            ap_log_rerror(FCGI_LOG_ERR_ERRNO, r,
                "FastCGI: failed to connect to server \"%s\": "
                "select() failed (pending error)", fr->fs_path);
            return FCGI_FAILED;
        }
    }
    else {
        ap_log_rerror(FCGI_LOG_ERR_ERRNO, r,
            "FastCGI: failed to connect to server \"%s\": "
            "select() error - THIS CAN'T HAPPEN!", fr->fs_path);
        return FCGI_FAILED;
    }

ConnectionComplete:
    /* Return to blocking mode if it was set up */
    if (fr->fs->appConnectTimeout) {
        set_nonblocking(fr, FALSE);
    }

#ifdef TCP_NODELAY
    if (socket_addr->sa_family == AF_INET) {
        /* We shouldn't be sending small packets and there's no application
         * level ack of the data we send, so disable Nagle */
        int set = 1;
        setsockopt(fr->fd, IPPROTO_TCP, TCP_NODELAY, (char *)&set, sizeof(set));
    }
#endif

    return FCGI_OK;
}

static void sink_client_data(fcgi_request *fr)
{
    char *base;
    int size;

    fcgi_buf_reset(fr->clientInputBuffer);
    fcgi_buf_get_free_block_info(fr->clientInputBuffer, &base, &size);
	while (ap_get_client_block(fr->r, base, size) > 0);
}

static apr_status_t cleanup(void *data)
{
    fcgi_request * const fr = (fcgi_request *) data;

    if (fr == NULL) return APR_SUCCESS;

    /* its more than likely already run, but... */
    close_connection_to_fs(fr);

    send_request_complete(fr);

    if (fr->fs_stderr_len) {
        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
            "FastCGI: server \"%s\" stderr: %s", fr->fs_path, fr->fs_stderr);
    }

    return APR_SUCCESS;
}

static int socket_io(fcgi_request * const fr)
{
    enum
    {
        STATE_SOCKET_NONE,
        STATE_ENV_SEND,
        STATE_CLIENT_RECV,
        STATE_SERVER_SEND,
        STATE_SERVER_RECV,
        STATE_CLIENT_SEND,
        STATE_ERROR,
        STATE_CLIENT_ERROR
    }
    state = STATE_ENV_SEND;

    request_rec * const r = fr->r;

    struct timeval timeout;
    fd_set read_set;
    fd_set write_set;
    int nfds = 0;
    int select_status = 1;
    int idle_timeout;
    int rv;
    int client_send = FALSE;
    int client_recv = FALSE;
    pool *rp = r->pool;
    int is_connected = 0;

    client_recv = (fr->expectingClientContent != 0);

    idle_timeout = fr->fs->idle_timeout;

    for (;;)
    {
        FD_ZERO(&read_set);
        FD_ZERO(&write_set);

        switch (state)
        {
        case STATE_ENV_SEND:

            if (fcgi_protocol_queue_env(r, fr) == 0)
            {
                goto SERVER_SEND;
            }

            state = STATE_CLIENT_RECV;

            /* fall through */

        case STATE_CLIENT_RECV:

            if (read_from_client_n_queue(fr))
            {
                state = STATE_CLIENT_ERROR;
                break;
            }

            if (fr->eofSent)
            {
                state = STATE_SERVER_SEND;
            }

            /* fall through */

SERVER_SEND:

        case STATE_SERVER_SEND:

            if (! is_connected)
            {
                if (open_connection_to_fs(fr) != FCGI_OK)
                {
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                set_nonblocking(fr, TRUE);
                is_connected = 1;
                nfds = fr->fd + 1;
            }

            if (BufferLength(fr->serverOutputBuffer))
            {
                FD_SET(fr->fd, &write_set);
            }
            else
            {
                ASSERT(fr->eofSent);
                state = STATE_SERVER_RECV;
            }

            /* fall through */

        case STATE_SERVER_RECV:

            FD_SET(fr->fd, &read_set);

            /* fall through */

        case STATE_CLIENT_SEND:

            if (client_send || ! BufferFree(fr->clientOutputBuffer))
            {
                if (write_to_client(fr))
                {
                    state = STATE_CLIENT_ERROR;
                    break;
                }

                client_send = 0;
            }

            break;

        case STATE_ERROR:
        case STATE_CLIENT_ERROR:

            break;

        default:

            ASSERT(0);
        }

        if (state == STATE_CLIENT_ERROR || state == STATE_ERROR)
        {
            break;
        }

        /* setup the io timeout */

        if (BufferLength(fr->clientOutputBuffer))
        {
            /* don't let client data sit too long, it might be a push */
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;
        }
        else
        {
            timeout.tv_sec = idle_timeout;
            timeout.tv_usec = 0;
        }

        /* wait on the socket */
        select_status = ap_select(nfds, &read_set, &write_set, NULL, &timeout);

        if (select_status < 0)
        {
            ap_log_rerror(FCGI_LOG_ERR_ERRNO, r, "FastCGI: comm with server "
                "\"%s\" aborted: select() failed", fr->fs_path);
            state = STATE_ERROR;
            break;
        }

        if (select_status == 0)
        {
            /* select() timeout */

            if (BufferLength(fr->clientOutputBuffer))
            {
                client_send = TRUE;
            }
            else
            {
                ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r, "FastCGI: comm with "
                    "server \"%s\" aborted: idle timeout (%d sec)",
                    fr->fs_path, idle_timeout);
                state = STATE_ERROR;
            }
        }

        if (FD_ISSET(fr->fd, &write_set))
        {
            /* send to the server */

            rv = fcgi_buf_socket_send(fr->serverOutputBuffer, fr->fd);

            if (rv < 0)
            {
                ap_log_rerror(FCGI_LOG_ERR, r, "FastCGI: comm with server "
                    "\"%s\" aborted: write failed", fr->fs_path);
                state = STATE_ERROR;
                break;
            }
        }

        if (FD_ISSET(fr->fd, &read_set))
        {
            /* recv from the server */

            rv = fcgi_buf_socket_recv(fr->serverInputBuffer, fr->fd);

            if (rv < 0)
            {
                ap_log_rerror(FCGI_LOG_ERR, r, "FastCGI: comm with server "
                    "\"%s\" aborted: read failed", fr->fs_path);
                state = STATE_ERROR;
                break;
            }

            if (rv == 0)
            {
                fr->keepReadingFromFcgiApp = FALSE;
                state = STATE_CLIENT_SEND;
                break;
            }
        }

        if (fcgi_protocol_dequeue(rp, fr))
        {
            state = STATE_ERROR;
            break;
        }

        if (fr->parseHeader == SCAN_CGI_READING_HEADERS)
        {
            const char * err = process_headers(r, fr);
            if (err)
            {
                ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
                    "FastCGI: comm with server \"%s\" aborted: "
                    "error parsing headers: %s", fr->fs_path, err);
                state = STATE_ERROR;
                break;
            }
        }

        if (fr->exitStatusSet)
        {
            fr->keepReadingFromFcgiApp = FALSE;
            state = STATE_CLIENT_SEND;
            break;
        }
    }

    return (state == STATE_ERROR);
}


/*----------------------------------------------------------------------
 * This is the core routine for moving data between the FastCGI
 * application and the Web server's client.
 */
static int do_work(request_rec * const r, fcgi_request * const fr)
{
    int rv;
    pool *rp = r->pool;

    fcgi_protocol_queue_begin_request(fr);

    rv = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
    if (rv != OK)
    {
        return rv;
    }

    fr->expectingClientContent = ap_should_client_block(r);

    ap_register_cleanup(rp, (void *)fr, cleanup, ap_null_cleanup);

    {
        rv = socket_io(fr);
    }

    /* comm with the server is done */
    close_connection_to_fs(fr);

    sink_client_data(fr);

    while (rv == 0 && (BufferLength(fr->serverInputBuffer) || BufferLength(fr->clientOutputBuffer)))
    {
        if (fcgi_protocol_dequeue(rp, fr))
        {
            rv = HTTP_INTERNAL_SERVER_ERROR;
        }

        if (fr->parseHeader == SCAN_CGI_READING_HEADERS)
        {
            const char * err = process_headers(r, fr);
            if (err)
            {
                ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
                    "FastCGI: comm with server \"%s\" aborted: "
                    "error parsing headers: %s", fr->fs_path, err);
                rv = HTTP_INTERNAL_SERVER_ERROR;
            }
        }

        if (write_to_client(fr))
        {
            break;
        }
    }

    switch (fr->parseHeader)
    {
    case SCAN_CGI_FINISHED:

        /* RUSSIAN_APACHE requires rflush() over bflush() */
        ap_rflush(r);

        /* fall through */

    case SCAN_CGI_INT_REDIRECT:
    case SCAN_CGI_SRV_REDIRECT:

        break;

    case SCAN_CGI_READING_HEADERS:

        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r, "FastCGI: incomplete headers "
            "(%d bytes) received from server \"%s\"", fr->header->nelts, fr->fs_path);

        /* fall through */

    case SCAN_CGI_BAD_HEADER:

        rv = HTTP_INTERNAL_SERVER_ERROR;
        break;

    default:

        ASSERT(0);
        rv = HTTP_INTERNAL_SERVER_ERROR;
    }

    return rv;
}

static int
create_fcgi_request(request_rec * const r,
                    const char * const path,
                    fcgi_request ** const frP)
{
    const char *fs_path;
    pool * const p = r->pool;
    fcgi_server *fs;
    fcgi_request * const fr = (fcgi_request *)ap_pcalloc(p, sizeof(fcgi_request));

    fs_path = path ? path : r->filename;

    fs = fcgi_util_fs_get_by_id(fs_path);

    if (fs == NULL)
    {
        ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
            "FastCGI: invalid server \"%s\": %s", fs_path, err);
        return HTTP_FORBIDDEN;
    }

    fr->nph = (strncmp(strrchr(fs_path, '/'), "/nph-", 5) == 0) ||
		    (fs && fs->nph);

    fr->serverInputBuffer = fcgi_buf_new(p, SERVER_BUFSIZE);
    fr->serverOutputBuffer = fcgi_buf_new(p, SERVER_BUFSIZE);
    fr->clientInputBuffer = fcgi_buf_new(p, SERVER_BUFSIZE);
    fr->clientOutputBuffer = fcgi_buf_new(p, SERVER_BUFSIZE);
    fr->erBufPtr = fcgi_buf_new(p, sizeof(FCGI_EndRequestBody) + 1);
    fr->gotHeader = FALSE;
    fr->fs_stderr = NULL;
    fr->r = r;
    fr->readingEndRequestBody = FALSE;
    fr->exitStatus = 0;
    fr->exitStatusSet = FALSE;
    fr->requestId = 1; /* anything but zero is OK here */
    fr->eofSent = FALSE;
    fr->expectingClientContent = FALSE;
    fr->keepReadingFromFcgiApp = TRUE;
    fr->fs = fs;
    fr->fs_path = fs_path;
    fr->authHeaders = ap_make_table(p, 10);
    fr->fd = -1;

    if (fr->nph) {
	struct ap_filter_t *cur;

	fr->parseHeader = SCAN_CGI_FINISHED;
	fr->header = ap_make_array(p, 1, 1);

	/* get rid of all filters up through protocol...  since we
	 * haven't parsed off the headers, there is no way they can
	 * work
	 */

	cur = r->proto_output_filters;
	while (cur && cur->frec->ftype < AP_FTYPE_CONNECTION) {
	    cur = cur->next;
	}
	r->output_filters = r->proto_output_filters = cur;
    } else {
	fr->parseHeader = SCAN_CGI_READING_HEADERS;
	fr->header = ap_make_array(p, 1, 1);
    }

    fr->user = "-";
    fr->group = "-";

    *frP = fr;

    return OK;
}

/*
 *----------------------------------------------------------------------
 *
 * handler --
 *
 *      This routine gets called for a request that corresponds to
 *      a FastCGI connection.  It performs the request synchronously.
 *
 * Results:
 *      Final status of request: OK or NOT_FOUND or HTTP_INTERNAL_SERVER_ERROR.
 *
 * Side effects:
 *      Request performed.
 *
 *----------------------------------------------------------------------
 */

/* Stolen from mod_cgi.c..
 * KLUDGE --- for back-combatibility, we don't have to check ExecCGI
 * in ScriptAliased directories, which means we need to know if this
 * request came through ScriptAlias or not... so the Alias module
 * leaves a note for us.
 */
static int apache_is_scriptaliased(request_rec *r)
{
    const char *t = ap_table_get(r->notes, "alias-forced-type");
    return t && (!strcasecmp(t, "cgi-script"));
}

/* If a script wants to produce its own Redirect body, it now
 * has to explicitly *say* "Status: 302".  If it wants to use
 * Apache redirects say "Status: 200".  See process_headers().
 */
static int post_process_for_redirects(request_rec * const r,
    const fcgi_request * const fr)
{
    switch(fr->parseHeader) {
        case SCAN_CGI_INT_REDIRECT:

            /* @@@ There are still differences between the handling in
             * mod_cgi and mod_fastcgi.  This needs to be revisited.
             */
            /* We already read the message body (if any), so don't allow
             * the redirected request to think it has one.  We can ignore
             * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
             */
            r->method = "GET";
            r->method_number = M_GET;
            ap_table_unset(r->headers_in, "Content-length");

            ap_internal_redirect_handler(ap_table_get(r->headers_out, "Location"), r);
            return OK;

        case SCAN_CGI_SRV_REDIRECT:
            return HTTP_MOVED_TEMPORARILY;

        default:
            return OK;
    }
}

/******************************************************************************
 * Process fastcgi-script requests.  Based on mod_cgi::cgi_handler().
 */
static int content_handler(request_rec *r)
{
    fcgi_request *fr = NULL;
    int ret;

    if (strcmp(r->handler, FASTCGI_HANDLER_NAME))
        return DECLINED;

    /* Setup a new FastCGI request */
    ret = create_fcgi_request(r, NULL, &fr);
    if (ret)
    {
        return ret;
    }

    /* Process the fastcgi-script request */
    if ((ret = do_work(r, fr)) != OK)
        return ret;

    /* Special case redirects */
    ret = post_process_for_redirects(r, fr);

    return ret;
}


static int
fixups(request_rec * r)
{
    if (fcgi_util_fs_get_by_id(r->filename))
    {
        r->handler = FASTCGI_HANDLER_NAME;
        return OK;
    }

    return DECLINED;
}


static const command_rec fastcgi_cmds[] =
{
    AP_INIT_RAW_ARGS("FastCgiExternalServer", fcgi_config_new_external_server, NULL, RSRC_CONF, NULL),

    { NULL }
};


static void register_hooks(apr_pool_t * p)
{
    /* ap_hook_pre_config(x_pre_config, NULL, NULL, APR_HOOK_MIDDLE); */
    ap_hook_post_config(init_module, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(content_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(fixups, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA fastcgi_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,                           /* per-directory config creator */
    NULL,                           /* dir config merger */
    NULL,                           /* server config creator */
    NULL,                           /* server config merger */
    fastcgi_cmds,                   /* command table */
    register_hooks,                 /* set up other request processing hooks */
};
