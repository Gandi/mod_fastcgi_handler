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

#include <unistd.h>

#if APR_HAVE_CTYPE_H
#include <ctype.h>
#endif

#include "fcgi.h"

#include "unixd.h"

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
static
apr_status_t init_module(apr_pool_t * p, apr_pool_t * plog,
		apr_pool_t * tp, server_rec * s)
{
	ap_add_version_component(p, "mod_fastcgi/" MOD_FASTCGI_VERSION);
	return APR_SUCCESS;
}

/*
 *----------------------------------------------------------------------
 *
 * get_header_line
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
static
char *get_header_line(char *start)
{
	char *p = start;
	char *end = start;

	if (p[0] == '\r' && p[1] == '\n') { /* If EOL in 1st 2 chars */
		p++;                            /* point to \n and stop */
	}

	else if (*p != '\n') {
		while (*p != '\0') {
			if (*p == '\n' && p[1] != ' ' && p[1] != '\t')
				break;
			p++;
		}
	}

	ASSERT(*p != '\0');
	end = p;
	end++;

	/* trim any trailing whitespace. */
	while (isspace((unsigned char)p[-1]) && p > start) {
		p--;
	}

	*p = '\0';
	return end;
}

static
int set_nonblocking(const fcgi_request *fr, int nonblocking)
{
	int nb_flag = 0;
	int fd_flags = fcntl(fr->socket_fd, F_GETFL, 0);

	if (fd_flags < 0)
		return -1;

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

	return fcntl(fr->socket_fd, F_SETFL, fd_flags);
}

/*******************************************************************************
 * Close the connection to the FastCGI server.  This is normally called by
 * do_work(), but may also be called as in request pool cleanup.
 */
static
void close_connection_to_fs(fcgi_request *fr)
{
	if (fr->socket_fd >= 0) {
		struct linger linger = {0, 0};
		set_nonblocking(fr, FALSE);
		/* abort the connection entirely */
		setsockopt(fr->socket_fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
		close(fr->socket_fd);
		fr->socket_fd = -1;
	}
}

/*
 *----------------------------------------------------------------------
 *
 * process_headers
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
static
const char *process_headers(request_rec *r, fcgi_request *fr)
{
	ASSERT(fr->parseHeader == SCAN_CGI_READING_HEADERS);

	if (fr->header == NULL)
		return NULL;

	/* do we have the entire header? scan for the blank line that terminates the header. */
	char *p = (char *)fr->header->elts;
	int len = fr->header->nelts;
	int flag = 0;
	char *key, *value;

	while (len-- && flag < 2) {
		switch(*p) {
			case '\r':
				break;
			case '\n':
				flag++;
				break;
			case '\0':
			case '\v':
			case '\f':
				key = "Invalid Character";
				goto BadHeader;
			default:
				flag = 0;
				break;
		}
		p++;
	}

	/* return (to be called later when we have more data) if we don't have an
	 * entire header. */
	if (flag < 2)
		return NULL;

	/* parse all the headers. */
	fr->parseHeader = SCAN_CGI_FINISHED;

	int hasContentType, hasStatus, hasLocation;
	hasContentType = hasStatus = hasLocation = FALSE;

	char *next = (char *)fr->header->elts;

	while(1) {
		key = next;
		next = get_header_line(next);

		if (*key == '\0') {
			break;
		}

		if ((p = strchr(key, ':')) == NULL) {
			goto BadHeader;
		}

		value = p + 1;
		while (p != key && isspace((unsigned char)*(p - 1))) { /* XXX: always false since p-1 is always ':' ? */
			p--;
		}

		if (p == key) {
			goto BadHeader;
		}

		*p = '\0';
		if (strpbrk(key, " \t") != NULL) {
			*p = ' ';
			goto BadHeader;
		}

		while (isspace((unsigned char)*value)) {
			value++;
		}

		if (strcasecmp(key, "Status") == 0) {
			int statusValue = strtol(value, NULL, 10);

			if (hasStatus) {
				goto DuplicateNotAllowed;
			}

			if (statusValue < 0) {
				fr->parseHeader = SCAN_CGI_BAD_HEADER;
				return apr_psprintf(r->pool, "invalid Status '%s'", value);
			}

			hasStatus = TRUE;
			r->status = statusValue;
			r->status_line = apr_pstrdup(r->pool, value);
		}

		else if (strcasecmp(key, "Content-type") == 0) {
			if (hasContentType) {
				goto DuplicateNotAllowed;
			}

			hasContentType = TRUE;
			r->content_type = apr_pstrdup(r->pool, value);
		}

		else if (strcasecmp(key, "Location") == 0) {
			if (hasLocation) {
				goto DuplicateNotAllowed;
			}
			hasLocation = TRUE;
			apr_table_set(r->headers_out, "Location", value);
		}

		else {
			/* If the script wants them merged, it can do it */
			apr_table_add(r->err_headers_out, key, value);
		}
	}

	/*
	 * Who responds, this handler or Apache?
	 */
	if (hasLocation) {
		const char *location = apr_table_get(r->headers_out, "Location");
		/*
		 * Based on internal redirect handling in mod_cgi.c...
		 *
		 * If a script wants to produce its own Redirect
		 * body, it now has to explicitly *say* "Status: 302"
		 */
		if (r->status == 200) {
			if (location[0] == '/') {
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
		fcgi_buf_reset(fr->client_output_buffer);
		fcgi_buf_reset(fr->server_output_buffer);
		return NULL;
	}

	len = fr->header->nelts - (next - fr->header->elts);

	ASSERT(len >= 0);
	ASSERT(fcgi_buf_length(fr->client_output_buffer) == 0);

	if (fcgi_buf_free(fr->client_output_buffer) < len) {
		fr->client_output_buffer = fcgi_buf_new(r->pool, len);
	}

	ASSERT(fcgi_buf_free(fr->client_output_buffer) >= len);

	if (len > 0) {
		int sent;
		sent = fcgi_buf_add_block(fr->client_output_buffer, next, len);
		ASSERT(sent == len);
	}

	return NULL;

BadHeader:
	/* Log first line of a multi-line header */
	if ((p = strpbrk(key, "\r\n")) != NULL)
		*p = '\0';
	fr->parseHeader = SCAN_CGI_BAD_HEADER;
	return apr_psprintf(r->pool, "malformed header '%s'", key);

DuplicateNotAllowed:
	fr->parseHeader = SCAN_CGI_BAD_HEADER;
	return apr_psprintf(r->pool, "duplicate header '%s'", key);
}

/*
 * Read from the client filling both the FastCGI server buffer and the
 * client buffer with the hopes of buffering the client data before
 * making the connect() to the FastCGI server.  This prevents slow
 * clients from keeping the FastCGI server in processing longer than is
 * necessary.
 */
static
int read_from_client_n_queue(fcgi_request *fr)
{
	char *end;
	int count;
	long int countRead;

	while (fcgi_buf_free(fr->client_input_buffer) > 0 || fcgi_buf_free(fr->server_output_buffer) > 0) {
		fcgi_protocol_queue_client_buffer(fr);

		if (fr->should_client_block <= 0)
			return OK;

		fcgi_buf_get_free_block_info(fr->client_input_buffer, &end, &count);
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
			fr->should_client_block = 0;
		}
		else {
			fcgi_buf_add_update(fr->client_input_buffer, countRead);
		}
	}
	return OK;
}

static
int write_to_client(fcgi_request *fr)
{
	char *begin;
	int count;
	int rv;
	apr_bucket * bkt;
	apr_bucket_brigade * bde;
	apr_bucket_alloc_t * const bkt_alloc = fr->r->connection->bucket_alloc;

	fcgi_buf_get_block_info(fr->client_output_buffer, &begin, &count);
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

	rv = ap_pass_brigade(fr->r->output_filters, bde);

	if (rv || fr->r->connection->aborted) {
		ap_log_rerror(FCGI_LOG_INFO_NOERRNO, fr->r,
				"FastCGI: client stopped connection before send body completed");
		return -1;
	}

	fcgi_buf_toss(fr->client_output_buffer, count);
	return OK;
}

static
int open_connection_to_fs(fcgi_request *fr)
{
	/* create the socket */
	fr->socket_fd = socket(fr->socket_addr->sa_family, SOCK_STREAM, 0);

	if (fr->socket_fd < 0) {
		ap_log_rerror(FCGI_LOG_ERR_ERRNO, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"socket() failed", fr->server);
		return FCGI_FAILED;
	}

	if (fr->socket_fd >= FD_SETSIZE) {
		ap_log_rerror(FCGI_LOG_ERR, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"socket file descriptor (%u) is larger than "
				"FD_SETSIZE (%u), you probably need to rebuild Apache with a "
				"larger FD_SETSIZE", fr->server, fr->socket_fd, FD_SETSIZE);
		return FCGI_FAILED;
	}

	/* connect the socket */
	if (connect(fr->socket_fd, (struct sockaddr *)fr->socket_addr, fr->socket_addr_len) == 0)
		goto connection_complete;

	if (errno != EINPROGRESS) {
		ap_log_rerror(FCGI_LOG_ERR, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"connect() failed", fr->server);
		return FCGI_FAILED;
	}

	/* the connect() is non-blocking */
	errno = 0;

	struct timeval tval;
	tval.tv_sec = 0;
	tval.tv_usec = 0;

	fd_set write_fds, read_fds;
	FD_ZERO(&write_fds);
	FD_SET(fr->socket_fd, &write_fds);
	read_fds = write_fds;

	int status = select((fr->socket_fd+1), &read_fds, &write_fds, NULL, &tval);

	if (status == 0) {
		ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"connect() timed out (appConnTimeout=%dsec)",
				fr->server, 0);
		return FCGI_FAILED;
	}

	if (status < 0) {
		ap_log_rerror(FCGI_LOG_ERR_ERRNO, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"select() failed", fr->server);
		return FCGI_FAILED;
	}

	if (FD_ISSET(fr->socket_fd, &write_fds) || FD_ISSET(fr->socket_fd, &read_fds)) {
		int error = 0;
		apr_socklen_t len = sizeof(error);

		if (getsockopt(fr->socket_fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) < 0) {
			/* Solaris pending error */
			ap_log_rerror(FCGI_LOG_ERR_ERRNO, r,
					"FastCGI: failed to connect to server \"%s\": "
					"select() failed (Solaris pending error)", fr->server);
			return FCGI_FAILED;
		}

		if (error != 0) {
			/* Berkeley-derived pending error */
			errno = error;
			ap_log_rerror(FCGI_LOG_ERR_ERRNO, r,
					"FastCGI: failed to connect to server \"%s\": "
					"select() failed (pending error)", fr->server);
			return FCGI_FAILED;
		}
	} else {
		ap_log_rerror(FCGI_LOG_ERR_ERRNO, r,
				"FastCGI: failed to connect to server \"%s\": "
				"select() error - THIS CAN'T HAPPEN!", fr->server);
		return FCGI_FAILED;
	}

connection_complete:
#ifdef TCP_NODELAY
	if (fr->socket_addr->sa_family == AF_INET) {
		/* We shouldn't be sending small packets and there's no application
		 * level ack of the data we send, so disable Nagle */
		int set = 1;
		setsockopt(fr->socket_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&set, sizeof(set));
	}
#endif

	return FCGI_OK;
}

static
int socket_io(fcgi_request * const fr)
{
	static enum {
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

	int rv;
	int client_send = 0;
	int idle_timeout = fr->cfg->idle_timeout;

	if (idle_timeout < 0)
		idle_timeout = FCGI_DEFAULT_IDLE_TIMEOUT;

	while (1) {
		int nfds = 0;
		fd_set read_set, write_set;

		FD_ZERO(&read_set);
		FD_ZERO(&write_set);

		switch (state) {
			case STATE_ENV_SEND:
				if (fcgi_protocol_queue_env(r, fr) == 0) {
					goto SERVER_SEND;
				}

				state = STATE_CLIENT_RECV;

				/* fall through */

			case STATE_CLIENT_RECV:
				if (read_from_client_n_queue(fr)) {
					state = STATE_CLIENT_ERROR;
					break;
				}

				if (fr->eofSent) {
					state = STATE_SERVER_SEND;
				}

				/* fall through */

SERVER_SEND:

			case STATE_SERVER_SEND:
				if (fr->socket_fd == -1) {
					if (open_connection_to_fs(fr) != FCGI_OK) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}

					set_nonblocking(fr, TRUE);
					nfds = fr->socket_fd + 1;
				}

				if (fcgi_buf_length(fr->server_output_buffer)) {
					FD_SET(fr->socket_fd, &write_set);
				} else {
					ASSERT(fr->eofSent);
					state = STATE_SERVER_RECV;
				}

				/* fall through */

			case STATE_SERVER_RECV:
				FD_SET(fr->socket_fd, &read_set);
				/* fall through */

			case STATE_CLIENT_SEND:
				if (client_send || !fcgi_buf_free(fr->client_output_buffer)) {
					if (write_to_client(fr)) {
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

		if (state == STATE_CLIENT_ERROR || state == STATE_ERROR) {
			break;
		}

		/* setup the io timeout */
		struct timeval timeout;

		if (fcgi_buf_length(fr->client_output_buffer)) {
			/* don't let client data sit too long, it might be a push */
			timeout.tv_sec = 0;
			timeout.tv_usec = 100000;
		} else {
			timeout.tv_sec = idle_timeout;
			timeout.tv_usec = 0;
		}

		/* wait on the socket */
		int select_status = select(nfds, &read_set, &write_set, NULL, &timeout);

		if (select_status < 0) {
			ap_log_rerror(FCGI_LOG_ERR_ERRNO, r, "FastCGI: comm with server "
					"\"%s\" aborted: select() failed", fr->server);
			state = STATE_ERROR;
			break;
		}

		if (select_status == 0) {
			/* select() timeout */

			if (fcgi_buf_length(fr->client_output_buffer)) {
				client_send = 1;
			} else {
				ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r, "FastCGI: comm with "
						"server \"%s\" aborted: idle timeout (%d sec)",
						fr->server, idle_timeout);
				state = STATE_ERROR;
			}
		}

		if (FD_ISSET(fr->socket_fd, &write_set)) {
			/* send to the server */
			rv = fcgi_buf_socket_send(fr->server_output_buffer, fr->socket_fd);

			if (rv < 0) {
				ap_log_rerror(FCGI_LOG_ERR, r, "FastCGI: comm with server "
						"\"%s\" aborted: write failed", fr->server);
				state = STATE_ERROR;
				break;
			}
		}

		if (FD_ISSET(fr->socket_fd, &read_set)) {
			/* recv from the server */
			rv = fcgi_buf_socket_recv(fr->server_input_buffer, fr->socket_fd);

			if (rv < 0) {
				ap_log_rerror(FCGI_LOG_ERR, r, "FastCGI: comm with server "
						"\"%s\" aborted: read failed", fr->server);
				state = STATE_ERROR;
				break;
			}

			if (rv == 0) {
				state = STATE_CLIENT_SEND;
				break;
			}
		}

		if (fcgi_protocol_dequeue(r->pool, fr)) {
			state = STATE_ERROR;
			break;
		}

		if (fr->parseHeader == SCAN_CGI_READING_HEADERS) {
			const char *err = process_headers(r, fr);
			if (err) {
				ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
						"FastCGI: comm with server \"%s\" aborted: "
						"error parsing headers: %s", fr->server, err);
				state = STATE_ERROR;
				break;
			}
		}

		if (fr->exitStatusSet) {
			state = STATE_CLIENT_SEND;
			break;
		}
	}

	return (state == STATE_ERROR);
}


static
apr_status_t cleanup(void *data)
{
	fcgi_request *fr = data;

	if (fr != NULL) {
		close_connection_to_fs(fr);

		if (fr->stderr_len) {
			ap_log_rerror(FCGI_LOG_ERR_NOERRNO, fr->r,
					"FastCGI: server \"%s\" stderr: %s", fr->server, fr->stderr);
		}
	}

	return APR_SUCCESS;
}

/*----------------------------------------------------------------------
 * This is the core routine for moving data between the FastCGI
 * application and the Web server's client.
 */
static
int do_work(request_rec *r, fcgi_request *fr)
{
	int rv;
	apr_pool_t *rp = r->pool;

	fcgi_protocol_queue_begin_request(fr);

	/* setup proper handling of chunked content */
	rv = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR);
	if (rv != OK) {
		return rv;
	}

	fr->should_client_block = ap_should_client_block(r);

	/* make sure our pool is clean when destroyed */
	apr_pool_cleanup_register(rp, (void *)fr, cleanup, apr_pool_cleanup_null);

	/* do socket I/O */
	rv = socket_io(fr);

	/* communication with the server is done */
	close_connection_to_fs(fr);

	/* read & destroy all remaining client data */
	char *base;
	int size;

	fcgi_buf_reset(fr->client_input_buffer);
	fcgi_buf_get_free_block_info(fr->client_input_buffer, &base, &size);

	while (ap_get_client_block(fr->r, base, size) > 0);

	/* send response to client */
	while (rv == 0 && (fcgi_buf_length(fr->server_input_buffer) || fcgi_buf_length(fr->client_output_buffer))) {
		if (fcgi_protocol_dequeue(rp, fr)) {
			rv = HTTP_INTERNAL_SERVER_ERROR;
		}

		if (fr->parseHeader == SCAN_CGI_READING_HEADERS) {
			const char *err = process_headers(r, fr);
			if (err) {
				ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r,
						"FastCGI: comm with server \"%s\" aborted: "
						"error parsing headers: %s", fr->server, err);
				rv = HTTP_INTERNAL_SERVER_ERROR;
			}
		}

		if (write_to_client(fr)) {
			break;
		}
	}

	/* check if headers have been processed correctly */
	switch (fr->parseHeader) {
		case SCAN_CGI_FINISHED:
		case SCAN_CGI_INT_REDIRECT:
		case SCAN_CGI_SRV_REDIRECT:
			break;

		case SCAN_CGI_READING_HEADERS:
			ap_log_rerror(FCGI_LOG_ERR_NOERRNO, r, "FastCGI: incomplete headers "
					"(%d bytes) received from server \"%s\"", fr->header->nelts, fr->server);

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

static
int create_fcgi_request(request_rec *r, fcgi_request **frP)
{
	apr_pool_t *p = r->pool;
	fcgi_request *fr = apr_pcalloc(p, sizeof(fcgi_request));

	/* setup server socket struct */
	fr->server = apr_pstrdup(p, r->handler + 5);

	const char *err = fcgi_util_socket_make_addr(p, fr);

	if (err) {
		ap_log_rerror(FCGI_LOG_NOERRNO, r,
				"fastcgi_pass: invalid server address: '%s'", fr->server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* keep a pointer to cfg and r for convenience */
	fr->cfg = ap_get_module_config(r->per_dir_config, &fastcgi_pass_module);
	fr->r = r;

	/* setup FastCGI buffers */
	fr->server_input_buffer = fcgi_buf_new(p, SERVER_BUFSIZE);
	fr->server_output_buffer = fcgi_buf_new(p, SERVER_BUFSIZE);
	fr->client_input_buffer = fcgi_buf_new(p, SERVER_BUFSIZE);
	fr->client_output_buffer = fcgi_buf_new(p, SERVER_BUFSIZE);
	fr->erBufPtr = fcgi_buf_new(p, sizeof(FCGI_EndRequestBody) + 1);

	fr->gotHeader = FALSE;
	fr->stderr = NULL;
	fr->readingEndRequestBody = FALSE;
	fr->exitStatus = 0;
	fr->exitStatusSet = FALSE;
	fr->requestId = 1; /* anything but zero is OK here */
	fr->eofSent = FALSE;
	fr->should_client_block = 0;
	fr->socket_fd = -1;
	fr->parseHeader = SCAN_CGI_READING_HEADERS;
	fr->header = apr_array_make(p, 1, 1);

	*frP = fr;

	return OK;
}

/* If a script wants to produce its own Redirect body, it now
 * has to explicitly *say* "Status: 302".  If it wants to use
 * Apache redirects say "Status: 200".  See process_headers().
 */
static
int post_process_for_redirects(request_rec * const r,
		const fcgi_request * const fr)
{
	switch (fr->parseHeader) {
		case SCAN_CGI_INT_REDIRECT:
			r->method = apr_pstrdup(r->pool, "GET");
			r->method_number = M_GET;

			/* We already read the message body (if any), so don't allow
			 * the redirected request to think it has one.  We can ignore
			 * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
			 */
			apr_table_unset(r->headers_in, "Content-length");

			const char *location = apr_table_get(r->headers_out, "Location");
			ap_internal_redirect_handler(location, r);

			return OK;

		case SCAN_CGI_SRV_REDIRECT:
			return HTTP_MOVED_TEMPORARILY;

		default:
			return OK;
	}
}

static
int fastcgi_pass_handler(request_rec *r)
{
	if (strncmp(r->handler, "fcgi:", 5))
		return DECLINED;

	fcgi_request *fr = NULL;
	int ret;

	/* create a new FastCGI request object */
	if ((ret = create_fcgi_request(r, &fr))) {
		return ret;
	}

	/* process the FastCGI request */
	if ((ret = do_work(r, fr)) != OK)
		return ret;

	/* special case for redirects */
	return post_process_for_redirects(r, fr);
}

static
void *fastcgi_pass_create_dir_config(apr_pool_t *p, char *dir)
{
	fastcgi_pass_cfg *cfg = apr_pcalloc(p, sizeof(fastcgi_pass_cfg));

	cfg->idle_timeout = -1;
	cfg->headers = apr_array_make(p, 1, sizeof(char *));

	return cfg;
}

static
void *fastcgi_pass_merge_dir_config(apr_pool_t *p, void *parent, void *current)
{
	fastcgi_pass_cfg *parent_cfg = (fastcgi_pass_cfg *) parent;
	fastcgi_pass_cfg *current_cfg = (fastcgi_pass_cfg *) current;
	fastcgi_pass_cfg *cfg = apr_pcalloc(p, sizeof(fastcgi_pass_cfg));

	cfg->idle_timeout = current->idle_timeout == -1 ?
			parent->idle_timeout : current->idle_timeout;

	cfg->headers = apr_array_append(p, parent->headers, current->headers);

	return cfg;
}

static
const char *fastcgi_pass_cmd_pass_header(cmd_parms *cmd, void *mconf,
		const char *arg)
{
	fastcgi_pass_cfg *cfg = (fastcgi_pass_cfg *) mconf;
	*(const char **)apr_array_push(cfg->headers) = arg;
	return NULL;
}

static
const command_rec fastcgi_pass_cmds[] =
{
	AP_INIT_ITERATE("FastCgiPassHeader", fastcgi_pass_cmd_pass_header,
			OR_FILEINFO, "a list of headers to pass to the FastCGI application."),

	{ NULL }
};

static
void fastcgi_pass_register_hooks(apr_pool_t * p)
{
	ap_hook_post_config(init_module, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_handler(fastcgi_pass_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA fastcgi_pass_module =
{
	STANDARD20_MODULE_STUFF,
	fastcgi_pass_create_dir_config,
	fastcgi_pass_merge_dir_config,
	NULL,
	NULL,
	fastcgi_pass_cmds,
	fastcgi_pass_register_hooks,
};
