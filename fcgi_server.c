#include <unistd.h>
#include <sys/socket.h>

#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_config.h>
#include <http_request.h>
#include <http_log.h>
#include <util_filter.h>
#include <util_script.h>

#include "fcgi_body.h"
#include "fcgi_record.h"
#include "fcgi_server.h"

struct memory {
	char *ptr;
	uint32_t length;
};

static
ssize_t socket_send(fcgi_request_t *fr, void *buf, size_t len)
{
	ssize_t bytes_sent;

	do {
		bytes_sent = write(fr->socket_fd, buf, len);
	} while (bytes_sent == -1 && errno == EINTR);

	return bytes_sent;
}

static
ssize_t socket_recv(fcgi_request_t *fr, void *buf, size_t len)
{
	ssize_t bytes_read;

	do {
		bytes_read = recv(fr->socket_fd, buf, len, MSG_WAITALL);
	} while (bytes_read == -1 && errno == EINTR);

	if (bytes_read == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, fr->r,
				"FastCGI: failed to read from backend server");
	}

	return bytes_read;
}

static
void socket_sink(fcgi_request_t *fr)
{
	ssize_t bytes_read;
	char buf[1024];

	do {
		do {
			bytes_read = recv(fr->socket_fd, buf, 1024, MSG_WAITALL);
		} while (bytes_read == -1 && errno == EINTR);
	} while (bytes_read > 0);
}

void fcgi_server_disconnect(fcgi_request_t *fr)
{
	if (fr->socket_fd >= 0) {
		struct linger linger = {0, 0};
		setsockopt(fr->socket_fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
		close(fr->socket_fd);
		fr->socket_fd = -1;
	}
}

int fcgi_server_connect(fcgi_request_t *fr)
{
	/* create the socket */
	fr->socket_fd = socket(fr->socket_addr->sa_family, SOCK_STREAM, 0);

	if (fr->socket_fd < 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"socket() failed", fr->server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (fr->socket_fd >= FD_SETSIZE) {
		fcgi_server_disconnect(fr);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"socket file descriptor (%u) is larger than "
				"FD_SETSIZE (%u), you probably need to rebuild Apache with a "
				"larger FD_SETSIZE", fr->server, fr->socket_fd, FD_SETSIZE);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* connect the socket */
	if (connect(fr->socket_fd, (struct sockaddr *)fr->socket_addr, fr->socket_addr_len) == -1) {
		fcgi_server_disconnect(fr);
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"connect() failed", fr->server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* TODO: non-blocking socket */

#ifdef TCP_NODELAY
	if (fr->socket_addr->sa_family == AF_INET) {
		/* We shouldn't be sending small packets and there's no application
		 * level ack of the data we send, so disable Nagle */
		int set = 1;
		setsockopt(fr->socket_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&set, sizeof(set));
	}
#endif

	return OK;
}

int fcgi_server_send_begin_record(fcgi_request_t *fr, uint16_t request_id,
		void *record_buffer)
{
	/* build record into current buffer */
	fcgi_record_begin_request_build((fcgi_record_begin_request_t)record_buffer,
			request_id, FCGI_RESPONDER, 0); /* TODO: FCGI_KEEP_CONN */

	/* send data to the FastCGI server */
	ssize_t bytes_sent = socket_send(fr, record_buffer,
			sizeof(struct fcgi_record_begin_request));

	if (bytes_sent == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, fr->r,
				"FastCGI: failed to write to backend server (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

int fcgi_server_send_params_record(fcgi_request_t *fr, uint16_t request_id,
		void *record_buffer)
{
	/* add all environment variables to r->subprocess_env */
	ap_add_common_vars(fr->r);
	ap_add_cgi_vars(fr->r);

	/* build FCGI_PARAMS record based on apache environement */
	apr_pool_t *p = fr->r->pool;
	char **env = ap_create_environment(p, fr->r->subprocess_env);

	/* TODO: what if params > 64K? */
	apr_status_t status;
	status = fcgi_record_params_build((fcgi_header_t)record_buffer, request_id, env);

	if (status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: failed to build params record (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	apr_size_t len = fcgi_header_content_length_get((fcgi_header_t)record_buffer) +
		fcgi_header_padding_length_get((fcgi_header_t)record_buffer) +
		FCGI_HEADER_LEN;

	/* send data to the FastCGI server */
	ssize_t bytes_sent = socket_send(fr, record_buffer, len);

	if (bytes_sent == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, fr->r,
				"FastCGI: failed to write to backend server (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* build and send VOID FCGI_PARAMS record */
	status = fcgi_record_params_build((fcgi_header_t)record_buffer, request_id, NULL);

	if (status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: failed to build params record (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* send data to the FastCGI server */
	bytes_sent = socket_send(fr, record_buffer, FCGI_HEADER_LEN);

	if (bytes_sent == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, fr->r,
				"FastCGI: failed to write to backend server (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

int fcgi_server_send_stdin_record(fcgi_request_t *fr, uint16_t request_id,
		void *record_buffer)
{
	apr_bucket_brigade *bb = apr_brigade_create(fr->r->pool,
			fr->r->connection->bucket_alloc);

	int seen_eos = 0, server_stopped_reading = 0;
	apr_status_t rv;

	do {
		apr_bucket *bucket;

		rv = ap_get_brigade(fr->r->input_filters, bb, AP_MODE_READBYTES,
				APR_BLOCK_READ, HUGE_STRING_LEN);

		if (rv != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, fr->r,
					"FastCGI: error reading request entity data");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		for (bucket = APR_BRIGADE_FIRST(bb);
				bucket != APR_BRIGADE_SENTINEL(bb);
				bucket = APR_BUCKET_NEXT(bucket))
		{
			const char *data;
			apr_size_t len;

			if (APR_BUCKET_IS_EOS(bucket)) {
				seen_eos = 1;
				break;
			}

			/* We can't do much with this. */
			if (APR_BUCKET_IS_FLUSH(bucket)) {
				continue;
			}

			/* if the FastCGI server stopped reading, we still must read to EOS. */
			if (server_stopped_reading) {
				continue;
			}

			/* read from client */
			apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);

			/* build FCGI_STDIN record
			 *
			 * A bucket can hold up to 8000 bytes. Since FastCGI packets can be
			 * up to 64K we don't have to worry about to much stdin data being
			 * read in one single iteration.
			 */
			int padding_length = fcgi_record_build((fcgi_header_t)record_buffer,
					request_id, FCGI_STDIN, len);

			/* send header data to the FastCGI server */
			ssize_t bytes_sent = socket_send(fr,
					record_buffer, FCGI_HEADER_LEN);

			if (bytes_sent == -1) {
				server_stopped_reading = 1;
				continue;
			}

			/* send stdin data to the FastCGI server */
			bytes_sent = socket_send(fr, (char *)data, len);

			if (bytes_sent == -1) {
				server_stopped_reading = 1;
				continue;
			}

			/* send padding to the FastCGI server */
			bytes_sent = socket_send(fr,
					((char *)record_buffer) + FCGI_HEADER_LEN + len,
					padding_length);

			if (bytes_sent == -1) {
				server_stopped_reading = 1;
				continue;
			}
		}

		apr_brigade_cleanup(bb);
	} while (!seen_eos);

	apr_brigade_cleanup(bb);

	/* build void FCGI_STDIN record */
	fcgi_header_set((fcgi_header_t)record_buffer, FCGI_VERSION_1, FCGI_STDIN, request_id, 0, 0);

	/* send data to the FastCGI server */
	ssize_t bytes_sent = socket_send(fr, record_buffer, FCGI_HEADER_LEN);

	if (bytes_sent == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, errno, fr->r,
				"FastCGI: failed to write to backend server (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

static
int fcgi_server_recv_check_header(fcgi_request_t *fr,
		uint16_t request_id, fcgi_header_t header, uint8_t *type,
		uint32_t *payload_len, uint16_t *padding_len)
{
	/* get record version */
	uint8_t version = fcgi_header_version_get(header);
	if (version != FCGI_VERSION_1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: unsupported FastCGI version from backend server (id:%u, version=%u)",
				request_id, version);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* get record type */
	*type = fcgi_header_type_get(header);
	if (*type != FCGI_END_REQUEST && *type != FCGI_STDOUT && *type != FCGI_STDERR) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: invalid record type from backend server (id=%u, type=%u)",
				request_id, *type);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* get request id */
	uint16_t received_request_id = fcgi_header_request_id_get(header);
	if (received_request_id != request_id) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: unexpected request_id from backend server (id=%u, received_id=%u)",
				request_id, received_request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* get content and padding length of the record from header */
	*padding_len = fcgi_header_padding_length_get(header);
	*payload_len = fcgi_header_content_length_get(header) +
		*padding_len;

	return OK;
}

static
int fcgi_server_send_stdout_data(fcgi_request_t *fr, uint16_t request_id,
		void *data, uint16_t payload_len)
{
	apr_bucket_alloc_t *bkt_alloc = fr->r->connection->bucket_alloc;
	apr_bucket_brigade *bde = apr_brigade_create(fr->r->pool, bkt_alloc);
	apr_bucket *bkt = apr_bucket_transient_create(data, payload_len, bkt_alloc);
	APR_BRIGADE_INSERT_TAIL(bde, bkt);

	int rv = ap_pass_brigade(fr->r->output_filters, bde);

	if (rv || fr->r->connection->aborted) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, fr->r,
				"FastCGI: client stopped connection before send body completed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

static int
getsfunc_MEMORY(char *buffer, int len, void *arg)
{
	struct memory *m = (struct memory *) arg;
	const char *c;
	uint32_t line_len;

	if (m->length == 0) {
		buffer[0] = '\0';
		return 0;
	}
	c = memchr(m->ptr, '\n', m->length);
	if (c) {
		c++; // we include \n in the line we return
		line_len = c - m->ptr;
	} else {
		line_len = m->length;
	}
	if (line_len >= len) {
		// >= and -1 because we need room for the final \0
		line_len = len - 1;
	}
	memcpy(buffer, m->ptr, line_len);
	buffer[line_len] = '\0';
	m->ptr += line_len;
	m->length -= line_len;
	return line_len;
}

static int
ap_scan_script_header_err_memory(request_rec *r,
				 char *buffer,
				 char **new,
				 char *ptr,
				 uint32_t length)
{
	struct memory m = {.ptr = ptr, .length = length};
	int res;

	res = ap_scan_script_header_err_core_ex(r, buffer, getsfunc_MEMORY,
						(void *) &m, APLOG_MODULE_INDEX);
	if (new)
		*new = m.ptr;
	return res;
}

/* copied from mod_cgi.c and slightly modified
 * to work with fcgi_record types */
static
int fcgi_server_parse_headers(fcgi_request_t *fr, uint16_t request_id,
		char **data, uint32_t payload_len)
{
	request_rec *r = fr->r;
	int ret;

	if ((ret = ap_scan_script_header_err_memory(r, NULL, data,
						    *data, payload_len))) {
		/*
		 * ret could be HTTP_NOT_MODIFIED in the case that the CGI script
		 * does not set an explicit status and ap_meets_conditions, which
		 * is called by ap_scan_script_header_err_brigade, detects that
		 * the conditions of the requests are met and the response is
		 * not modified.
		 * In this case set r->status and return OK in order to prevent
		 * running through the error processing stack as this would
		 * break with mod_cache, if the conditions had been set by
		 * mod_cache itself to validate a stale entity.
		 * BTW: We circumvent the error processing stack anyway if the
		 * CGI script set an explicit status code (whatever it is) and
		 * the only possible values for ret here are:
		 *
		 * HTTP_NOT_MODIFIED          (set by ap_meets_conditions)
		 * HTTP_PRECONDITION_FAILED   (set by ap_meets_conditions)
		 * HTTP_INTERNAL_SERVER_ERROR (if something went wrong during the
		 * processing of the response of the CGI script, e.g broken headers
		 * or a crashed CGI process).
		 */
		if (ret == HTTP_NOT_MODIFIED) {
			r->status = ret;
			return OK;
		}

		return ret;
	}

	const char *location = apr_table_get(r->headers_out, "Location");

#if 0
	if (location && r->status == 200) {
		/* For a redirect whether internal or not, discard any
		 * remaining stdout from the script, and log any remaining
		 * stderr output, as normal. */
		discard_script_output(bb);
		apr_brigade_destroy(bb);
		apr_file_pipe_timeout_set(script_err, r->server->timeout);
		log_script_err(r, script_err);
	}
#endif

	if (location && location[0] == '/' && r->status == 200) {
		/* This redirect needs to be a GET no matter what the original
		 * method was.
		 */
		r->method = apr_pstrdup(r->pool, "GET");
		r->method_number = M_GET;

		/* We already read the message body (if any), so don't allow
		 * the redirected request to think it has one.  We can ignore
		 * Transfer-Encoding, since we used REQUEST_CHUNKED_ERROR.
		 */
		apr_table_unset(r->headers_in, "Content-Length");

		ap_internal_redirect_handler(location, r);
		return OK;
	}

	else if (location && r->status == 200) {
		/* XX Note that if a script wants to produce its own Redirect
		 * body, it now has to explicitly *say* "Status: 302"
		 */
		return HTTP_MOVED_TEMPORARILY;
	}

	return OK;
}

int fcgi_server_recv_stdout_stderr_record(fcgi_request_t *fr,
		uint16_t request_id, void *buffer)
{
	apr_status_t status = OK;

	/* state information */
	uint8_t type = FCGI_UNKNOWN_TYPE;
	uint32_t payload_len = 0;
	uint16_t padding_len = 0;
	int seen_eos = 0;
	int is_cgi_header = 1;

	char *p, *data;
	int i;

	do {
		payload_len = 0;

		/* Step 1: read FCGI packet header */
		ssize_t bytes_read = socket_recv(fr, buffer, FCGI_HEADER_LEN);

		if (bytes_read == -1) {
			status = HTTP_INTERNAL_SERVER_ERROR;
			goto out;
		}

		if (bytes_read < FCGI_HEADER_LEN) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
					"FastCGI: premature end of header from backend server (id=%u, bytes_read=%lu, needed=%u)",
					request_id, bytes_read, FCGI_HEADER_LEN);
			status = HTTP_INTERNAL_SERVER_ERROR;
			goto out;
		}

		/* Step 2: parse header */
		status = fcgi_server_recv_check_header(fr, request_id,
				(fcgi_header_t)buffer, &type, &payload_len, &padding_len);

		if (status != OK)
			goto out;

		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, fr->r,
				"FastCGI: packet received (id=%u, type=%u, payload_len=%u)",
				request_id, type, payload_len);

		if (payload_len == 0)
			continue;

		/* Step 3: read FCGI payload */
		bytes_read = socket_recv(fr, buffer, payload_len);

		if (bytes_read == -1) {
			status = HTTP_INTERNAL_SERVER_ERROR;
			goto out;
		}

		if (bytes_read < payload_len) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
					"FastCGI: premature end of payload from backend server (id=%u, bytes_read=%lu, needed=%u)",
					request_id, bytes_read, payload_len);
			status = HTTP_INTERNAL_SERVER_ERROR;
			goto out;
		}

		payload_len -= padding_len;
		data = buffer;
		data[payload_len] = '\0';

		/* Step 4: handle packet types */
		switch (type) {
			case FCGI_END_REQUEST:
				seen_eos = 1;
				break;

			case FCGI_STDOUT:
				p = data;

				if (is_cgi_header) {
					is_cgi_header = 0;

					/* TODO: nph */
					/* XXX: this assumes that the backend does not send more
					 * than 64K of headers, which is probably safe, but it
					 * should be fixed nevertheless. */

					status = fcgi_server_parse_headers(fr, request_id,
							&data, payload_len);

					if (status != OK) {
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, fr->r,
								"FastCGI: => CGI headers return not OK (id=%u, status=%i)",
								request_id, status);
						goto out;
					}

					if (data) {
						payload_len -= (data - p);
					}
				}

				if (data) {
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, fr->r,
							"FastCGI: sending CGI data (id=%u, payload_len=%u)",
							request_id, payload_len);

					status = fcgi_server_send_stdout_data(fr, request_id,
							data, payload_len);

					if (status != OK) {
						goto out;
					}
				}
				break;

			case FCGI_STDERR:
				p = data;

				for (i = 0; i < payload_len; i++) {
					if (data[i] == '\n' || data[i] == '\r' || data[i] == '\0') {
						data[i] = '\0';

						if ((data - p) > 0) {
							ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
									"FastCGI: STDERR(id=%u): %s", request_id, p);
						}

						p = data + i + 1;
					}
				}
				break;
		}
	} while (!seen_eos);

out:
	socket_sink(fr);
	fcgi_server_disconnect(fr);
	return status;
}
