#include <unistd.h>

#include <apr_lib.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <util_filter.h>
#include <util_script.h>

#include "fcgi_body.h"
#include "fcgi_record.h"
#include "fcgi_server.h"

static
ssize_t socket_send(int fd, void *buf, size_t len)
{
	ssize_t bytes_sent;

	do {
		bytes_sent = write(fd, buf, len);
	} while (bytes_sent == -1 && errno == EINTR);

	return bytes_sent;
}

static
ssize_t socket_recv(int fd, void *buf, size_t len)
{
	ssize_t bytes_read;

	do {
		bytes_read = read(fd, buf, len);
	} while (bytes_read == -1 && errno == EINTR);

	return bytes_read;
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
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"socket file descriptor (%u) is larger than "
				"FD_SETSIZE (%u), you probably need to rebuild Apache with a "
				"larger FD_SETSIZE", fr->server, fr->socket_fd, FD_SETSIZE);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* connect the socket */
	if (connect(fr->socket_fd, (struct sockaddr *)fr->socket_addr, fr->socket_addr_len) == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
				"FastCGI: failed to connect to server \"%s\": "
				"connect() failed", fr->server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

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
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, fr->r->server,
			"FastCGI: ==> STEP 1 - begin send FCGI_BEGIN_REQUEST(id=%u)",
			request_id);

	/* build record into current buffer */
	fcgi_record_begin_request_build((fcgi_record_begin_request_t)record_buffer,
			request_id, FCGI_RESPONDER, 0); /* TODO: FCGI_KEEP_CONN */

	/* send data to the FastCGI server */
	ssize_t bytes_sent = socket_send(fr->socket_fd, record_buffer,
			sizeof(struct fcgi_record_begin_request));

	if (bytes_sent == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, fr->r->server,
				"FastCGI: failed to write to backend server (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, fr->r->server,
			"FastCGI: FCGI_BEGIN_REQUEST(id=%u) has been sent", request_id);

	return OK;
}

/* Obtain the Request-URI from the original request-line, returning
 * a new string from the request pool containing the URI or "".
 */
static
char *fcgi_original_uri(request_rec *r)
{
	char *first, *last;

	if (r->the_request == NULL) {
		return (char *) apr_pcalloc(r->pool, 1);
	}

	first = r->the_request;     /* use the request-line */

	while (*first && !apr_isspace(*first)) {
		++first;                /* skip over the method */
	}
	while (apr_isspace(*first)) {
		++first;                /*   and the space(s)   */
	}

	last = first;
	while (*last && !apr_isspace(*last)) {
		++last;                 /* end at next whitespace */
	}

	return apr_pstrmemdup(r->pool, first, last - first);
}

static
void fcgi_add_cgi_vars(request_rec *r)
{
	apr_table_t *e = r->subprocess_env;

	apr_table_setn(e, "GATEWAY_INTERFACE", "CGI/1.1");
	apr_table_setn(e, "SERVER_PROTOCOL", r->protocol);
	apr_table_setn(e, "REQUEST_METHOD", r->method);
	apr_table_setn(e, "QUERY_STRING", r->args ? r->args : "");
	apr_table_setn(e, "REQUEST_URI", fcgi_original_uri(r));

	/* Note that the code below special-cases scripts run from includes,
	 * because it "knows" that the sub_request has been hacked to have the
	 * args and path_info of the original request, and not any that may have
	 * come with the script URI in the include command.  Ugh.
	 */

	if (!strcmp(r->protocol, "INCLUDED")) {
		apr_table_setn(e, "SCRIPT_NAME", r->uri);
		if (r->path_info && *r->path_info) {
			apr_table_setn(e, "PATH_INFO", r->path_info);
		}
	}       
	else if (!r->path_info || !*r->path_info) {
		apr_table_setn(e, "SCRIPT_NAME", r->uri);
	}
	else {
		int path_info_start = ap_find_path_info(r->uri, r->path_info);

		apr_table_setn(e, "SCRIPT_NAME",
				apr_pstrndup(r->pool, r->uri, path_info_start));

		apr_table_setn(e, "PATH_INFO", r->path_info);
	}

	const char *document_root = apr_table_get(e, "DOCUMENT_ROOT");
	const char *script_name = apr_table_get(e, "SCRIPT_NAME");

	apr_table_setn(e, "SCRIPT_FILENAME", apr_pstrcat(r->pool, document_root, script_name, NULL));
	apr_table_setn(e, "PATH_TRANSLATED",apr_pstrcat(r->pool, document_root, script_name, NULL));
}

int fcgi_server_send_params_record(fcgi_request_t *fr, uint16_t request_id,
		void *record_buffer)
{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, fr->r->server,
			"FastCGI: ==> STEP 2 - begin send FCGI_PARAMS(id=%u)",
			request_id);

	/* add all environment variables to r->subprocess_env */
	ap_add_common_vars(fr->r);
	fcgi_add_cgi_vars(fr->r);
	/* TODO: FastCgiPassHeader */

	/* build FCGI_PARAMS record based on apache environement */
	apr_pool_t *p = fr->r->pool;
	char **env = ap_create_environment(p, fr->r->subprocess_env);

	apr_status_t status;
	status = fcgi_record_params_build((fcgi_header_t)record_buffer, request_id, env);

	if (status != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, fr->r->server,
				"FastCGI: failed to build params record (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	apr_size_t len = fcgi_header_content_length_get((fcgi_header_t)record_buffer) +
		fcgi_header_padding_length_get((fcgi_header_t)record_buffer) +
		FCGI_HEADER_LEN;

	/* send data to the FastCGI server */
	ssize_t bytes_sent = socket_send(fr->socket_fd, record_buffer, len);

	if (bytes_sent == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, fr->r->server,
				"FastCGI: failed to write to backend server (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* build and send VOID FCGI_PARAMS record */
	status = fcgi_record_params_build((fcgi_header_t)record_buffer, request_id, NULL);

	if (status != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, fr->r->server,
				"FastCGI: failed to build params record (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* send data to the FastCGI server */
	bytes_sent = socket_send(fr->socket_fd, record_buffer, FCGI_HEADER_LEN);

	if (bytes_sent == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, fr->r->server,
				"FastCGI: failed to write to backend server (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

int fcgi_server_send_stdin_record(fcgi_request_t *fr, uint16_t request_id,
		void *record_buffer)
{
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, fr->r->server,
			"FastCGI: ==> STEP 3 - begin send FCGI_STDIN(id=%u)",
			request_id);

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

			/* build FCGI_STDIN record */
			len = fcgi_record_build((fcgi_header_t)record_buffer, request_id, FCGI_STDIN, len);

			/* send data to the FastCGI server */
			ssize_t bytes_sent = socket_send(fr->socket_fd, record_buffer, len);

			if (bytes_sent == -1) {
				server_stopped_reading = 1;
			}
		}

		apr_brigade_cleanup(bb);
	} while (!seen_eos);

	apr_brigade_cleanup(bb);

	/* build void FCGI_STDIN record */
	fcgi_header_set((fcgi_header_t)record_buffer, FCGI_VERSION_1, FCGI_STDIN, request_id, 0, 0);

	/* send data to the FastCGI server */
	ssize_t bytes_sent = socket_send(fr->socket_fd, record_buffer, FCGI_HEADER_LEN);

	if (bytes_sent == -1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, errno, fr->r->server,
				"FastCGI: failed to write to backend server (id=%u)", request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

static
int fcgi_server_recv_check_header(fcgi_request_t *fr,
		uint16_t request_id, fcgi_header_t header, uint8_t *type,
		uint16_t *content_length, uint32_t *total_record_len)
{
	/* get record version */
	uint8_t version = fcgi_header_version_get(header);
	if (version != FCGI_VERSION_1) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, fr->r->server,
				"FastCGI: unsupported FastCGI version from backend server (id:%u, version=%u)",
				request_id, version);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* get record type */
	*type = fcgi_header_type_get(header);
	if (*type != FCGI_END_REQUEST && *type != FCGI_STDOUT && *type != FCGI_STDERR) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, fr->r->server,
				"FastCGI: invalid record type from backend server (id=%u, type=%u)",
				request_id, *type);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* get request id */
	uint16_t received_request_id = fcgi_header_request_id_get(header);
	if (received_request_id != request_id) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, fr->r->server,
				"FastCGI: unexpected request_id from backend server (id=%u, received_id=%u)",
				request_id, received_request_id);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* get content and padding length of the record from header */
	uint8_t padding_length = fcgi_header_padding_length_get(header);

	*content_length = fcgi_header_content_length_get(header);
	*total_record_len = *content_length + padding_length + FCGI_HEADER_LEN;

	return OK;
}

static
int fcgi_server_send_stdout_data(fcgi_request_t *fr, uint16_t request_id,
		void *record_buffer, uint16_t content_length)
{
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, fr->r,
			"FastCGI: sending STDOUT record to client (id=%u, length=%u)",
			request_id, content_length);

	apr_bucket_alloc_t *bkt_alloc = fr->r->connection->bucket_alloc;
	apr_bucket_brigade *bde = apr_brigade_create(fr->r->pool, bkt_alloc);
	apr_bucket *bkt = apr_bucket_transient_create(record_buffer, content_length, bkt_alloc);
	APR_BRIGADE_INSERT_TAIL(bde, bkt);

	int rv = ap_pass_brigade(fr->r->output_filters, bde);

	if (rv || fr->r->connection->aborted) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, fr->r,
				"FastCGI: client stopped connection before send body completed");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

int fcgi_server_recv_stdout_stderr_record(fcgi_request_t *fr,
		uint16_t request_id, void *record_buffer)
{
	apr_status_t status = OK;

	/* current record header information */
	int is_header = 1;
	uint8_t type = FCGI_UNKNOWN_TYPE;
	uint16_t content_length = 0;

	/* globale buffer manipulation */
	int seen_eos = 0;
	size_t buffer_len = 0;
	uint32_t total_record_len = 0;

	char *p = NULL;
	int i;

	/* cgi header parsing */
	//int                 nFlagStep=0;
	//int                 is_cgi_header=0;
	//int                 nPrevChar=0;
	//int                 nNewLigneSize=0;
	//int                 nNewLigneChar=0;
	//apr_bucket_brigade  *ptrCGIHeaderBucketBrigade = apr_brigade_create(p, r->connection->bucket_alloc); /* create empty brigade */

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, fr->r->server,
			"FastCGI: ==> STEP 4 - Begin receive FCGI_STDOUT/FCGI_STDERR Stream ... id:%u",
			request_id);

	do {
		while ((buffer_len < FCGI_HEADER_LEN || buffer_len < total_record_len) && !seen_eos)
		{
			/* read data from the FastCGI server */
			ssize_t bytes_read = socket_recv(fr->socket_fd, ((char *)record_buffer) + buffer_len, HUGE_STRING_LEN);

			if (bytes_read == 0) {
				seen_eos = 1;
			} else if (bytes_read == -1) {
				ap_log_error(APLOG_MARK, APLOG_ERR, errno, fr->r->server,
						"FastCGI: failed to read from backend server (id=%u)", request_id);
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			/* inc buffer len with received data len */
			buffer_len += bytes_read;

			if (buffer_len < FCGI_HEADER_LEN && seen_eos) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, fr->r->server,
						"FastCGI: premature end of header from backend server (id=%u, buffer_len=%lu)",
						request_id, buffer_len);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}

		/* if is header zone and buffer_len >= FCGI_HEADER_LEN */
		if (is_header) {
			is_header = 0;
			status = fcgi_server_recv_check_header(fr, request_id,
					(fcgi_header_t)record_buffer, &type,
					&content_length, &total_record_len);

			if (status != APR_SUCCESS)
				return status;
		}

		if (buffer_len < total_record_len && seen_eos) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, fr->r->server,
					"FastCGI: premature end of stream from backend server (id=%u, buffer_len=%lu, record_length=%u)",
					request_id, buffer_len, total_record_len);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (buffer_len < total_record_len) {
			continue;
		}

		switch (type) {
			case FCGI_END_REQUEST:
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, fr->r->server,
						"FastCGI: => FCGI_END_REQUEST received (id=%u)", request_id);
				seen_eos = 1;
				break;

			case FCGI_STDOUT:
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, fr->r->server,
						"FastCGI: => FCGI_STDOUT received (id=%u, content_length=%u)",
						request_id, content_length);

				//if (!is_cgi_header) {
					status = fcgi_server_send_stdout_data(fr, request_id,
							((char *)record_buffer) + FCGI_HEADER_LEN, content_length);

					if (status != APR_SUCCESS) {
						return status;
					}
				//} else {
				//	status = fcgi_stdout_cgi_header(p, r, request_id, (char*)record_buffer+FCGI_HEADER_LEN, &nNewLigneSize,
				//			&nNewLigneChar, &nPrevChar, &is_cgi_header, &nFlagStep, ptrCGIHeaderBucketBrigade,&content_length);

				//	if (status != APR_SUCCESS)
				//		return status;
				//}
				break;

			case FCGI_STDERR:
				p = ((char *)record_buffer) + FCGI_HEADER_LEN;

				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, fr->r->server,
						"FastCGI: => FCGI_STDERR received (id=%u, content_length=%u)",
						request_id, content_length);

				for (i = 0; i < content_length; i++) {
					if (((char *)record_buffer)[i] == '\n' || ((char *)record_buffer)[i] == '\r') {
						((char *)record_buffer)[i] = '\0';

						if ((p - (char *)record_buffer + i) > 0) {
							ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, fr->r,
									"FastCGI: STDERR(id=%u): %s", request_id, p);
						}

						p = ((char *)record_buffer) + i + 1;
					}
				}
				break;
		}

		if (buffer_len >= total_record_len) {
			buffer_len -= total_record_len;

			if (buffer_len > 0) {
				memcpy(record_buffer, ((char *)record_buffer) + total_record_len, buffer_len);
			}

			total_record_len = 0;
			content_length = 0;
			is_header = 1;
		}
	} while (!seen_eos);

	return OK;
}
