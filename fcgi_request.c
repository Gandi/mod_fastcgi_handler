#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <apr_strings.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include "fcgi_header.h"
#include "fcgi_request.h"

#include "mod_fastcgi_handler.h"

#ifndef SUN_LEN
#define SUN_LEN(sock) \
    (sizeof(*(sock)) - sizeof((sock)->sun_path) + strlen((sock)->sun_path))
#endif

static
const char *fcgi_util_socket_make_domain_addr(apr_pool_t *p,
		struct sockaddr_un **socket_addr, int *socket_addr_len,
		const char *socket_path)
{
	size_t socket_path_len = strlen(socket_path);

	if (socket_path_len >= sizeof((*socket_addr)->sun_path)) {
		return apr_pstrcat(p, "path \"", socket_path,
				"\" is too long for a Domain socket", NULL);
	}

	if (*socket_addr == NULL)
		*socket_addr = apr_pcalloc(p, sizeof(struct sockaddr_un));
	else
		memset(*socket_addr, 0, sizeof(struct sockaddr_un));

	(*socket_addr)->sun_family = AF_UNIX;
	strcpy((*socket_addr)->sun_path, socket_path);

	*socket_addr_len = SUN_LEN(*socket_addr);
	return NULL;
}

static
int convert_string_to_in_addr(const char *hostname, struct in_addr *addr)
{
	if (inet_aton(hostname, addr) == 0) {
		struct hostent *hp;

		if ((hp = gethostbyname(hostname)) == NULL)
			return -1;

		memcpy((char *) addr, hp->h_addr, hp->h_length);

		int count = 0;
		while (hp->h_addr_list[count] != 0)
			count++;

		return count == 1 ? 0 : -1;
	}

	return 0;
}

static
const char *fcgi_util_socket_make_inet_addr(apr_pool_t *p,
		struct sockaddr_in **socket_addr, int *socket_addr_len,
		const char *host, unsigned short port)
{
	if (*socket_addr == NULL)
		*socket_addr = apr_pcalloc(p, sizeof(struct sockaddr_in));
	else
		memset(*socket_addr, 0, sizeof(struct sockaddr_in));

	(*socket_addr)->sin_family = AF_INET;
	(*socket_addr)->sin_port = htons(port);

	/* get an in_addr represention of the host */
	if (convert_string_to_in_addr(host, &(*socket_addr)->sin_addr) == -1) {
		return apr_pstrcat(p, "failed to resolve \"", host,
				"\" to exactly one IP address", NULL);
	}

	*socket_addr_len = sizeof(struct sockaddr_in);
	return NULL;
}

static
const char *fcgi_util_socket_make_addr(apr_pool_t *p, fcgi_request_t *fr)
{
	if (!fr->server || !*fr->server)
		return apr_pstrdup(p, "empty");

	if (*fr->server == '/') {
		return fcgi_util_socket_make_domain_addr(p,
				(struct sockaddr_un **)&fr->socket_addr,
				&fr->socket_addr_len, fr->server);
	}

	char *host = apr_pstrdup(p, fr->server);
	char *port_str = strchr(host, ':');

	if (!port_str) {
		return apr_pstrdup(p, "no port specified");
	} else {
		*port_str++ = '\0';
	}

	unsigned short port = atoi(port_str);

	if (port <= 0)
		return apr_pstrdup(p, "invalid port sepcified");

	return fcgi_util_socket_make_inet_addr(p,
			(struct sockaddr_in **)&fr->socket_addr,
			&fr->socket_addr_len, host, port);
}

int fcgi_request_create(request_rec *r, fcgi_request_t **frP)
{
	apr_pool_t *p = r->pool;
	fcgi_request_t *fr = apr_pcalloc(p, sizeof(fcgi_request_t));

	/* setup server socket struct */
	fr->server = apr_pstrdup(p, r->handler + 5);

	const char *err = fcgi_util_socket_make_addr(p, fr);

	if (err) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"FastCGI: invalid server address: '%s': %s",
				fr->server, err);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* keep a pointer to cfg and r for convenience */
	fr->cfg = ap_get_module_config(r->per_dir_config, &fastcgi_handler_module);
	fr->r = r;

	*frP = fr;

	return OK;
}

#define CHECK(e) do { \
	status = e; \
	if (status != OK) { \
		goto err; \
	} \
} while (0)

int fcgi_request_process(fcgi_request_t *fr)
{
	apr_pool_t *p = fr->r->pool;
	int status;

	unsigned int request_id = (fr->r->connection->id & 0xffff) + 1;

	/* allocate a buffer for at least FCGI_MAX_LENGTH+FCGI_HEADER_LEN bytes */
	uint8_t *record_buffer = apr_pcalloc(p, (FCGI_MAX_LENGTH + FCGI_HEADER_LEN + 1) * 2);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, fr->r,
			"FastCGI: ==> STEP 1 - send FCGI_BEGIN_REQUEST(id=%u)",
			request_id);

	CHECK(fcgi_server_send_begin_record(fr, request_id, record_buffer));

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, fr->r,
			"FastCGI: ==> STEP 2 - send FCGI_PARAMS(id=%u)",
			request_id);

	CHECK(fcgi_server_send_params_record(fr, request_id, record_buffer));

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, fr->r,
			"FastCGI: ==> STEP 3 - send FCGI_STDIN(id=%u)",
			request_id);

	CHECK(fcgi_server_send_stdin_record(fr, request_id, record_buffer));

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, fr->r,
			"FastCGI: ==> STEP 4 - recv FCGI_STDOUT(id=%u)",
			request_id);

	CHECK(fcgi_server_recv_stdout_stderr_record(fr, request_id, record_buffer));

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, fr->r,
			"FastCGI: ==> STEP 5 - return OK(id=%u)",
			request_id);

err:
	fcgi_server_disconnect(fr);
	return status;
}
