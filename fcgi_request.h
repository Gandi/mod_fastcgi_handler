#ifndef FCGI_REQUEST_H
#define FCGI_REQUEST_H

#include <stdint.h>

#include <httpd.h>

#include "mod_fastcgi_handler.h"

typedef struct {
	const char *server;                /* server name as given in httpd.conf */
	fastcgi_handler_cfg *cfg;          /* pointer to per-dir config for convenience */
	request_rec *r;

	struct sockaddr *socket_addr;      /* socket address of the FastCGI application */
	int socket_addr_len;               /* length of socket struct */
	int socket_fd;                     /* socket descriptor to FastCGI server */
} fcgi_request_t;

int fcgi_request_create(request_rec *r, fcgi_request_t **frP);

int fcgi_request_process(fcgi_request_t *fr);

#endif
