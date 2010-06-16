#ifndef FCGI_REQUEST_H
#define FCGI_REQUEST_H

#include <stdint.h>

#include <httpd.h>

#include "mod_fastcgi_pass.h"

typedef struct {
	const char *server;                /* server name as given in httpd.conf */
	fastcgi_pass_cfg *cfg;             /* pointer to per-dir config for convenience */
	request_rec *r;

	struct sockaddr *socket_addr;      /* socket address of the FastCGI application */
	int socket_addr_len;               /* length of socket struct */
	int socket_fd;                     /* socket descriptor to FastCGI server */

	//int gotHeader;                     /* TRUE if reading content bytes */
	//unsigned char packetType;          /* type of packet */
	//int dataLen;                       /* length of data bytes */
	//int paddingLen;                    /* record padding after content */

	//fcgi_buf_t *server_input_buffer;   /* input buffer from FastCgi server */
	//fcgi_buf_t *server_output_buffer;  /* output buffer to FastCgi server */
	//fcgi_buf_t *client_input_buffer;   /* client input buffer */
	//fcgi_buf_t *client_output_buffer;  /* client output buffer */

	//int should_client_block;     /* >0 => more content, <=0 => no more */
	//apr_array_header_t *header;
	//char *stderr;
	//int stderr_len;
	//int parseHeader;                /* TRUE iff parsing response headers */
	//int readingEndRequestBody;
	//FCGI_EndRequestBody endRequestBody;
	//fcgi_buf_t *erBufPtr;
	//int exitStatus;
	//int exitStatusSet;
	//unsigned int requestId;
	//int eofSent;
} fcgi_request_t;

int fcgi_request_create(request_rec *r, fcgi_request_t **frP);

int fcgi_request_process(fcgi_request_t *fr);

#endif
