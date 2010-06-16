#ifndef FCGI_SERVER_H
#define FCGI_SERVER_H

#include <stdint.h>

#include "fcgi_request.h"

int fcgi_server_connect(fcgi_request_t *fr);

int fcgi_server_send_begin_record(fcgi_request_t *fr, uint16_t request_id,
		void *record_buffer);

int fcgi_server_send_params_record(fcgi_request_t *fr, uint16_t request_id,
		void *record_buffer);

int fcgi_server_send_stdin_record(fcgi_request_t *fr, uint16_t request_id,
		void *record_buffer);

int fcgi_server_recv_stdout_stderr_record(fcgi_request_t *fr,
		uint16_t request_id, void *record_buffer);

#endif
