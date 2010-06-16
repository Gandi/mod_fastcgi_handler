#ifndef FCGI_RECORD_H
#define FCGI_RECORD_H

#include <stdint.h>

#include "fcgi_header.h"
#include "fcgi_body.h"

struct fcgi_record_begin_request {
	struct fcgi_header header;
	struct fcgi_body_begin_request body;
};

typedef struct fcgi_record_begin_request *fcgi_record_begin_request_t;

struct fcgi_record_end_request {
	struct fcgi_header header;
	struct fcgi_body_end_request body;
};

typedef struct fcgi_record_end_request *fcgi_record_end_request_t;

void fcgi_record_begin_request_build(fcgi_record_begin_request_t begin_request_record,
		uint16_t request_id, uint32_t role, uint8_t flags);

void fcgi_record_end_request_build(fcgi_record_end_request_t end_request_record,
		uint16_t request_id, uint32_t app_status, uint8_t protocol_status);

int fcgi_record_params_build(fcgi_header_t header,
		uint16_t request_id, char **env);

uint32_t fcgi_record_build(fcgi_header_t header, uint16_t request_id,
		uint8_t stream_type, uint16_t content_length);

#endif
