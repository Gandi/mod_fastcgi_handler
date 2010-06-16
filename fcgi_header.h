#ifndef FCGI_HEADER_H
#define FCGI_HEADER_H

#include <stdint.h>

struct fcgi_header {
	uint8_t version;
	uint8_t type;
	uint8_t request_idB1;
	uint8_t request_idB0;
	uint8_t content_lengthB1;
	uint8_t content_lengthB0;
	uint8_t padding_length;
	uint8_t reserved;
};

typedef struct fcgi_header *fcgi_header_t;

/* maximum length of a FastCGI packet */
#define FCGI_MAX_LENGTH 0xffff

/* number of bytes in an fcgi_header_t */
#define FCGI_HEADER_LEN 8

/* values for the version component of fcgi_header_t */
#define FCGI_VERSION_1 1

/* values for type component of fcgi_header_t */
#define FCGI_BEGIN_REQUEST       1
#define FCGI_ABORT_REQUEST       2
#define FCGI_END_REQUEST         3
#define FCGI_PARAMS              4
#define FCGI_STDIN               5
#define FCGI_STDOUT              6
#define FCGI_STDERR              7
#define FCGI_DATA                8
#define FCGI_GET_VALUES          9
#define FCGI_GET_VALUES_RESULT  10
#define FCGI_UNKNOWN_TYPE       11
#define FCGI_MAXTYPE (FCGI_UNKNOWN_TYPE)

/* value for request_id component of fcgi_header_t */
#define FCGI_NULL_REQUEST_ID 0

void     fcgi_header_version_set(fcgi_header_t header, uint8_t version);
uint8_t  fcgi_header_version_get(fcgi_header_t header);

void     fcgi_header_type_set(fcgi_header_t header, uint8_t type);
uint8_t  fcgi_header_type_get(fcgi_header_t header);

void     fcgi_header_request_id_set(fcgi_header_t header, uint16_t  request_id);
uint16_t fcgi_header_request_id_get(fcgi_header_t header);

void     fcgi_header_content_length_set(fcgi_header_t header, uint16_t content_length);
uint16_t fcgi_header_content_length_get(fcgi_header_t header);

void     fcgi_header_padding_length_set(fcgi_header_t header, uint8_t padding_length);
uint8_t  fcgi_header_padding_length_get(fcgi_header_t header);

void     fcgi_header_reserved_set(fcgi_header_t header);

void fcgi_header_set(fcgi_header_t header, uint8_t version, uint8_t type,
		uint16_t request_id, uint16_t content_length, uint8_t padding_length);

#endif
