#ifndef FCGI_BODY_H
#define FCGI_BODY_H

#include <stdint.h>

struct fcgi_body_begin_request {
	uint8_t roleB1;
	uint8_t roleB0;
	uint8_t flags;
	uint8_t reserved[5];
};

typedef struct fcgi_body_begin_request *fcgi_body_begin_request_t;

/* mask for flags component of fcgi_body_begin_request_t */
#define FCGI_KEEP_CONN 1

/* values for role component of fcgi_body_begin_request_t */
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

uint16_t fcgi_body_begin_request_role_get(fcgi_body_begin_request_t begin_request_body);
void     fcgi_body_begin_request_role_set(fcgi_body_begin_request_t begin_request_body, uint16_t role);

uint8_t  fcgi_body_begin_request_flags_get(fcgi_body_begin_request_t begin_request_body);
void     fcgi_body_begin_request_flags_set(fcgi_body_begin_request_t begin_request_body, uint8_t flags);

void     fcgi_body_begin_request_reserved_set(fcgi_body_begin_request_t begin_request_body);

void fcgi_body_begin_request_set(fcgi_body_begin_request_t begin_request_body,
		uint16_t role, uint8_t flags);


uint16_t fcgi_record_params_calc_len(uint16_t key_len, uint16_t value_len);

uint16_t fcgi_record_params_value_get(uint8_t *data, char **keyP,
		uint16_t *key_lenP, char **valueP, uint16_t *value_lenP);

uint16_t fcgi_record_params_value_set(uint8_t *data, const char *key,
		uint16_t key_len, const char *value, uint16_t value_len);

uint16_t fcgi_record_params_set(uint8_t *data, char **env);


struct fcgi_body_end_request {
	uint8_t app_statusB3;
	uint8_t app_statusB2;
	uint8_t app_statusB1;
	uint8_t app_statusB0;
	uint8_t protocol_status;
	uint8_t reserved[3];
};

typedef struct fcgi_body_end_request *fcgi_body_end_request_t;

uint32_t fcgi_body_end_request_app_status_get(fcgi_body_end_request_t end_request_body);
void     fcgi_body_end_request_app_status_set(fcgi_body_end_request_t end_request_body,
		uint32_t app_status);

uint8_t fcgi_body_end_request_protocol_status_get(fcgi_body_end_request_t end_request_body);
void    fcgi_body_end_request_protocol_status_set(fcgi_body_end_request_t end_request_body,
		uint8_t protocol_status);

void fcgi_body_end_request_reserved_set(fcgi_body_end_request_t end_request_body);

void fcgi_body_end_request_set(fcgi_body_end_request_t end_request_body,
		uint32_t app_status, uint8_t protocol_status);

/* values for protocol_status component of fcgi_body_end_request_t */
#define FCGI_REQUEST_COMPLETE 0
#define FCGI_CANT_MPX_CONN    1
#define FCGI_OVERLOADED       2
#define FCGI_UNKNOWN_ROLE     3

#endif
