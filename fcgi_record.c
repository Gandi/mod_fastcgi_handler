#include <string.h>

#include "fcgi_record.h"

void fcgi_record_begin_request_build(fcgi_record_begin_request_t begin_request_record,
		uint16_t request_id, uint32_t role, uint8_t flags)
{
	fcgi_header_set(&begin_request_record->header, FCGI_VERSION_1,
			FCGI_BEGIN_REQUEST, request_id, sizeof(fcgi_body_begin_request_t), 0);
	fcgi_body_begin_request_set(&begin_request_record->body, role, flags);
}

void fcgi_record_end_request_build(fcgi_record_end_request_t end_request_record,
		uint16_t request_id, uint32_t app_status, uint8_t protocol_status)
{
	fcgi_header_set(&end_request_record->header, FCGI_VERSION_1,
			FCGI_END_REQUEST, request_id, sizeof(fcgi_body_end_request_t), 0);
	fcgi_body_end_request_set(&end_request_record->body, app_status, protocol_status);
}

int fcgi_record_params_build(fcgi_header_t header, uint16_t request_id, char **env)
{
	uint8_t padding_length = 0;
	uint16_t content_length = 0;
	uint8_t *data = (uint8_t *)(header) + FCGI_HEADER_LEN;

	if (env) {
		content_length = fcgi_record_params_set(data, env);

		if (content_length == 0)
			return -1;

		/* pad record with 8 bytes aligned */
		padding_length = content_length % 8;
		padding_length = padding_length == 0 ? 0 : 8 - padding_length;
	}

	fcgi_header_set(header, FCGI_VERSION_1, FCGI_PARAMS, request_id, content_length, padding_length);

	/* set padding zone to zero */
	if (padding_length > 0)
		memset(data + content_length, '\0', padding_length);

	return 0;
}

uint32_t fcgi_record_build(fcgi_header_t header, uint16_t request_id,
		uint8_t stream_type, uint16_t content_length)
{
	uint8_t padding_length = 0;

	if (content_length != 0) {
		/* pad record with 8 bytes aligned */
		padding_length = content_length % 8;
		padding_length = padding_length == 0 ? 0 : 8 - padding_length;
	} else {
		padding_length = 0;
	}

	uint8_t *data = (uint8_t *)(header) + FCGI_HEADER_LEN;

	/* set request_id to zero for management type of record */
	if (stream_type == FCGI_GET_VALUES)
		request_id = 0;

	fcgi_header_set(header, FCGI_VERSION_1, stream_type, request_id, content_length, padding_length);

	/* set padding zone to zero */
	if (padding_length > 0)
		memset(data + content_length, '\0', padding_length);

	return padding_length;
}
