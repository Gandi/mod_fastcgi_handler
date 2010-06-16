#include <string.h>

#include "fcgi_header.h"
#include "fcgi_body.h"

#define fcgi_header_twobyte_set(header, field, value) do { \
	(header)->field ## B0 = value & 0xff; \
	(header)->field ## B1 = (value >> 8) & 0xff; \
} while (0)

#define fcgi_header_twobyte_get(header, field) \
	(((header)->field ## B0 & 0xff) | \
	 (((header)->field ## B1 & 0xff) << 8))

#define fcgi_header_fourbyte_set(header, field, value) do { \
	(header)->field ## B0 = value & 0xff; \
	(header)->field ## B1 = (value >> 8) & 0xff; \
	(header)->field ## B2 = (value >> 16) & 0xff; \
	(header)->field ## B3 = (value >> 24) & 0xff; \
} while (0)

#define fcgi_header_fourbyte_get(header, field) \
	(((header)->field ## B0 & 0xff) | \
	 (((header)->field ## B1 & 0xff) << 8) | \
	 (((header)->field ## B1 & 0xff) << 16) | \
	 (((header)->field ## B1 & 0xff) << 24))


uint16_t fcgi_body_begin_request_role_get(fcgi_body_begin_request_t begin_request_body)
{
	return fcgi_header_twobyte_get(begin_request_body, role);
}

uint8_t fcgi_body_begin_request_flags_get(fcgi_body_begin_request_t begin_request_body)
{
	return begin_request_body->flags;
}

void fcgi_body_begin_request_role_set(fcgi_body_begin_request_t begin_request_body, uint16_t role)
{
	fcgi_header_twobyte_set(begin_request_body, role, role);
}

void fcgi_body_begin_request_flags_set(fcgi_body_begin_request_t begin_request_body, uint8_t flags)
{
	begin_request_body->flags = flags;
}

void fcgi_body_begin_request_reserved_set(fcgi_body_begin_request_t begin_request_body)
{
	memset(begin_request_body->reserved, 0, sizeof(begin_request_body->reserved));
}

void fcgi_body_begin_request_set(fcgi_body_begin_request_t begin_request_body, uint16_t role, uint8_t flags)
{
	fcgi_body_begin_request_role_set(begin_request_body, role);
	fcgi_body_begin_request_flags_set(begin_request_body, flags);
	fcgi_body_begin_request_reserved_set(begin_request_body); /* alway set to 0 */
}

uint16_t fcgi_record_params_calc_len(uint16_t key_len, uint16_t value_len)
{
	uint16_t len = key_len + value_len;
	len += key_len > 127 ? 4 : 1;
	len += value_len > 127 ? 4 : 1;
	return len;
}

uint16_t fcgi_record_params_value_get(uint8_t *data, char **keyP,
		uint16_t *key_lenP, char **valueP, uint16_t *value_lenP)
{
	uint32_t key_len = 0, value_len = 0;
	int pos = 0;

	if (((*data) >> 7) == 0 && ((*(data+1)) >> 7) == 0) {
		key_len = *data++;
		value_len = *data++;
		pos += 2;
	}

	else if (((*data) >> 7) == 0 && ((*(data + 1)) >> 7) == 1) {
		key_len = *data++;
		value_len  = (*data++) << 24;
		value_len |= (*data++) << 16;
		value_len |= (*data++) << 8;
		value_len |= (*data++);
		pos += 5;
	}

	else if (((*data) >> 7) == 1 && ((*(data + 4)) >> 7) == 0) {
		key_len  = (*data++) << 24;
		key_len |= (*data++) << 16;
		key_len |= (*data++) << 8;
		key_len |= (*data++);
		value_len += (*data++);
		pos += 5;
	}

	else if (((*data) >> 7) == 1 && ((*(data + 4)) >> 7) == 1) {
		key_len  = (*data++) << 24;
		key_len |= (*data++) << 16;
		key_len |= (*data++) << 8;
		key_len |= (*data++);
		value_len  = (*data++) << 24;
		value_len |= (*data++) << 16;
		value_len |= (*data++) << 8;
		value_len |= (*data++);
		pos += 8;
	}

	*keyP = (char *)(data + pos);
	*valueP = (char *)((*keyP) + key_len);

	/* must be lower than FCGI_MAX_LENGTH */
	if ((key_len + value_len + FCGI_HEADER_LEN) > FCGI_MAX_LENGTH)
		return 0;

	*key_lenP = key_len;
	*value_lenP = value_len;

	return pos + key_len + value_len;
}

uint16_t fcgi_record_params_value_set(uint8_t *data, const char *key,
		uint16_t key_len, const char *value, uint16_t value_len)
{
	if (!key || !value || !data)
		return 0;

	if ((key_len + value_len + FCGI_HEADER_LEN) > FCGI_MAX_LENGTH)
		return 0;

	if (key_len > 127) {
		*(data++) = ((key_len >> 24) & 0xff) | 0x80;
		*(data++) =  (key_len >> 16) & 0xff;
		*(data++) =  (key_len >> 8 ) & 0xff;
		*(data++) =  (key_len >> 0 ) & 0xff;
	} else {
		*(data++) =  (key_len >> 0) & 0xff;
	}

	if (value_len > 127) {
		*(data++) = ((value_len >> 24) & 0xff) | 0x80;
		*(data++) =  (value_len >> 16) & 0xff;
		*(data++) =  (value_len >> 8 ) & 0xff;
		*(data++) =  (value_len >> 0 ) & 0xff;
	} else {
		*(data++) =  (value_len >> 0) & 0xff;
	}

	memcpy(data, key, key_len);
	memcpy(data + key_len, value, value_len);

	return fcgi_record_params_calc_len(key_len, value_len);
}

uint16_t fcgi_record_params_set(uint8_t *data, char **env)
{
	char *key, *value;
	uint16_t key_len, value_len;
	uint16_t len=0;
	uint32_t pos=0;

	for (; *env != NULL; env++) {
		key = *env;

		if ((value = strchr(*env, '=')) == NULL)
			continue;

		key_len = value - key;
		value++; /* skip '=' */
		value_len = strlen(value);

		len = fcgi_record_params_value_set(data + pos, key, key_len, value, value_len);

		if (len == 0)
			return 0;

		pos += len;

		if ((pos + FCGI_HEADER_LEN) > FCGI_MAX_LENGTH)
			return 0;
	}
	return pos;
}

uint32_t fcgi_body_end_request_app_status_get(fcgi_body_end_request_t end_request_body)
{
	return fcgi_header_fourbyte_get(end_request_body, app_status);
}

uint8_t fcgi_body_end_request_protocol_status_get(fcgi_body_end_request_t end_request_body)
{
	return end_request_body->protocol_status;
}

void fcgi_body_end_request_app_status_set(fcgi_body_end_request_t end_request_body, uint32_t app_status)
{
	fcgi_header_fourbyte_set(end_request_body, app_status, app_status);
}

void fcgi_body_end_request_protocol_status_set(fcgi_body_end_request_t end_request_body, uint8_t protocol_status)
{
	end_request_body->protocol_status = protocol_status;
}

void fcgi_body_end_request_reserved_set(fcgi_body_end_request_t end_request_body)
{
	memset(end_request_body->reserved, 0, sizeof(end_request_body->reserved));
}

void fcgi_body_end_request_set(fcgi_body_end_request_t end_request_body, uint32_t app_status, uint8_t protocol_status)
{
	fcgi_body_end_request_app_status_set(end_request_body, app_status);
	fcgi_body_end_request_protocol_status_set(end_request_body, protocol_status);
	fcgi_body_end_request_reserved_set(end_request_body); /* alway set to 0 */
}
