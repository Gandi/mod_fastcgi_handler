#include "fcgi_header.h"

#define fcgi_header_twobyte_set(header, field, value) do { \
	(header)->field ## B0 = value & 0xff; \
	(header)->field ## B1 = (value >> 8) & 0xff; \
} while (0)

#define fcgi_header_twobyte_get(header, field) \
	(((header)->field ## B0 & 0xff) | \
	 (((header)->field ## B1 & 0xff) << 8))

void fcgi_header_version_set(fcgi_header_t header, uint8_t version)
{
	header->version = version;
}

uint8_t fcgi_header_version_get(fcgi_header_t header)
{
	return header->version;
}

void fcgi_header_type_set(fcgi_header_t header, uint8_t type)
{
	header->type = type;
}

uint8_t fcgi_header_type_get(fcgi_header_t header)
{
	return header->type;
}

void fcgi_header_request_id_set(fcgi_header_t header, uint16_t  request_id)
{
	fcgi_header_twobyte_set(header, request_id, request_id);
}

uint16_t fcgi_header_request_id_get(fcgi_header_t header)
{
	return fcgi_header_twobyte_get(header, request_id);
}

void fcgi_header_content_length_set(fcgi_header_t header, uint16_t content_length)
{
	fcgi_header_twobyte_set(header, content_length, content_length);
}

uint16_t fcgi_header_content_length_get(fcgi_header_t header)
{
	return fcgi_header_twobyte_get(header, content_length);
}

void fcgi_header_padding_length_set(fcgi_header_t header, uint8_t padding_length)
{
	header->padding_length = padding_length;
}

uint8_t fcgi_header_padding_length_get(fcgi_header_t header)
{
	return header->padding_length;
}

void fcgi_header_reserved_set(fcgi_header_t header)
{
	header->reserved = 0;
}

/* set all FastCGI record header field */
void fcgi_header_set(fcgi_header_t header, uint8_t version, uint8_t type,
		uint16_t request_id, uint16_t content_length, uint8_t padding_length)
{
	fcgi_header_version_set(header, version); /* set by default to v1 */
	fcgi_header_type_set(header, type);
	fcgi_header_request_id_set(header, request_id);
	fcgi_header_content_length_set(header, content_length);
	fcgi_header_padding_length_set(header, padding_length);
	fcgi_header_reserved_set(header); /* alway set to zero in v1 */
}
