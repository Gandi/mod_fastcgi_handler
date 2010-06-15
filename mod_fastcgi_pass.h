#ifndef MOD_FASTCGI_H
#define MOD_FASTCGI_H

/* max number of chars in a line of stderr we can handle from a FastCGI Server */
#define FCGI_SERVER_MAX_STDERR_LINE_LEN 1023

#define SERVER_BUFSIZE 8192

#ifndef SUN_LEN
#define SUN_LEN(sock) \
    (sizeof(*(sock)) - sizeof((sock)->sun_path) + strlen((sock)->sun_path))
#endif

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

typedef struct {
	int idle_timeout;
	apr_array_header_t *headers;
} fastcgi_pass_cfg;

#endif
