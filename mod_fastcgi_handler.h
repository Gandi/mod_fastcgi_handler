#ifndef MOD_FASTCGI_H
#define MOD_FASTCGI_H

#include <apr_tables.h>

#include <ap_compat.h>
#include <http_config.h>

#define FCGI_DEFAULT_IDLE_TIMEOUT 30

typedef struct {
	apr_table_t *action_types;
	int idle_timeout;
} fastcgi_handler_cfg;

extern module MODULE_VAR_EXPORT fastcgi_handler_module;

#endif
