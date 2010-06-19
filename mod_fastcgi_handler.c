#include <unistd.h>

#include "fcgi_request.h"
#include "fcgi_server.h"

static
int fastcgi_handler(request_rec *r)
{
	if (strncmp(r->handler, "fcgi:", 5))
		return DECLINED;

	fcgi_request_t *fr = NULL;
	int ret;

	/* Step 1: create a new FastCGI request object */
	if ((ret = fcgi_request_create(r, &fr)) != OK) {
		return ret;
	}

	/* Step 2: connect to the FastCGI server */
	if ((ret = fcgi_server_connect(fr)) != OK) {
		return ret;
	}

	/* Step 3: process the request */
	return fcgi_request_process(fr);
}

static
void *fastcgi_handler_create_dir_config(apr_pool_t *p, char *dir)
{
	fastcgi_handler_cfg *cfg = apr_pcalloc(p, sizeof(fastcgi_handler_cfg));

	cfg->idle_timeout = -1;

	return cfg;
}

static
void *fastcgi_handler_merge_dir_config(apr_pool_t *p, void *parent, void *current)
{
	fastcgi_handler_cfg *parent_cfg = (fastcgi_handler_cfg *) parent;
	fastcgi_handler_cfg *current_cfg = (fastcgi_handler_cfg *) current;
	fastcgi_handler_cfg *cfg = apr_pcalloc(p, sizeof(fastcgi_handler_cfg));

	cfg->idle_timeout = current_cfg->idle_timeout == -1 ?
			parent_cfg->idle_timeout : current_cfg->idle_timeout;

	return cfg;
}

static
const command_rec fastcgi_handler_cmds[] =
{
	{ NULL }
};

static
void fastcgi_handler_register_hooks(apr_pool_t * p)
{
	ap_hook_handler(fastcgi_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA fastcgi_handler_module =
{
	STANDARD20_MODULE_STUFF,
	fastcgi_handler_create_dir_config,
	fastcgi_handler_merge_dir_config,
	NULL,
	NULL,
	fastcgi_handler_cmds,
	fastcgi_handler_register_hooks,
};
