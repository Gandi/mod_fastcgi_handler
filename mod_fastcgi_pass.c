#include <unistd.h>

#include "fcgi_request.h"
#include "fcgi_server.h"

static
int fastcgi_pass_handler(request_rec *r)
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
void *fastcgi_pass_create_dir_config(apr_pool_t *p, char *dir)
{
	fastcgi_pass_cfg *cfg = apr_pcalloc(p, sizeof(fastcgi_pass_cfg));

	cfg->idle_timeout = -1;
	cfg->headers = apr_array_make(p, 1, sizeof(char *));

	return cfg;
}

static
void *fastcgi_pass_merge_dir_config(apr_pool_t *p, void *parent, void *current)
{
	fastcgi_pass_cfg *parent_cfg = (fastcgi_pass_cfg *) parent;
	fastcgi_pass_cfg *current_cfg = (fastcgi_pass_cfg *) current;
	fastcgi_pass_cfg *cfg = apr_pcalloc(p, sizeof(fastcgi_pass_cfg));

	cfg->idle_timeout = current_cfg->idle_timeout == -1 ?
			parent_cfg->idle_timeout : current_cfg->idle_timeout;

	cfg->headers = apr_array_append(p, parent_cfg->headers, current_cfg->headers);

	return cfg;
}

static
const char *fastcgi_pass_cmd_pass_header(cmd_parms *cmd, void *mconf,
		const char *arg)
{
	fastcgi_pass_cfg *cfg = (fastcgi_pass_cfg *) mconf;
	*(const char **)apr_array_push(cfg->headers) = arg;
	return NULL;
}

static
const command_rec fastcgi_pass_cmds[] =
{
	AP_INIT_ITERATE("FastCgiPassHeader", fastcgi_pass_cmd_pass_header, NULL,
			OR_FILEINFO, "a list of headers to pass to the FastCGI application."),

	{ NULL }
};

static
void fastcgi_pass_register_hooks(apr_pool_t * p)
{
	ap_hook_handler(fastcgi_pass_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA fastcgi_pass_module =
{
	STANDARD20_MODULE_STUFF,
	fastcgi_pass_create_dir_config,
	fastcgi_pass_merge_dir_config,
	NULL,
	NULL,
	fastcgi_pass_cmds,
	fastcgi_pass_register_hooks,
};
