#include <unistd.h>

#include "fcgi_request.h"
#include "fcgi_server.h"

static
int fastcgi_handler(request_rec *r)
{
	fastcgi_handler_cfg *conf = (fastcgi_handler_cfg *)
		ap_get_module_config(r->per_dir_config, &fastcgi_handler_module);
	const char *action;

	action = r->handler;
	if (!action || strncmp(action, "fcgi:", 5)) {
		const char *type;
		type = ap_field_noparam(r->pool, r->content_type);
		if (type)
			action = apr_table_get(conf->action_types, type);
		if (!action || strncmp(action, "fcgi:", 5))
			return DECLINED;
	}

	fcgi_request_t *fr = NULL;
	int ret;

	/* Step 1: create a new FastCGI request object */
	if ((ret = fcgi_request_create(r, action+5, &fr)) != OK) {
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
	cfg->action_types = apr_table_make(p, 4);

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

	cfg->action_types = apr_table_overlay(p, current_cfg->action_types,
					      parent_cfg->action_types);

	return cfg;
}

static
const char *add_action(cmd_parms *cmd, void *m_v,
                              const char *type, const char *script)
{
	fastcgi_handler_cfg *cfg = (fastcgi_handler_cfg *)m_v;

	apr_table_setn(cfg->action_types, type, script);

	return NULL;
}

static
const command_rec fastcgi_handler_cmds[] =
{
	AP_INIT_TAKE2("FcgiAction", add_action, NULL, RSRC_CONF,
		       "a media type followed by a fcgi:socket"),
	{ NULL }
};

static
void fastcgi_handler_register_hooks(apr_pool_t * p)
{
	ap_hook_handler(fastcgi_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(fastcgi_handler_module) =
{
	STANDARD20_MODULE_STUFF,
	fastcgi_handler_create_dir_config,
	fastcgi_handler_merge_dir_config,
	NULL,
	NULL,
	fastcgi_handler_cmds,
	fastcgi_handler_register_hooks,
};
