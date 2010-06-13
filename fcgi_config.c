#include <limits.h>
#include <unistd.h>

#include "mpm_common.h"
#include "unixd.h"

#include "fcgi.h"

/*******************************************************************************
 * Get the next configuration directive argument, & return an in_addr and port.
 * The arg must be in the form "host:port" where host can be an IP or hostname.
 * The pool arg should be persistant storage.
 */
static
const char *get_host_n_port(apr_pool_t *p, const char **arg, const char **host,
		u_short *port)
{
	char *cvptr, *portStr;
	long tmp;

	*host = ap_getword_conf(p, arg);
	if (**host == '\0')
		return "\"\"";

	portStr = strchr(*host, ':');
	if (portStr == NULL)
		return "missing port specification";

	/* Split the host and port portions */
	*portStr++ = '\0';

	/* Convert port number */
	tmp = (u_short) strtol(portStr, &cvptr, 10);
	if (*cvptr != '\0' || tmp < 1 || tmp > USHRT_MAX)
		return apr_pstrcat(p, "bad port number \"", portStr, "\"", NULL);

	*port = (unsigned short) tmp;

	return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return an u_int.
 * The pool arg should be temporary storage.
 */
static
const char *get_u_int(apr_pool_t *p, const char **arg, u_int *num, u_int min)
{
	char *ptr;
	const char *val = ap_getword_conf(p, arg);

	if (*val == '\0')
		return "\"\"";
	*num = (u_int)strtol(val, &ptr, 10);

	if (*ptr != '\0')
		return apr_pstrcat(p, "\"", val, "\" must be a positive integer", NULL);
	else if (*num < min)
		return apr_psprintf(p, "\"%u\" must be >= %u", *num, min);
	return NULL;
}

static
const char *get_pass_header(apr_pool_t *p, const char **arg, apr_array_header_t **array)
{
	const char **header;

	if (!*array) {
		*array = apr_array_make(p, 10, sizeof(char*));
	}

	header = (const char **)apr_array_push(*array);
	*header = ap_getword_conf(p, arg);

	return header ? NULL : "\"\"";
}

/*******************************************************************************
 * Return a "standard" message for common configuration errors.
 */
static
const char *invalid_value(apr_pool_t *p, const char *cmd, const char *id, const char
		*opt, const char *err)
{
	return apr_psprintf(p, "%s%s%s: invalid value for %s: %s",
			cmd, id ? " " : "", id ? id : "",  opt, err);
}

apr_status_t fcgi_config_reset_globals(void *dummy)
{
	fcgi_servers = NULL;
	return APR_SUCCESS;
}

/*******************************************************************************
 * Configure a static FastCGI server that is started/managed elsewhere.
 */
const char *fcgi_config_new_external_server(cmd_parms *cmd, void *dummy, const char *arg)
{
	fcgi_server *s;
	apr_pool_t * const p = cmd->pool, *tp = cmd->temp_pool;
	const char * const name = cmd->cmd->name;
	const char *option, *err;

	if ((err = ap_check_cmd_context(cmd, GLOBAL_ONLY))) {
		return err;
	}

	char *fs_path = ap_getword_conf(p, &arg);

	if (!*fs_path) {
		return apr_pstrcat(tp, name, " requires a path and either a -socket or -host option", NULL);
	}

	if (apr_filepath_merge(&fs_path, "", fs_path, 0, p))
		return apr_psprintf(tp, "%s %s: invalid filepath", name, fs_path);

	fs_path = ap_server_root_relative(p, fs_path);

	ap_getparents(fs_path);
	ap_no2slash(fs_path);

	/* See if we've already got one of these bettys configured */
	s = fcgi_util_fs_get_by_id(fs_path);
	if (s != NULL) {
		return apr_psprintf(tp,
				"%s: redefinition of previously defined class \"%s\"", name, fs_path);
	}

	s = fcgi_util_fs_new(p);
	s->fs_path = fs_path;

	/*  Parse directive arguments */
	while (*arg != '\0') {
		option = ap_getword_conf(tp, &arg);

		if (strcasecmp(option, "-host") == 0) {
			if ((err = get_host_n_port(p, &arg, &s->host, &s->port)))
				return invalid_value(tp, name, fs_path, option, err);
		}

		else if (strcasecmp(option, "-socket") == 0) {
			s->socket_path = ap_getword_conf(tp, &arg);
			if (*s->socket_path == '\0')
				return invalid_value(tp, name, fs_path, option, "\"\"");
		}

		else if (strcasecmp(option, "-appConnTimeout") == 0) {
			if ((err = get_u_int(tp, &arg, &s->appConnectTimeout, 0)))
				return invalid_value(tp, name, fs_path, option, err);
		}

		else if (strcasecmp(option, "-idle-timeout") == 0) {
			if ((err = get_u_int(tp, &arg, &s->idle_timeout, 1)))
				return invalid_value(tp, name, fs_path, option, err);
		}

		else if (strcasecmp(option, "-pass-header") == 0) {
			if ((err = get_pass_header(p, &arg, &s->pass_headers)))
				return invalid_value(tp, name, fs_path, option, err);
		}

		else if (strcasecmp(option, "-flush") == 0) {
			s->flush = 1;
		}

		else {
			return apr_psprintf(tp, "%s %s: invalid option: %s", name, fs_path, option);
		}
	}

	/* Require one of -socket or -host, but not both */
	if (s->socket_path != NULL && s->port != 0) {
		return apr_psprintf(tp,
				"%s %s: -host and -socket are mutually exclusive options",
				name, fs_path);
	}

	if (s->socket_path == NULL && s->port == 0) {
		return apr_psprintf(tp,
				"%s %s: -socket or -host option missing", name, fs_path);
	}

	/* Build the appropriate sockaddr structure */
	if (s->port != 0) {
		err = fcgi_util_socket_make_inet_addr(p, (struct sockaddr_in **)&s->socket_addr,
				&s->socket_addr_len, s->host, s->port);
		if (err != NULL)
			return apr_psprintf(tp, "%s %s: %s", name, fs_path, err);
	} else {
		err = fcgi_util_socket_make_domain_addr(p, (struct sockaddr_un **)&s->socket_addr,
				&s->socket_addr_len, s->socket_path);
		if (err != NULL)
			return apr_psprintf(tp, "%s %s: %s", name, fs_path, err);
	}

	/* Add it to the list of FastCGI servers */
	fcgi_util_fs_add(s);

	return NULL;
}
