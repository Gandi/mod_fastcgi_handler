/*
 * $Id: fcgi_config.c,v 1.50 2004/01/07 01:56:00 robs Exp $
 */

#define CORE_PRIVATE
#include "fcgi.h"


#include <limits.h>
#include "mpm_common.h"     /* ap_uname2id, ap_gname2id */

#include <unistd.h>
#include "unixd.h"



/*******************************************************************************
 * Get the next configuration directive argument, & return an in_addr and port.
 * The arg must be in the form "host:port" where host can be an IP or hostname.
 * The pool arg should be persistant storage.
 */
static const char *get_host_n_port(pool *p, const char **arg,
        const char **host, u_short *port)
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
        return ap_pstrcat(p, "bad port number \"", portStr, "\"", NULL);

    *port = (unsigned short) tmp;

    return NULL;
}

/*******************************************************************************
 * Get the next configuration directive argument, & return an u_int.
 * The pool arg should be temporary storage.
 */
static const char *get_u_int(pool *p, const char **arg,
        u_int *num, u_int min)
{
    char *ptr;
    const char *val = ap_getword_conf(p, arg);

    if (*val == '\0')
        return "\"\"";
    *num = (u_int)strtol(val, &ptr, 10);

    if (*ptr != '\0')
        return ap_pstrcat(p, "\"", val, "\" must be a positive integer", NULL);
    else if (*num < min)
        return ap_psprintf(p, "\"%u\" must be >= %u", *num, min);
    return NULL;
}

static const char *get_pass_header(pool *p, const char **arg, array_header **array)
{
    const char **header;

    if (!*array) {
        *array = ap_make_array(p, 10, sizeof(char*));
    }

    header = (const char **)ap_push_array(*array);
    *header = ap_getword_conf(p, arg);

    return header ? NULL : "\"\"";
}

/*******************************************************************************
 * Return a "standard" message for common configuration errors.
 */
static const char *invalid_value(pool *p, const char *cmd, const char *id,
        const char *opt, const char *err)
{
    return ap_psprintf(p, "%s%s%s: invalid value for %s: %s",
                    cmd, id ? " " : "", id ? id : "",  opt, err);
}

/*******************************************************************************
 * Set/Reset the uid/gid that Apache and the PM will run as.  This is ap_user_id
 * and ap_group_id if we're started as root, and euid/egid otherwise.  Also try
 * to check that the config files don't set the User/Group after a FastCGI
 * directive is used that depends on it.
 */
/*@@@ To be complete, we should save a handle to the server each AppClass is
 * configured in and at init() check that the user/group is still what we
 * thought it was.  Also the other directives should only be allowed in the
 * parent Apache server.
 */
const char *fcgi_config_set_fcgi_uid_n_gid(int set)
{
    static int isSet = 0;

    uid_t uid = geteuid();
    gid_t gid = getegid();

    if (set == 0) {
        isSet = 0;
        fcgi_user_id = (uid_t)-1;
        fcgi_group_id = (gid_t)-1;
        return NULL;
    }

    if (uid == 0) {
        uid = ap_user_id;
    }

    if (gid == 0) {
        gid = ap_group_id;
    }

    if (isSet && (uid != fcgi_user_id || gid != fcgi_group_id)) {
        return "User/Group commands must preceed FastCGI server definitions";
    }

    isSet = 1;
    fcgi_user_id = uid;
    fcgi_group_id = gid;

    return NULL;
}

apr_status_t fcgi_config_reset_globals(void* dummy)
{
    fcgi_servers = NULL;
    fcgi_config_set_fcgi_uid_n_gid(0);

    dynamicAppConnectTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;

    return APR_SUCCESS;
}

/*******************************************************************************
 * Configure a static FastCGI server that is started/managed elsewhere.
 */
const char *fcgi_config_new_external_server(cmd_parms *cmd, void *dummy, const char *arg)
{
    fcgi_server *s;
    pool * const p = cmd->pool, *tp = cmd->temp_pool;
    const char * const name = cmd->cmd->name;
    char *fs_path = ap_getword_conf(p, &arg);
    const char *option, *err;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

    if (!*fs_path) {
        return ap_pstrcat(tp, name, " requires a path and either a -socket or -host option", NULL);
    }

    if (apr_filepath_merge(&fs_path, "", fs_path, 0, p))
        return ap_psprintf(tp, "%s %s: invalid filepath", name, fs_path);

    fs_path = ap_server_root_relative(p, fs_path);

    ap_getparents(fs_path);
    ap_no2slash(fs_path);

    /* See if we've already got one of these bettys configured */
    s = fcgi_util_fs_get_by_id(fs_path);
    if (s != NULL) {
        return ap_psprintf(tp,
            "%s: redefinition of previously defined class \"%s\"", name, fs_path);
    }

    s = fcgi_util_fs_new(p);
    s->fs_path = fs_path;
    s->directive = APP_CLASS_EXTERNAL;

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
        else if (strcasecmp(option, "-user") == 0) {
            s->user = ap_getword_conf(tp, &arg);
            if (*s->user == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
        }
        else if (strcasecmp(option, "-group") == 0) {
            s->group = ap_getword_conf(tp, &arg);
            if (*s->group == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
        }
        else {
            return ap_psprintf(tp, "%s %s: invalid option: %s", name, fs_path, option);
        }
    } /* while */


    if (s->user || s->group)
    {
        ap_log_error(FCGI_LOG_WARN, cmd->server, "FastCGI: there is no "
                     "fastcgi wrapper set, user/group options are ignored");
    }

    /* Require one of -socket or -host, but not both */
    if (s->socket_path != NULL && s->port != 0) {
        return ap_psprintf(tp,
            "%s %s: -host and -socket are mutually exclusive options",
            name, fs_path);
    }
    if (s->socket_path == NULL && s->port == 0) {
        return ap_psprintf(tp,
            "%s %s: -socket or -host option missing", name, fs_path);
    }

    /* Build the appropriate sockaddr structure */
    if (s->port != 0) {
        err = fcgi_util_socket_make_inet_addr(p, (struct sockaddr_in **)&s->socket_addr,
            &s->socket_addr_len, s->host, s->port);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
    } else {

        err = fcgi_util_socket_make_domain_addr(p, (struct sockaddr_un **)&s->socket_addr,
                                  &s->socket_addr_len, s->socket_path);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
    }

    /* Add it to the list of FastCGI servers */
    fcgi_util_fs_add(s);

    return NULL;
}
