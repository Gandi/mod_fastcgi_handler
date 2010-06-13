/*
 * $Id: fcgi_config.c,v 1.50 2004/01/07 01:56:00 robs Exp $
 */

#define CORE_PRIVATE
#include "fcgi.h"


#include <limits.h>
#include "mpm_common.h"     /* ap_uname2id, ap_gname2id */

#ifdef WIN32
#include <direct.h>
#else
#include <unistd.h>
#include "unixd.h"
#endif


#ifdef WIN32
/* warning C4100: unreferenced formal parameter */
/* warning C4706: assignment within conditional expression */ 
#pragma warning( disable : 4100 4706 )
#endif

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

const char *fcgi_config_set_env_var(pool *p, char **envp, unsigned int *envc, char * var)
{
    if (*envc >= MAX_INIT_ENV_VARS) {
        return "too many variables, must be <= MAX_INIT_ENV_VARS";
    }

    if (strchr(var, '=') == NULL) {
        *(envp + *envc) = ap_pstrcat(p, var, "=", getenv(var), NULL);
    }
    else {
        *(envp + *envc) = var;
    }

    (*envc)++;

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

#ifndef WIN32

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

#endif /* !WIN32 */

    return NULL;
}

apcb_t fcgi_config_reset_globals(void* dummy)
{
    fcgi_config_pool = NULL;
    fcgi_servers = NULL;
    fcgi_config_set_fcgi_uid_n_gid(0);
    fcgi_wrapper = NULL;
    fcgi_socket_dir = NULL;
    
    fcgi_dynamic_total_proc_count = 0;
    fcgi_dynamic_epoch = 0;
    fcgi_dynamic_last_analyzed = 0;

    dynamicMaxProcs = FCGI_DEFAULT_MAX_PROCS;
    dynamicMinProcs = FCGI_DEFAULT_MIN_PROCS;
    dynamicMaxClassProcs = FCGI_DEFAULT_MAX_CLASS_PROCS;
    dynamicKillInterval = FCGI_DEFAULT_KILL_INTERVAL;
    dynamicUpdateInterval = FCGI_DEFAULT_UPDATE_INTERVAL;
    dynamicGain = FCGI_DEFAULT_GAIN;
    dynamicThreshold1 = FCGI_DEFAULT_THRESHOLD_1;
    dynamicThresholdN = FCGI_DEFAULT_THRESHOLD_N;
    dynamicPleaseStartDelay = FCGI_DEFAULT_START_PROCESS_DELAY;
    dynamicAppConnectTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;
    dynamicEnvp = &fcgi_empty_env;
    dynamicProcessSlack = FCGI_DEFAULT_PROCESS_SLACK;
    dynamicAutoRestart = FCGI_DEFAULT_RESTART_DYNAMIC;
    dynamicAutoUpdate = FCGI_DEFAULT_AUTOUPDATE;
    dynamicListenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
    dynamicInitStartDelay = DEFAULT_INIT_START_DELAY;
    dynamicRestartDelay = FCGI_DEFAULT_RESTART_DELAY;
    dynamicMinServerLife = FCGI_DEFAULT_MIN_SERVER_LIFE;
    dynamic_pass_headers = NULL;
    dynamic_idle_timeout = FCGI_DEFAULT_IDLE_TIMEOUT;
	dynamicFlush = FCGI_FLUSH;

#ifndef WIN32
	/* Close any old pipe (HUP/USR1) */
	if (fcgi_pm_pipe[0] != -1) {
		close(fcgi_pm_pipe[0]);
		fcgi_pm_pipe[0] = -1;
	}
	if (fcgi_pm_pipe[1] != -1) {
		close(fcgi_pm_pipe[1]);
		fcgi_pm_pipe[1] = -1;
	}
#endif

    return APCB_OK;
}

/*******************************************************************************
 * Create a directory to hold Unix/Domain sockets.
 */
const char *fcgi_config_make_dir(pool *tp, char *path)
{
    struct stat finfo;
    const char *err = NULL;

    /* Is the directory spec'd correctly */
    if (*path != '/') {
        return "path is not absolute (it must start with a \"/\")";
    }
    else {
        int i = strlen(path) - 1;

        /* Strip trailing "/"s */
        while(i > 0 && path[i] == '/') path[i--] = '\0';
    }

    /* Does it exist? */
    if (stat(path, &finfo) != 0) {
        /* No, but maybe we can create it */
#ifdef WIN32
        if (mkdir(path) != 0) 
#else
        if (mkdir(path, S_IRWXU) != 0)
#endif
        {
            return ap_psprintf(tp,
                "doesn't exist and can't be created: %s",
                strerror(errno));
        }

#ifndef WIN32
        /* If we're root, we're gonna setuid/setgid so we need to chown */
        if (geteuid() == 0 && chown(path, ap_user_id, ap_group_id) != 0) {
            return ap_psprintf(tp,
                "can't chown() to the server (uid %ld, gid %ld): %s",
                (long)ap_user_id, (long)ap_group_id, strerror(errno));
        }
#endif
    }
    else {
        /* Yes, is it a directory? */
        if (!S_ISDIR(finfo.st_mode))
            return "isn't a directory!";

        /* Can we RWX in there? */
#ifdef WIN32
        err = fcgi_util_check_access(tp, NULL, &finfo, _S_IREAD | _S_IWRITE | _S_IEXEC, fcgi_user_id, fcgi_group_id);
#else
        err = fcgi_util_check_access(tp, NULL, &finfo, R_OK | W_OK | X_OK,
                          fcgi_user_id, fcgi_group_id);
#endif
        if (err != NULL) {
            return ap_psprintf(tp,
                "access for server (uid %ld, gid %ld) failed: %s",
                (long)fcgi_user_id, (long)fcgi_group_id, err);
        }
    }
    return NULL;
}

/*******************************************************************************
 * Create a "dynamic" subdirectory.  If the directory
 * already exists we don't mess with it unless 'wax' is set.
 */
#ifndef WIN32
const char *fcgi_config_make_dynamic_dir(pool *p, const int wax)
{
    const char *err;
    pool *tp;

    fcgi_dynamic_dir = ap_pstrcat(p, fcgi_socket_dir, "/dynamic", NULL);

    if ((err = fcgi_config_make_dir(p, fcgi_dynamic_dir)))
        return ap_psprintf(p, "can't create dynamic directory \"%s\": %s", fcgi_dynamic_dir, err);

    /* Don't step on a running server unless its OK. */
    if (!wax)
        return NULL;

    {
        apr_dir_t * dir;
        apr_finfo_t finfo;

        if (apr_pool_create(&tp, p))
            return "apr_pool_create() failed";

        if (apr_dir_open(&dir, fcgi_dynamic_dir, tp))
            return "apr_dir_open() failed";

        /* delete the contents */

        while (apr_dir_read(&finfo, APR_FINFO_NAME, dir) == APR_SUCCESS)
        {
            if (strcmp(finfo.name, ".") == 0 || strcmp(finfo.name, "..") == 0)
                continue;

            apr_file_remove(finfo.name, tp);
        }
    }


    ap_destroy_pool(tp);

    return NULL;
}
#endif

/*******************************************************************************
 * Change the directory used for the Unix/Domain sockets from the default.
 * Create the directory and the "dynamic" subdirectory.
 */
const char *fcgi_config_set_socket_dir(cmd_parms *cmd, void *dummy, const char *arg)
{
    pool * const tp = cmd->temp_pool;
    const char * const name = cmd->cmd->name;
    const char *err;
    char * arg_nc;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

    if (fcgi_socket_dir) {
        return ap_psprintf(tp, "%s %s: already defined as \"%s\"",
                        name, arg, fcgi_socket_dir);
    }

    err = fcgi_config_set_fcgi_uid_n_gid(1);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg, err);

    if (fcgi_servers != NULL) {
        return ap_psprintf(tp,
            "The %s command must preceed static FastCGI server definitions",
            name);
    }

    arg_nc = ap_pstrdup(cmd->pool, arg);

#ifndef WIN32

    if (apr_filepath_merge(&arg_nc, "", arg, 0, cmd->pool))
        return ap_psprintf(tp, "%s %s: invalid filepath", name, arg);

    arg_nc = ap_server_root_relative(cmd->pool, arg_nc);

#else /* WIN32 */

	if (strncmp(arg_nc, "\\\\.\\pipe\\", 9) != 0)
		return ap_psprintf(tp, "%s %s is invalid format",name, arg_nc);

#endif

    fcgi_socket_dir = arg_nc;

#ifdef WIN32
    fcgi_dynamic_dir = ap_pstrcat(cmd->pool, fcgi_socket_dir, "dynamic", NULL);
#else
    err = fcgi_config_make_dir(tp, fcgi_socket_dir);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg_nc, err);

    err = fcgi_config_make_dynamic_dir(cmd->pool, 0);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg_nc, err);
#endif

    return NULL;
}

/*******************************************************************************
 * Enable, disable, or specify the path to a wrapper used to invoke all
 * FastCGI applications.
 */
const char *fcgi_config_set_wrapper(cmd_parms *cmd, void *dummy, const char *arg)
{
#ifdef WIN32
    return ap_psprintf(cmd->temp_pool, 
        "the %s directive is not supported on WIN", cmd->cmd->name);
#else

    const char *err = NULL;
    const char * const name = cmd->cmd->name;
    pool * const tp = cmd->temp_pool;
    char * wrapper = NULL;

    err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err)
    {
        return err;
    }

    if (fcgi_wrapper)
    {
        return ap_psprintf(tp, "%s was already set to \"%s\"",
                           name, fcgi_wrapper);
    }

    err = fcgi_config_set_fcgi_uid_n_gid(1);
    if (err != NULL)
        return ap_psprintf(tp, "%s %s: %s", name, arg, err);

    if (fcgi_servers != NULL) {
        return ap_psprintf(tp,
            "The %s command must preceed static FastCGI server definitions", name);
    }

    if (strcasecmp(arg, "Off") == 0) {
        fcgi_wrapper = NULL;
        return NULL;
    }

    if (strcasecmp(arg, "On") == 0) 
    {
        wrapper = SUEXEC_BIN;
    }
    else
    {
        if (apr_filepath_merge(&wrapper, "", arg, 0, cmd->pool))
            return ap_psprintf(tp, "%s %s: invalid filepath", name, arg);

        wrapper = ap_server_root_relative(cmd->pool, wrapper);
    }

    err = fcgi_util_check_access(tp, wrapper, NULL, X_OK, fcgi_user_id, fcgi_group_id);
    if (err) 
    {
        return ap_psprintf(tp, "%s: \"%s\" execute access for server "
                           "(uid %ld, gid %ld) failed: %s", name, wrapper,
                           (long) fcgi_user_id, (long) fcgi_group_id, err);
    }

    fcgi_wrapper = wrapper;

    return NULL;
#endif /* !WIN32 */
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
    s = fcgi_util_fs_get_by_id(fs_path, fcgi_util_get_server_uid(cmd->server),
                               fcgi_util_get_server_gid(cmd->server));
    if (s != NULL) {
        if (fcgi_wrapper) {
            return ap_psprintf(tp,
                "%s: redefinition of a previously defined class \"%s\" "
                "with uid=%ld and gid=%ld",
                name, fs_path, (long) fcgi_util_get_server_uid(cmd->server),
                (long) fcgi_util_get_server_gid(cmd->server));
        }
        else 
        {
            return ap_psprintf(tp,
                "%s: redefinition of previously defined class \"%s\"", name, fs_path);
        }
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
#ifdef WIN32
            return ap_psprintf(tp, 
                "%s %s: the -user option isn't supported on WIN", name, fs_path);
#else
            s->user = ap_getword_conf(tp, &arg);
            if (*s->user == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
#endif
        }
        else if (strcasecmp(option, "-group") == 0) {
#ifdef WIN32
            return ap_psprintf(tp, 
                "%s %s: the -group option isn't supported on WIN", name, fs_path);
#else
            s->group = ap_getword_conf(tp, &arg);
            if (*s->group == '\0')
                return invalid_value(tp, name, fs_path, option, "\"\"");
#endif
        }
        else {
            return ap_psprintf(tp, "%s %s: invalid option: %s", name, fs_path, option);
        }
    } /* while */


#ifndef WIN32
    if (fcgi_wrapper)
    {
        if (s->group == NULL)
        {
            s->group = ap_psprintf(tp, "#%ld", fcgi_util_get_server_gid(cmd->server));
        }

        if (s->user == NULL)
        {
            s->user = ap_psprintf(p, "#%ld", fcgi_util_get_server_uid(cmd->server));
        }

        s->uid = ap_uname2id(s->user);
        s->gid = ap_gname2id(s->group);
    }
    else if (s->user || s->group)
    {
        ap_log_error(FCGI_LOG_WARN, cmd->server, "FastCGI: there is no "
                     "fastcgi wrapper set, user/group options are ignored");
    }

    if ((err = fcgi_util_fs_set_uid_n_gid(p, s, s->uid, s->gid)))
    {
        return ap_psprintf(tp,
            "%s %s: invalid user or group: %s", name, fs_path, err);
    }
#endif /* !WIN32 */

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

        if (fcgi_socket_dir == NULL)
        {
#ifdef WIN32
            fcgi_socket_dir = DEFAULT_SOCK_DIR;
#else
            fcgi_socket_dir = ap_server_root_relative(p, DEFAULT_SOCK_DIR);
#endif
        }

        s->socket_path = fcgi_util_socket_make_path_absolute(p, s->socket_path, 0);
#ifndef WIN32
        err = fcgi_util_socket_make_domain_addr(p, (struct sockaddr_un **)&s->socket_addr,
                                  &s->socket_addr_len, s->socket_path);
        if (err != NULL)
            return ap_psprintf(tp, "%s %s: %s", name, fs_path, err);
#endif
    }

    /* Add it to the list of FastCGI servers */
    fcgi_util_fs_add(s);

    return NULL;
}

void *fcgi_config_create_dir_config(pool *p, char *dummy)
{
    fcgi_dir_config *dir_config = ap_pcalloc(p, sizeof(fcgi_dir_config));

    dir_config->authenticator_options = FCGI_AUTHORITATIVE;
    dir_config->authorizer_options = FCGI_AUTHORITATIVE;
    dir_config->access_checker_options = FCGI_AUTHORITATIVE;

    return dir_config;
}
