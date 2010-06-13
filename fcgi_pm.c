/*
 * $Id: fcgi_pm.c,v 1.93 2004/04/15 02:01:26 robs Exp $
 */


#include "fcgi.h"

#include <pwd.h>
#include <unistd.h>
#include "unixd.h"
#include "apr_signal.h"

#include <utime.h>

#ifdef _HPUX_SOURCE
#include <unistd.h>
#define seteuid(arg) setresuid(-1, (arg), -1)
#endif

int fcgi_dynamic_total_proc_count = 0;    /* number of running apps */
time_t fcgi_dynamic_epoch = 0;            /* last time kill_procs was
                                           * invoked by process mgr */
time_t fcgi_dynamic_last_analyzed = 0;    /* last time calculation was
                                           * made for the dynamic procs */

static time_t now = 0;



static int seteuid_root(void)
{
    int rc = seteuid(getuid());
    if (rc) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: seteuid(0) failed");
    }
    return rc;
}

static int seteuid_user(void)
{
    int rc = seteuid(ap_user_id);
    if (rc) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: seteuid(%u) failed", (unsigned)ap_user_id);
    }
    return rc;
}

/*
 * Signal the process to exit.  How (or if) the process responds
 * depends on the FastCGI application library (esp. on Win32) and
 * possibly application code (signal handlers and whether or not
 * SA_RESTART is on).  At any rate, we send the signal with the
 * hopes that the process will exit on its own.  Later, as we 
 * review the state of application processes, if we see one marked 
 * for death, but that hasn't died within a specified period of
 * time, fcgi_kill() is called again with a KILL)
 */
static void fcgi_kill(ServerProcess *process, int sig)
{
    FCGIDBG3("fcgi_kill(%ld, %d)", (long) process->pid, sig);

    process->state = FCGI_VICTIM_STATE;                


    if (fcgi_wrapper) 
    {
        seteuid_root();
    }

    kill(process->pid, sig);

    if (fcgi_wrapper) 
    {
        seteuid_user();
    }

}

/*******************************************************************************
 * Send SIGTERM to each process in the server class, remove socket
 * file if appropriate.  Currently this is only called when the PM is shutting
 * down and thus memory isn't freed and sockets and files aren't closed.
 */
static void shutdown_all()
{
    fcgi_server *s = fcgi_servers;
    
    while (s) 
    {
        ServerProcess *proc = s->procs;
        int i;
        int numChildren = (s->directive == APP_CLASS_DYNAMIC)
            ? dynamicMaxClassProcs
            : s->numProcesses;
        
        if (s->socket_path != NULL && s->directive != APP_CLASS_EXTERNAL) 
        {
            /* Remove the socket file */
            if (unlink(s->socket_path) != 0 && errno != ENOENT) {
                ap_log_error(FCGI_LOG_ERR, fcgi_apache_main_server,
                    "FastCGI: unlink() failed to remove socket file \"%s\" for%s server \"%s\"",
                    s->socket_path,
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "", s->fs_path);
            }
        }

        /* Send TERM to all processes */
        for (i = 0; i < numChildren; i++, proc++) 
        {
            if (proc->state == FCGI_RUNNING_STATE) 
            {
                fcgi_kill(proc, SIGTERM);
            }
        }
        
        s = s->next;
    }
}

static int init_listen_sock(fcgi_server * fs)
{
    ap_assert(fs->directive != APP_CLASS_EXTERNAL);

    /* Create the socket */
    if ((fs->listenFd = socket(fs->socket_addr->sa_family, SOCK_STREAM, 0)) < 0) 
    {
        ap_log_error(FCGI_LOG_CRIT_ERRNO, fcgi_apache_main_server,
            "FastCGI: can't create %sserver \"%s\": socket() failed", 
            (fs->directive == APP_CLASS_DYNAMIC) ? "(dynamic) " : "",
            fs->fs_path);
        return -1;
    }

    if (fs->socket_addr->sa_family == AF_UNIX) 
    {
        /* Remove any existing socket file.. just in case */
        unlink(((struct sockaddr_un *)fs->socket_addr)->sun_path);
    }
    else 
    {
        int flag = 1;
        setsockopt(fs->listenFd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));
    }

    /* Bind it to the socket_addr */
    if (bind(fs->listenFd, fs->socket_addr, fs->socket_addr_len))
    {
        char port[11];

        ap_snprintf(port, sizeof(port), "port=%d", 
            ((struct sockaddr_in *)fs->socket_addr)->sin_port);

        ap_log_error(FCGI_LOG_CRIT_ERRNO, fcgi_apache_main_server,
            "FastCGI: can't create %sserver \"%s\": bind() failed [%s]", 
            (fs->directive == APP_CLASS_DYNAMIC) ? "(dynamic) " : "",
            fs->fs_path,
            (fs->socket_addr->sa_family == AF_UNIX) ?
                ((struct sockaddr_un *)fs->socket_addr)->sun_path :
                port);
    }

    /* Twiddle Unix socket permissions */
    else if (fs->socket_addr->sa_family == AF_UNIX
        && chmod(((struct sockaddr_un *)fs->socket_addr)->sun_path, S_IRUSR | S_IWUSR))
    {
        ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
            "FastCGI: can't create %sserver \"%s\": chmod() of socket failed", 
            (fs->directive == APP_CLASS_DYNAMIC) ? "(dynamic) " : "",
            fs->fs_path);
    }

    /* Set to listen */
    else if (listen(fs->listenFd, fs->listenQueueDepth))
    {
        ap_log_error(FCGI_LOG_CRIT_ERRNO, fcgi_apache_main_server,
            "FastCGI: can't create %sserver \"%s\": listen() failed", 
            (fs->directive == APP_CLASS_DYNAMIC) ? "(dynamic) " : "",
            fs->fs_path);
    }
    else
    {
        return 0;
    }

    close(fs->listenFd);

    fs->listenFd = -1;
    
    return -2;
}

/*
 *----------------------------------------------------------------------
 *
 * pm_main
 *
 *      The FastCGI process manager, which runs as a separate
 *      process responsible for:
 *        - Starting all the FastCGI proceses.
 *        - Restarting any of these processes that die (indicated
 *          by SIGCHLD).
 *        - Catching SIGTERM and relaying it to all the FastCGI
 *          processes before exiting.
 *
 * Inputs:
 *      Uses global variable fcgi_servers.
 *
 * Results:
 *      Does not return.
 *
 * Side effects:
 *      Described above.
 *
 *----------------------------------------------------------------------
 */
static int caughtSigTerm = FALSE;
static int caughtSigChld = FALSE;
static int caughtSigAlarm = FALSE;

static void signal_handler(int signo)
{
    if ((signo == SIGTERM) || (signo == SIGUSR1) || (signo == SIGHUP)) {
        /* SIGUSR1 & SIGHUP are sent by apache to its process group
         * when apache get 'em.  Apache follows up (1.2.x) with attacks
         * on each of its child processes, but we've got the KillMgr
         * sitting between us so we never see the KILL.  The main loop
         * in ProcMgr also checks to see if the KillMgr has terminated,
         * and if it has, we handl it as if we should shutdown too. */
        caughtSigTerm = TRUE;
    } else if(signo == SIGCHLD) {
        caughtSigChld = TRUE;
    } else if(signo == SIGALRM) {
        caughtSigAlarm = TRUE;
    }
}

/*
 *----------------------------------------------------------------------
 *
 * spawn_fs_process --
 *
 *      Fork and exec the specified fcgi process.
 *
 * Results:
 *      0 for successful fork, -1 for failed fork.
 *
 *      In case the child fails before or in the exec, the child
 *      obtains the error log by calling getErrLog, logs
 *      the error, and exits with exit status = errno of
 *      the failed system call.
 *
 * Side effects:
 *      Child process created.
 *
 *----------------------------------------------------------------------
 */
static pid_t spawn_fs_process(fcgi_server *fs, ServerProcess *process)
{

    pid_t child_pid;
    int i;
    char *dirName;
    char *dnEnd, *failedSysCall;

    child_pid = fork();
    if (child_pid) {
        return child_pid;
    }

    /* We're the child.  We're gonna exec() so pools don't matter. */

    dnEnd = strrchr(fs->fs_path, '/');
    if (dnEnd == NULL) {
        dirName = "./";
    } else {
        dirName = ap_pcalloc(fcgi_config_pool, dnEnd - fs->fs_path + 1);
        dirName = memcpy(dirName, fs->fs_path, dnEnd - fs->fs_path);
    }
    if (chdir(dirName) < 0) {
        failedSysCall = "chdir()";
        goto FailedSystemCallExit;
    }

#ifndef __EMX__
     /* OS/2 dosen't support nice() */
    if (fs->processPriority != 0) {
        if (nice(fs->processPriority) == -1) {
            failedSysCall = "nice()";
            goto FailedSystemCallExit;
        }
    }
#endif

    /* Open the listenFd on spec'd fd */
    if (fs->listenFd != FCGI_LISTENSOCK_FILENO)
        dup2(fs->listenFd, FCGI_LISTENSOCK_FILENO);

    /* Close all other open fds, except stdout/stderr.  Leave these two open so
     * FastCGI applications don't have to find and fix ALL 3rd party libs that
     * write to stdout/stderr inadvertantly.  For now, just leave 'em open to the
     * main server error_log - @@@ provide a directive control where this goes.
     */
    ap_error_log2stderr(fcgi_apache_main_server);
    dup2(2, 1);
    for (i = 0; i < FCGI_MAX_FD; i++) {
        if (i != FCGI_LISTENSOCK_FILENO && i != 2 && i != 1) {
            close(i);
        }
    }

    /* Ignore SIGPIPE by default rather than terminate.  The fs SHOULD
     * install its own handler. */
    signal(SIGPIPE, SIG_IGN);

    if (fcgi_wrapper)
    {
        char *shortName;

        /* Relinquish our root real uid powers */
        seteuid_root();
        setuid(ap_user_id);

        /* Apache (2 anyway) doesn't use suexec if there is no user/group in
         * effect - this translates to a uid/gid of 0/0 (which should never
         * be a valid uid/gid for an suexec invocation so it should be safe */
        if (fs->uid == 0 && fs->gid == 0) {
            goto NO_SUEXEC;
        }

#ifdef NO_SUEXEC_FOR_AP_USER_N_GROUP

        /* AP13 does not use suexec if the target uid/gid is the same as the 
         * server's - AP20 does.  I (now) consider the AP2 approach better
         * (fcgi_pm.c v1.42 incorporated the 1.3 behaviour, v1.84 reverted it,
         * v1.85 added the compile time option to use the old behaviour). */
        if (fcgi_user_id == fs->uid && fcgi_group_id == fs->gid) {
            goto NO_SUEXEC;
        }

#endif
        shortName = strrchr(fs->fs_path, '/') + 1;

        do {
            execle(fcgi_wrapper, fcgi_wrapper, fs->username, fs->group,
                   shortName, NULL, fs->envp);
        } while (errno == EINTR);
    }
    else 
    {
NO_SUEXEC:
        do {
            execle(fs->fs_path, fs->fs_path, NULL, fs->envp);
        } while (errno == EINTR);
    }

    failedSysCall = "execle()";

FailedSystemCallExit:
    fprintf(stderr, "FastCGI: can't start server \"%s\" (pid %ld), %s failed: %s\n",
        fs->fs_path, (long) getpid(), failedSysCall, strerror(errno));
    exit(-1);

    /* avoid an irrelevant compiler warning */
    return(0);

}

static void reduce_privileges(void)
{
    const char *name;

    if (geteuid() != 0)
        return;

#ifndef __EMX__
    /* Get username if passed as a uid */
    if (ap_user_name[0] == '#') {
        uid_t uid = atoi(&ap_user_name[1]);
        struct passwd *ent = getpwuid(uid);

        if (ent == NULL) {
            ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
                "FastCGI: process manager exiting, getpwuid(%u) couldn't determine user name, "
                "you probably need to modify the User directive", (unsigned)uid);
            exit(1);
        }
        name = ent->pw_name;
    }
    else
        name = ap_user_name;

    /* Change Group */
    if (setgid(ap_group_id) == -1) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: process manager exiting, setgid(%u) failed", (unsigned)ap_group_id);
        exit(1);
    }

    /* See Apache PR2580. Until its resolved, do it the same way CGI is done.. */

    /* Initialize supplementary groups */
    if (initgroups(name, ap_group_id) == -1) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
            "FastCGI: process manager exiting, initgroups(%s,%u) failed",
            name, (unsigned)ap_group_id);
        exit(1);
    }
#endif /* __EMX__ */

    /* Change User */
    if (fcgi_wrapper) {
        if (seteuid_user() == -1) {
            ap_log_error(FCGI_LOG_ALERT_NOERRNO, fcgi_apache_main_server,
                "FastCGI: process manager exiting, failed to reduce privileges");
            exit(1);
        }
    }
    else {
        if (setuid(ap_user_id) == -1) {
            ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
                "FastCGI: process manager exiting, setuid(%u) failed", (unsigned)ap_user_id);
            exit(1);
        }
    }
}

/*************
 * Change the name of this process - best we can easily.
 */
static void change_process_name(const char * const name)
{
    /* under Apache2, ap_server_argv0 is const */
    strncpy((char *) ap_server_argv0, name, strlen(ap_server_argv0));
}

static void schedule_start(fcgi_server *s, int proc)
{
    /* If we've started one recently, don't register another */
    time_t time_passed = now - s->restartTime;

    if ((s->procs[proc].pid && (time_passed < (int) s->restartDelay))
        || ((s->procs[proc].pid == 0) && (time_passed < s->initStartDelay)))
    {
        FCGIDBG6("ignore_job: slot=%d, pid=%ld, time_passed=%ld, initStartDelay=%ld, restartDelay=%ld", proc, (long) s->procs[proc].pid, time_passed, s->initStartDelay, s->restartDelay);
        return;
    }

    FCGIDBG3("scheduling_start: %s (%d)", s->fs_path, proc);
    s->procs[proc].state = FCGI_START_STATE;
    if (proc == dynamicMaxClassProcs - 1) {
        ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
            "FastCGI: scheduled the %sstart of the last (dynamic) server "
            "\"%s\" process: reached dynamicMaxClassProcs (%d)",
            s->procs[proc].pid ? "re" : "", s->fs_path, dynamicMaxClassProcs);
    }
}

/*
 *----------------------------------------------------------------------
 *
 * dynamic_read_msgs
 *
 *      Removes the records written by request handlers and decodes them.
 *      We also update the data structures to reflect the changes.
 *
 *----------------------------------------------------------------------
 */

static void dynamic_read_msgs(int read_ready)
{
    fcgi_server *s;
    int rc;

    static int buflen = 0;
    static char buf[FCGI_MSGS_BUFSIZE + 1];
    char *ptr1, *ptr2, opcode;
    char execName[FCGI_MAXPATH + 1];
    char user[MAX_USER_NAME_LEN + 2];
    char group[MAX_GID_CHAR_LEN + 1];
    unsigned long q_usec = 0UL, req_usec = 0UL;

    pool *sp = NULL, *tp;

    user[MAX_USER_NAME_LEN + 1] = group[MAX_GID_CHAR_LEN] = '\0';

    /*
     * To prevent the idle application from running indefinitely, we
     * check the timer and if it is expired, we recompute the values
     * for each running application class.  Then, when FCGI_REQUEST_COMPLETE_JOB
     * message is received, only updates are made to the data structures.
     */
    if (fcgi_dynamic_last_analyzed == 0) {
        fcgi_dynamic_last_analyzed = now;
    }
    if ((now - fcgi_dynamic_last_analyzed) >= (int)dynamicUpdateInterval) {
        for (s = fcgi_servers; s != NULL; s = s->next) {
            if (s->directive != APP_CLASS_DYNAMIC)
                break;

            /* Advance the last analyzed timestamp by the elapsed time since
             * it was last set. Round the increase down to the nearest
             * multiple of dynamicUpdateInterval */

            fcgi_dynamic_last_analyzed += (((long)(now-fcgi_dynamic_last_analyzed)/dynamicUpdateInterval)*dynamicUpdateInterval);
            s->smoothConnTime = (unsigned long) ((1.0-dynamicGain)*s->smoothConnTime + dynamicGain*s->totalConnTime);
            s->totalConnTime = 0UL;
            s->totalQueueTime = 0UL;
        }
    }

    if (read_ready <= 0) {
        return;
    }
    
    rc = read(fcgi_pm_pipe[0], (void *)(buf + buflen), FCGI_MSGS_BUFSIZE - buflen);
    if (rc <= 0) {
        if (!caughtSigTerm) {
            ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server, 
                "FastCGI: read() from pipe failed (%d)", rc);
            if (rc == 0) {
                ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server, 
                    "FastCGI: the PM is shutting down, Apache seems to have disappeared - bye");
                caughtSigTerm = TRUE;
            }
        }
        return;
    }
    buflen += rc;
    buf[buflen] = '\0';


    apr_pool_create(&tp, fcgi_config_pool);

    for (ptr1 = buf; ptr1; ptr1 = ptr2) {
        int scan_failed = 0;

        ptr2 = strchr(ptr1, '*');
        if (ptr2) {
            *ptr2++ = '\0';
        }
        else {
            break;
        }
        
        opcode = *ptr1;

        switch (opcode) 
        {
        case FCGI_SERVER_START_JOB:
        case FCGI_SERVER_RESTART_JOB:

            if (sscanf(ptr1, "%c %s %16s %15s",
                &opcode, execName, user, group) != 4)
            {
                scan_failed = 1;
            }
            break;

        case FCGI_REQUEST_TIMEOUT_JOB:

            if (sscanf(ptr1, "%c %s %16s %15s",
                &opcode, execName, user, group) != 4)
            {
                scan_failed = 1;
            }
            break;

        case FCGI_REQUEST_COMPLETE_JOB:

            if (sscanf(ptr1, "%c %s %16s %15s %lu %lu",
                &opcode, execName, user, group, &q_usec, &req_usec) != 6)
            {
                scan_failed = 1;
            }
            break;

        default:

            scan_failed = 1;
            break;
        }

	FCGIDBG7("read_job: %c %s %s %s %lu %lu", opcode, execName, user, group, q_usec, req_usec);

        if (scan_failed) {
            ap_log_error(FCGI_LOG_ERR_NOERRNO, fcgi_apache_main_server,
                "FastCGI: bogus message, sscanf() failed: \"%s\"", ptr1);
            goto NextJob;
        }

        s = fcgi_util_fs_get(execName, user, group);

        if (s==NULL && opcode != FCGI_REQUEST_COMPLETE_JOB)
        {
            const char *err;
            
            /* Create a perm subpool to hold the new server data,
             * we can destroy it if something doesn't pan out */
            apr_pool_create(&sp, fcgi_config_pool);

            /* Create a new "dynamic" server */
            s = fcgi_util_fs_new(sp);

            s->directive = APP_CLASS_DYNAMIC;
            s->restartDelay = dynamicRestartDelay;
            s->listenQueueDepth = dynamicListenQueueDepth;
            s->initStartDelay = dynamicInitStartDelay;
            s->envp = dynamicEnvp;
            s->flush = dynamicFlush;
            
            s->fs_path = ap_pstrdup(sp, execName);
            ap_getparents(s->fs_path);
            ap_no2slash(s->fs_path);
            s->procs = fcgi_util_fs_create_procs(sp, dynamicMaxClassProcs);

            /* XXX the socket_path (both Unix and Win) *is* deducible and
             * thus can and will be used by other apache instances without
             * the use of shared data regarding the processes serving the 
             * requests.  This can result in slightly unintuitive process
             * counts and security implications.  This is prevented
             * if suexec (Unix) is in use.  This is both a feature and a flaw.
             * Changing it now would break existing installations. */

            /* Create socket file's path */
            s->socket_path = fcgi_util_socket_hash_filename(tp, execName, user, group);
            s->socket_path = fcgi_util_socket_make_path_absolute(sp, s->socket_path, 1);

            /* Create sockaddr, prealloc it so it won't get created in tp */
            s->socket_addr = ap_pcalloc(sp, sizeof(struct sockaddr_un));
            err = fcgi_util_socket_make_domain_addr(tp, (struct sockaddr_un **)&s->socket_addr,
                                          &s->socket_addr_len, s->socket_path);
            if (err) {
                ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                    "FastCGI: can't create (dynamic) server \"%s\": %s", execName, err);
                goto BagNewServer;
            }

            if (init_listen_sock(s)) {
                goto BagNewServer;
            }

            /* If a wrapper is being used, config user/group info */
            if (fcgi_wrapper) {
                if (user[0] == '~') {
                    /* its a user dir uri, the rest is a username, not a uid */
                    struct passwd *pw = getpwnam(&user[1]);

                    if (!pw) {
                        ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                            "FastCGI: can't create (dynamic) server \"%s\": can't get uid/gid for wrapper: getpwnam(%s) failed",
                            execName, &user[1]);
                        goto BagNewServer;
                    }
                    s->uid = pw->pw_uid;
                    s->user = ap_pstrdup(sp, user);
                    s->username = s->user;

                    s->gid = pw->pw_gid;
                    s->group = ap_psprintf(sp, "%ld", (long)s->gid);
                }
                else {
                    struct passwd *pw;

                    s->uid = (uid_t)atol(user);
                    pw = getpwuid(s->uid);
                    if (!pw) {
                        ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                            "FastCGI: can't create (dynamic) server \"%s\": can't get uid/gid for wrapper: getwpuid(%ld) failed",
                            execName, (long)s->uid);
                        goto BagNewServer;
                    }
                    s->user = ap_pstrdup(sp, user);
                    s->username = ap_pstrdup(sp, pw->pw_name);

                    s->gid = (gid_t)atol(group);
                    s->group = ap_pstrdup(sp, group);
                }
            }

            fcgi_util_fs_add(s);
        }
        else {
            if (opcode == FCGI_SERVER_RESTART_JOB) {
                /* Check to see if the binary has changed.  If so,
                * kill the FCGI application processes, and
                * restart them.
                */
                struct stat stbuf;
                int i;
                char * app_path = execName;

                if (stat(app_path, &stbuf) == 0 && stbuf.st_mtime > s->startTime)
                {
                    int do_restart = 0;

                    /* prevent addition restart requests */
                    s->startTime = now;
                    utime(s->socket_path, NULL);

                    /* kill old server(s) */
                    for (i = 0; i < dynamicMaxClassProcs; i++) 
                    {
                        if (s->procs[i].pid > 0 
                            && stbuf.st_mtime > s->procs[i].start_time) 
                        {
                            fcgi_kill(&s->procs[i], SIGTERM);
                            do_restart++;
                        }
                    }

                    if (do_restart)
                    {
                        ap_log_error(FCGI_LOG_WARN_NOERRNO, 
                            fcgi_apache_main_server, "FastCGI: restarting "
                            "old server \"%s\" processes, newer version "
                            "found", app_path);
                    }
                }

                /* If dynamicAutoRestart, don't mark any new processes
                 * for  starting because we probably got the
                 * FCGI_SERVER_START_JOB due to dynamicAutoUpdate and the ProcMgr
                 * will be restarting all of those we just killed.
                 */
                if (dynamicAutoRestart)
                    goto NextJob;
            } 
            else if (opcode == FCGI_SERVER_START_JOB) {
                /* we've been asked to start a process--only start
                * it if we're not already running at least one
                * instance.
                */
                int i;

                for (i = 0; i < dynamicMaxClassProcs; i++) {
                   if (s->procs[i].state == FCGI_RUNNING_STATE)
                      break;
                }
                /* if already running, don't start another one */
                if (i < dynamicMaxClassProcs) {
                    goto NextJob;
                }
            }
        }

        switch (opcode)
        {
            int i, start;

            case FCGI_SERVER_RESTART_JOB:

                start = FALSE;
                
                /* We just waxed 'em all.  Try to find an idle slot. */

                for (i = 0; i < dynamicMaxClassProcs; ++i)
                {
                    if (s->procs[i].state == FCGI_START_STATE
                        || s->procs[i].state == FCGI_RUNNING_STATE)
                    {
                        break;
                    }
                    else if (s->procs[i].state == FCGI_KILLED_STATE 
                        || s->procs[i].state == FCGI_READY_STATE)
                    {
                        start = TRUE;
                        break;
                    }
                }

                /* Nope, just use the first slot */
                if (i == dynamicMaxClassProcs)
                {
                    start = TRUE;
                    i = 0;
                }
                
                if (start)
                {
                    schedule_start(s, i);
                }
                        
                break;

            case FCGI_SERVER_START_JOB:
            case FCGI_REQUEST_TIMEOUT_JOB:

                if ((fcgi_dynamic_total_proc_count + 1) > (int) dynamicMaxProcs) {
                    /*
                     * Extra instances should have been
                     * terminated beforehand, probably need
                     * to increase ProcessSlack parameter
                     */
                    ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                        "FastCGI: can't schedule the start of another (dynamic) server \"%s\" process: "
                        "exceeded dynamicMaxProcs (%d)", s->fs_path, dynamicMaxProcs);
                    goto NextJob;
                }

                /* find next free slot */
                for (i = 0; i < dynamicMaxClassProcs; i++) 
                {
                    if (s->procs[i].state == FCGI_START_STATE) 
                    {
                        FCGIDBG2("ignore_job: slot (%d) is already scheduled for starting", i);
                        break;
                    }
                    else if (s->procs[i].state == FCGI_RUNNING_STATE)
                    {
                        continue;
                    }
                        
                    schedule_start(s, i);
                    break;
                }

#ifdef FCGI_DEBUG
                if (i >= dynamicMaxClassProcs) {
                    FCGIDBG1("ignore_job: slots are max'd");
                }
#endif
                break;
            case FCGI_REQUEST_COMPLETE_JOB:
                /* only record stats if we have a structure */
                if (s) {
                    s->totalConnTime += req_usec;
                    s->totalQueueTime += q_usec;
                }
                break;
        }

NextJob:


        continue;

BagNewServer:
        if (sp) ap_destroy_pool(sp);

    }

    if (ptr1 == buf) {
        ap_log_error(FCGI_LOG_ERR_NOERRNO, fcgi_apache_main_server,
            "FastCGI: really bogus message: \"%s\"", ptr1);
        ptr1 += strlen(buf);
    }
            
    buflen -= ptr1 - buf;
    if (buflen) {
        memmove(buf, ptr1, buflen);
    }

    ap_destroy_pool(tp);
}

/*
 *----------------------------------------------------------------------
 *
 * dynamic_kill_idle_fs_procs
 *
 *      Implement a kill policy for the dynamic FastCGI applications.
 *      We also update the data structures to reflect the changes.
 *
 * Side effects:
 *      Processes are marked for deletion possibly killed.
 *
 *----------------------------------------------------------------------
 */
static void dynamic_kill_idle_fs_procs(void)
{
    fcgi_server *s;
    int victims = 0;

    for (s = fcgi_servers;  s != NULL; s = s->next) 
    {
        /* 
         * server's smoothed running time, or if that's 0, the current total 
         */
        unsigned long connTime;  
        
        /* 
         * maximum number of microseconds that all of a server's running 
         * processes together could have spent running since the last check 
         */
        unsigned long totalTime;  

        /* 
         * percentage, 0-100, of totalTime that the processes actually used 
         */
        int loadFactor;        
        
        int i;
        int really_running = 0;
        
        if (s->directive != APP_CLASS_DYNAMIC || s->numProcesses == 0)
        {
            continue;
        }

        /* s->numProcesses includes pending kills so get the "active" count */
        for (i = 0; i < dynamicMaxClassProcs; ++i)
        {
            if (s->procs[i].state == FCGI_RUNNING_STATE) ++really_running;
        }
                
        connTime = s->smoothConnTime ? s->smoothConnTime : s->totalConnTime;
        totalTime = really_running * (now - fcgi_dynamic_epoch) * 1000000 + 1;

        loadFactor = 100 * connTime / totalTime;

        if (really_running == 1)
        {
            if (loadFactor >= dynamicThreshold1)
            {
                continue;
            }
        }
        else
        {
            int load = really_running / ( really_running - 1) * loadFactor;
            
            if (load >= dynamicThresholdN)
            {
                continue;
            }
        }

        /*
         * Run through the procs to see if we can get away w/o waxing one.
         */
        for (i = 0; i < dynamicMaxClassProcs; ++i) 
        {
            if (s->procs[i].state == FCGI_START_STATE) 
            {
                s->procs[i].state = FCGI_READY_STATE;
                break;
            }
            else if (s->procs[i].state == FCGI_VICTIM_STATE) 
            {
                break;
            }
        }

        if (i >= dynamicMaxClassProcs)
        {
            ServerProcess * procs = s->procs;
            int youngest = -1;

            for (i = 0; i < dynamicMaxClassProcs; ++i) 
            {
                if (procs[i].state == FCGI_RUNNING_STATE) 
                {
                    if (youngest == -1 || procs[i].start_time >= procs[youngest].start_time)
                    {
                        youngest = i;
                    }
                }
            }

            if (youngest != -1)
            {
                ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                    "FastCGI: (dynamic) server \"%s\" (pid %ld) termination signaled",
                    s->fs_path, (long) s->procs[youngest].pid);

                fcgi_kill(&s->procs[youngest], SIGTERM);
                
                victims++;
            }

            /* 
             * If the number of non-victims is less than or equal to
             * the minimum that may be running without being killed off,
             * don't select any more victims. 
             */
            if (fcgi_dynamic_total_proc_count - victims <= dynamicMinProcs) 
            {
                break;
            }
        }
    }
}


static void setup_signals(void)
{
    struct sigaction sa;

    /* Setup handlers */

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGTERM) failed");
    }
    /* httpd restart */
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGHUP) failed");
    }
    /* httpd graceful restart */
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGUSR1) failed");
    }
    /* read messages from request handlers - kill interval expired */
    if (sigaction(SIGALRM, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGALRM) failed");
    }
    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        ap_log_error(FCGI_LOG_ALERT, fcgi_apache_main_server,
        "sigaction(SIGCHLD) failed");
    }
}

void fcgi_pm_main(void *dummy)
{
    fcgi_server *s;
    unsigned int i;
    int read_ready = 0;
    int alarmLeft = 0;

    int callWaitPid, callDynamicProcs;


    reduce_privileges();
    change_process_name("fcgi-pm");

    close(fcgi_pm_pipe[1]);
    setup_signals();

    if (fcgi_wrapper) {
        ap_log_error(FCGI_LOG_NOTICE_NOERRNO, fcgi_apache_main_server,
            "FastCGI: wrapper mechanism enabled (wrapper: %s)", fcgi_wrapper);
    }

    /* Initialize AppClass */
    for (s = fcgi_servers; s != NULL; s = s->next) 
    {
        if (s->directive != APP_CLASS_STANDARD)
            continue;


        for (i = 0; i < s->numProcesses; ++i) 
            s->procs[i].state = FCGI_START_STATE;
    }

    ap_log_error(FCGI_LOG_NOTICE_NOERRNO, fcgi_apache_main_server,
        "FastCGI: process manager initialized (pid %ld)", (long) getpid());

    now = time(NULL);

    /*
     * Loop until SIGTERM
     */
    for (;;) {
        int sleepSeconds = min(dynamicKillInterval, dynamicUpdateInterval);
        pid_t childPid;
        int waitStatus;
        unsigned int numChildren;
		unsigned int minServerLife;

        /*
         * If we came out of sigsuspend() for any reason other than
         * SIGALRM, pick up where we left off.
         */
        if (alarmLeft)
            sleepSeconds = alarmLeft;

        /*
         * Examine each configured AppClass for a process that needs
         * starting.  Compute the earliest time when the start should
         * be attempted, starting it now if the time has passed.  Also,
         * remember that we do NOT need to restart externally managed
         * FastCGI applications.
         */
        for (s = fcgi_servers; s != NULL; s = s->next) 
        {
            if (s->directive == APP_CLASS_EXTERNAL)
                continue;

            numChildren = (s->directive == APP_CLASS_DYNAMIC) 
                ? dynamicMaxClassProcs 
                : s->numProcesses;

            minServerLife = (s->directive == APP_CLASS_DYNAMIC) 
                ? dynamicMinServerLife 
                : s->minServerLife;

            for (i = 0; i < numChildren; ++i) 
            {
                if (s->procs[i].pid <= 0 && s->procs[i].state == FCGI_START_STATE)
                {
                    int restart = (s->procs[i].pid < 0);
                    time_t restartTime = s->restartTime;
                    
                    if (s->bad)
                    {
                        /* we've gone to using the badDelay, the only thing that
                           resets bad is when badDelay has expired.  but numFailures
                           is only just set below its threshold.  the proc's 
                           start_times are all reset when the bad is.  the numFailures
                           is reset when we see an app run for a period */

                        s->procs[i].start_time = 0;
                    }
                    
                    if (s->numFailures > MAX_FAILED_STARTS)
                    {
                        time_t last_start_time = s->procs[i].start_time;

                        if (last_start_time && now - last_start_time > minServerLife)
                        {
                            s->bad = 0;
                            s->numFailures = 0;
                            ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                                "FastCGI:%s server \"%s\" has remained"
                                " running for more than %d seconds, its restart"
                                " interval has been restored to %d seconds",
                                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                s->fs_path, minServerLife, s->restartDelay);
                        }
                        else
                        {
                            unsigned int j;

                            for (j = 0; j < numChildren; ++j)
                            {
                                if (s->procs[j].pid <= 0) continue;
                                if (s->procs[j].state != FCGI_RUNNING_STATE) continue;
                                if (s->procs[j].start_time == 0) continue;
                                if (now - s->procs[j].start_time > minServerLife) break;
                            }

                            if (j >= numChildren)
                            {
                                s->bad = 1;
                                ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                                    "FastCGI:%s server \"%s\" has failed to remain"
                                    " running for %d seconds given %d attempts, its restart"
                                    " interval has been backed off to %d seconds",
                                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                    s->fs_path, minServerLife, MAX_FAILED_STARTS,
                                    FAILED_STARTS_DELAY);
                            }
                            else
                            {
                                s->bad = 0;
                                s->numFailures = 0;
                                ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                                    "FastCGI:%s server \"%s\" has remained"
                                    " running for more than %d seconds, its restart"
                                    " interval has been restored to %d seconds",
                                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                    s->fs_path, minServerLife, s->restartDelay);
                            }
                        }
                    }
                    
                    if (s->bad)
                    {
                        restartTime += FAILED_STARTS_DELAY;
                    }
                    else
                    {                   
                        restartTime += (restart) ? s->restartDelay : s->initStartDelay;
                    }

                    if (restartTime <= now) 
                    {
                        if (s->bad) 
                        {
                            s->bad = 0;
                            s->numFailures = MAX_FAILED_STARTS;
                        }

                        if (s->listenFd < 0 && init_listen_sock(s)) 
                        {
                            if (sleepSeconds > s->initStartDelay)
                                sleepSeconds = s->initStartDelay;
                            break;
                        }
                        if (caughtSigTerm) {
                            goto ProcessSigTerm;
                        }
                        s->procs[i].pid = spawn_fs_process(s, &s->procs[i]);
                        if (s->procs[i].pid <= 0) {
                            ap_log_error(FCGI_LOG_CRIT, fcgi_apache_main_server,
                                "FastCGI: can't start%s server \"%s\": spawn_fs_process() failed",
                                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                s->fs_path);

                            sleepSeconds = min(sleepSeconds,
                                max((int) s->restartDelay, FCGI_MIN_EXEC_RETRY_DELAY));

                            s->procs[i].pid = -1;
                            break;
                        }

                        s->procs[i].start_time = now;
                        s->restartTime = now;

                        if (s->startTime == 0) {
                            s->startTime = now;
                        }
                        
                        if (s->directive == APP_CLASS_DYNAMIC) {
                            s->numProcesses++;
                            fcgi_dynamic_total_proc_count++;
                            FCGIDBG2("++ fcgi_dynamic_total_proc_count=%d", fcgi_dynamic_total_proc_count);
                        }

                        s->procs[i].state = FCGI_RUNNING_STATE;

                        if (fcgi_wrapper) {
                            ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                                "FastCGI:%s server \"%s\" (uid %ld, gid %ld) %sstarted (pid %ld)",
                                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                s->fs_path, (long) s->uid, (long) s->gid,
                                restart ? "re" : "", (long) s->procs[i].pid);
                        }
                        else {
                            ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                                "FastCGI:%s server \"%s\" %sstarted (pid %ld)",
                                (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                                s->fs_path, restart ? "re" : "", (long) s->procs[i].pid);
                        }
                        ap_assert(s->procs[i].pid > 0);
                    } else {
                        sleepSeconds = min(sleepSeconds, restartTime - now);
                    }
                }
            }
        }


        if(caughtSigTerm) {
            goto ProcessSigTerm;
        }
        if((!caughtSigChld) && (!caughtSigAlarm)) {
            fd_set rfds;

            alarm(sleepSeconds);

            FD_ZERO(&rfds);
            FD_SET(fcgi_pm_pipe[0], &rfds);
            read_ready = ap_select(fcgi_pm_pipe[0] + 1, &rfds, NULL, NULL, NULL);

            alarmLeft = alarm(0);
        }
        callWaitPid = caughtSigChld;
        caughtSigChld = FALSE;
        callDynamicProcs = caughtSigAlarm;
        caughtSigAlarm = FALSE;

        now = time(NULL);

        /*
         * Dynamic fcgi process management
         */
        if((callDynamicProcs) || (!callWaitPid)) {
            dynamic_read_msgs(read_ready);
            if(fcgi_dynamic_epoch == 0) {
                fcgi_dynamic_epoch = now;
            }
            if(((long)(now-fcgi_dynamic_epoch)>=dynamicKillInterval) ||
                    ((fcgi_dynamic_total_proc_count+dynamicProcessSlack)>=dynamicMaxProcs)) {
                dynamic_kill_idle_fs_procs();
                fcgi_dynamic_epoch = now;
            }
        }

        if(!callWaitPid) {
            continue;
        }

        /* We've caught SIGCHLD, so find out who it was using waitpid,
         * write a log message and update its data structure. */

        for (;;) {
            if (caughtSigTerm)
                goto ProcessSigTerm;

            childPid = waitpid(-1, &waitStatus, WNOHANG);
            
            if (childPid == -1 || childPid == 0)
                break;

            for (s = fcgi_servers; s != NULL; s = s->next) {
                if (s->directive == APP_CLASS_EXTERNAL)
                    continue;

                if (s->directive == APP_CLASS_DYNAMIC)
                    numChildren = dynamicMaxClassProcs;
                else
                    numChildren = s->numProcesses;

                for (i = 0; i < numChildren; i++) {
                    if (s->procs[i].pid == childPid)
                        goto ChildFound;
                }
            }

            /* TODO: print something about this unknown child */
            continue;

ChildFound:
            s->procs[i].pid = -1;

            if (s->directive == APP_CLASS_STANDARD) {
                /* Always restart static apps */
                s->procs[i].state = FCGI_START_STATE;
                if (! (WIFEXITED(waitStatus) && (WEXITSTATUS(waitStatus) == 0))) {
                    /* don't bump the failure count if the app exited with 0 */
                    s->numFailures++;
                }
            }
            else {
                s->numProcesses--;
                fcgi_dynamic_total_proc_count--;

                if (s->procs[i].state == FCGI_VICTIM_STATE) {
                    s->procs[i].state = FCGI_KILLED_STATE;
                }
                else {
                    /* A dynamic app died or exited without provocation from the PM */

                    if (! (WIFEXITED(waitStatus) && (WEXITSTATUS(waitStatus) == 0))) {
                        /* don't bump the failure count if the app exited with 0 */
                        s->numFailures++;
                    }

                    if (dynamicAutoRestart || (s->numProcesses <= 0 && dynamicThreshold1 == 0))
                        s->procs[i].state = FCGI_START_STATE;
                    else
                        s->procs[i].state = FCGI_READY_STATE;
                }
            }

            if (WIFEXITED(waitStatus)) {
                ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                    "FastCGI:%s server \"%s\" (pid %ld) terminated by calling exit with status '%d'",
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                    s->fs_path, (long) childPid, WEXITSTATUS(waitStatus));
            }
            else if (WIFSIGNALED(waitStatus)) {
                ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                    "FastCGI:%s server \"%s\" (pid %ld) terminated due to uncaught signal '%d' (%s)%s",
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                    s->fs_path, (long) childPid, WTERMSIG(waitStatus), get_signal_text(waitStatus),
#ifdef WCOREDUMP
                    WCOREDUMP(waitStatus) ? ", a core file may have been generated" : "");
#else
                    "");
#endif
            }
            else if (WIFSTOPPED(waitStatus)) {
                ap_log_error(FCGI_LOG_WARN_NOERRNO, fcgi_apache_main_server,
                    "FastCGI:%s server \"%s\" (pid %ld) stopped due to uncaught signal '%d' (%s)",
                    (s->directive == APP_CLASS_DYNAMIC) ? " (dynamic)" : "",
                    s->fs_path, (long) childPid, WTERMSIG(waitStatus), get_signal_text(waitStatus));
            }
        } /* for (;;), waitpid() */


    } /* for (;;), the whole shoot'n match */

ProcessSigTerm:
    /*
     * Kill off the children, then exit.
     */
    shutdown_all();

    exit(0);
}

