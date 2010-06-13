/*
 * $Id: fcgi_util.c,v 1.31 2004/01/07 01:56:00 robs Exp $
 */

#include "fcgi.h"

#include <netdb.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#if APR_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "unixd.h"

/*******************************************************************************
 * Build a Domain Socket Address structure, and calculate its size.
 * The error message is allocated from the pool p.  If you don't want the
 * struct sockaddr_un also allocated from p, pass it preallocated (!=NULL).
 */
const char *
fcgi_util_socket_make_domain_addr(pool *p, struct sockaddr_un **socket_addr,
        int *socket_addr_len, const char *socket_path)
{
    int socket_pathLen = strlen(socket_path);

    if (socket_pathLen >= sizeof((*socket_addr)->sun_path)) {
        return ap_pstrcat(p, "path \"", socket_path,
                       "\" is too long for a Domain socket", NULL);
    }

    if (*socket_addr == NULL)
        *socket_addr = ap_pcalloc(p, sizeof(struct sockaddr_un));
    else
        memset(*socket_addr, 0, sizeof(struct sockaddr_un));

    (*socket_addr)->sun_family = AF_UNIX;
    strcpy((*socket_addr)->sun_path, socket_path);

    *socket_addr_len = SUN_LEN(*socket_addr);
    return NULL;
}

/*******************************************************************************
 * Convert a hostname or IP address string to an in_addr struct.
 */
static int
convert_string_to_in_addr(const char * const hostname, struct in_addr * const addr)
{
    struct hostent *hp;
    int count;

    addr->s_addr = inet_addr((char *)hostname);

#if !defined(INADDR_NONE)
#define INADDR_NONE APR_INADDR_NONE
#endif

    if (addr->s_addr == INADDR_NONE) {
        if ((hp = gethostbyname((char *)hostname)) == NULL)
            return -1;

        memcpy((char *) addr, hp->h_addr, hp->h_length);
        count = 0;
        while (hp->h_addr_list[count] != 0)
            count++;

        return count;
    }
    return 1;
}


/*******************************************************************************
 * Build an Inet Socket Address structure, and calculate its size.
 * The error message is allocated from the pool p. If you don't want the
 * struct sockaddr_in also allocated from p, pass it preallocated (!=NULL).
 */
const char *
fcgi_util_socket_make_inet_addr(pool *p, struct sockaddr_in **socket_addr,
        int *socket_addr_len, const char *host, unsigned short port)
{
    if (*socket_addr == NULL)
        *socket_addr = ap_pcalloc(p, sizeof(struct sockaddr_in));
    else
        memset(*socket_addr, 0, sizeof(struct sockaddr_in));

    (*socket_addr)->sin_family = AF_INET;
    (*socket_addr)->sin_port = htons(port);

    /* Get an in_addr represention of the host */
    if (host != NULL) {
        if (convert_string_to_in_addr(host, &(*socket_addr)->sin_addr) != 1) {
            return ap_pstrcat(p, "failed to resolve \"", host,
                           "\" to exactly one IP address", NULL);
        }
    } else {
      (*socket_addr)->sin_addr.s_addr = htonl(INADDR_ANY);
    }

    *socket_addr_len = sizeof(struct sockaddr_in);
    return NULL;
}

/*******************************************************************************
 * Find a FastCGI server with a matching fs_path, and if fcgi_wrapper is
 * enabled with matching uid and gid.
 */
fcgi_server *
fcgi_util_fs_get_by_id(const char *ePath)
{
    char path[FCGI_MAXPATH];
    fcgi_server *s;

    /* @@@ This should now be done in the loop below */
    ap_cpystrn(path, ePath, FCGI_MAXPATH);
    ap_no2slash(path);

    for (s = fcgi_servers; s != NULL; s = s->next) {
        int i;
        const char *fs_path = s->fs_path;
        for (i = 0; fs_path[i] && path[i]; ++i) {
            if (fs_path[i] != path[i]) {
                break;
            }
        }
        if (fs_path[i]) {
            continue;
        }
        if (path[i] == '\0' || path[i] == '/') {
            return s;
        }
    }
    return NULL;
}

/*******************************************************************************
 * Allocate a new FastCGI server record from pool p with default values.
 */
fcgi_server *
fcgi_util_fs_new(pool *p)
{
    fcgi_server *s = (fcgi_server *) ap_pcalloc(p, sizeof(fcgi_server));

    /* Initialize anything who's init state is not zeroizzzzed */
    s->listenQueueDepth = FCGI_DEFAULT_LISTEN_Q;
    s->appConnectTimeout = FCGI_DEFAULT_APP_CONN_TIMEOUT;
    s->idle_timeout = FCGI_DEFAULT_IDLE_TIMEOUT;
    s->initStartDelay = DEFAULT_INIT_START_DELAY;
    s->restartDelay = FCGI_DEFAULT_RESTART_DELAY;
	s->minServerLife = FCGI_DEFAULT_MIN_SERVER_LIFE;
    s->restartOnExit = FALSE;
    s->directive = APP_CLASS_UNKNOWN;
    s->processPriority = FCGI_DEFAULT_PRIORITY;

    s->listenFd = -2;

    return s;
}

/*******************************************************************************
 * Add the server to the linked list of FastCGI servers.
 */
void
fcgi_util_fs_add(fcgi_server *s)
{
    s->next = fcgi_servers;
    fcgi_servers = s;
}
