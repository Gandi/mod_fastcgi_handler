#include <unistd.h>
#include <netdb.h>
#include <grp.h>
#include <pwd.h>

#if APR_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "unixd.h"

#include "fcgi.h"

/*******************************************************************************
 * Build a Domain Socket Address structure, and calculate its size.
 * The error message is allocated from the pool p.  If you don't want the
 * struct sockaddr_un also allocated from p, pass it preallocated (!=NULL).
 */
static
const char *fcgi_util_socket_make_domain_addr(apr_pool_t *p,
		struct sockaddr_un **socket_addr, int *socket_addr_len,
		const char *socket_path)
{
	int socket_pathLen = strlen(socket_path);

	if (socket_pathLen >= sizeof((*socket_addr)->sun_path)) {
		return apr_pstrcat(p, "path \"", socket_path,
				"\" is too long for a Domain socket", NULL);
	}

	if (*socket_addr == NULL)
		*socket_addr = apr_pcalloc(p, sizeof(struct sockaddr_un));
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
static
int convert_string_to_in_addr(const char *hostname, struct in_addr *addr)
{
	if (inet_aton(hostname, addr) == 0) {
		struct hostent *hp;

		if ((hp = gethostbyname(hostname)) == NULL)
			return -1;

		memcpy((char *) addr, hp->h_addr, hp->h_length);

		int count = 0;
		while (hp->h_addr_list[count] != 0)
			count++;

		return count == 1 ? 0 : -1;
	}

	return 0;
}

/*******************************************************************************
 * Build an Inet Socket Address structure, and calculate its size.
 * The error message is allocated from the pool p. If you don't want the
 * struct sockaddr_in also allocated from p, pass it preallocated (!=NULL).
 */
static
const char *fcgi_util_socket_make_inet_addr(apr_pool_t *p,
		struct sockaddr_in **socket_addr, int *socket_addr_len,
		const char *host, unsigned short port)
{
	if (*socket_addr == NULL)
		*socket_addr = apr_pcalloc(p, sizeof(struct sockaddr_in));
	else
		memset(*socket_addr, 0, sizeof(struct sockaddr_in));

	(*socket_addr)->sin_family = AF_INET;
	(*socket_addr)->sin_port = htons(port);

	/* get an in_addr represention of the host */
	if (convert_string_to_in_addr(host, &(*socket_addr)->sin_addr) == -1) {
		return apr_pstrcat(p, "failed to resolve \"", host,
				"\" to exactly one IP address", NULL);
	}

	*socket_addr_len = sizeof(struct sockaddr_in);
	return NULL;
}

const char *fcgi_util_socket_make_addr(apr_pool_t *p, fcgi_request *fr)
{
	if (!fr->server || !*fr->server)
		return apr_pstrdup(p, "empty");

	if (*fr->server == '/') {
		return fcgi_util_socket_make_domain_addr(p,
				(struct sockaddr_un **)&fr->socket_addr,
				&fr->socket_addr_len, fr->server);
	}

	char *port_str = strchr(apr_pstrdup(p, fr->server), ':');

	if (!port_str) {
		return apr_pstrdup(p, "no port specified");
	} else {
		*port_str++ = '\0';
	}

	unsigned short port = atoi(port_str);

	if (port <= 0)
		return apr_pstrdup(p, "invalid port sepcified");

	return fcgi_util_socket_make_inet_addr(p,
			(struct sockaddr_in **)&fr->socket_addr,
			&fr->socket_addr_len, fr->server, port);
}
