/* discover class
 *
 * Copyright (c) 2004 David Hammerton
 * crazney@crazney.net
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include "portability.h"
#include "thread.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "mdnsd/mdnsd.h"

#include "debug.h"

#include "private.h"
#include "discover.h"
#include "threadpool.h"

#include "endian_swap.h"

#define DEFAULT_DEBUG_CHANNEL "discover"

struct infocb_data
{
    SDiscover *pDiscover;
    SDiscover_HostList *host; /* host entry */
};

/* helper for info callback */
static SDiscover_HostList *DISC_get_refptr_from_hostptr(SDiscover_HostList **head,
                                                        SDiscover_HostList *ptr,
                                                        SDiscover_HostList ***refptr)
{
    SDiscover_HostList *prev = NULL;
    SDiscover_HostList *cur = *head;
    while (cur)
    {
        if (cur == ptr)
        {
            if (prev)
                *refptr = &(prev->next);
            else
                *refptr = head;
            return cur;
        }
        prev = cur;
        cur = cur->next;
    }
    return NULL;
}

/* callbacks from mdnsd */
static int InfoCallback(mdnsda answer,
                        void *arg, int addrecord)
{
    struct infocb_data *cbdata = (struct infocb_data *)arg;
    SDiscover *pDiscover = cbdata->pDiscover;

    if (!addrecord)
    {
        SDiscover_HostList *host = cbdata->host;
        SDiscover_HostList **refptr;
        ERR("info callback without addrecord, perhaps the host died during query?\n");
        if (answer->type == QTYPE_SRV)
        {
            if (DISC_get_refptr_from_hostptr(&pDiscover->prenamed, host, &refptr)
                                    != host)
                goto done;
        }
        else if (answer->type == QTYPE_A)
        {
            if (DISC_get_refptr_from_hostptr(&pDiscover->pending, host, &refptr)
                                    != host)
                goto done;
        }
        else goto done;
        *refptr = host->next;
        free(host);
done:
        free(cbdata);
        return -1;
    }

    if (answer->type == QTYPE_SRV)
    {
        SDiscover_HostList *host = cbdata->host;
        SDiscover_HostList **refptr;
        char c = 0;

        if (DISC_get_refptr_from_hostptr(&pDiscover->prenamed, host, &refptr)
                != host)
        {
            ERR("query returned non existant host?\n");
            free(cbdata);
            return -1;
        }
        *refptr = host->next;

        host->next = pDiscover->pending;
        pDiscover->pending = host;

        host->port = answer->srv.port;
        strcpy(host->hostname, answer->rdname);
        host->queried = -1;

        if (!write(pDiscover->newquery_pipe[1], &c, sizeof(c)))
            ERR("failed to write to pipe\n");

        TRACE("got a srv (%s, %s, %hd)\n", host->sharename_friendly, host->hostname, host->port);
    }
    else if (answer->type == QTYPE_A)
    {
        SDiscover_HostList *host = cbdata->host;
        SDiscover_HostList **refptr;
        u_int32_t ip;
        unsigned char *p_ip = (unsigned char*)&ip;

        if (DISC_get_refptr_from_hostptr(&pDiscover->pending, host, &refptr)
                != host)
        {
            ERR("query returned non existant host?\n");
            free(cbdata);
            return -1;
        }
        *refptr = host->next;

        host->next = pDiscover->have;
        pDiscover->have = host;

        /* FIXME: endian? */
        ip = __Swap32(answer->ip); /* will swap on little endian archs */
        host->ip[0] = p_ip[0];
        host->ip[1] = p_ip[1];
        host->ip[2] = p_ip[2];
        host->ip[3] = p_ip[3];

        host->queried = -1;

        TRACE("Got an ip for %s: %hhu.%hhu.%hhu.%hhu\n", host->sharename_friendly,
                host->ip[0],
                host->ip[1],
                host->ip[2],
                host->ip[3]);

        if (pDiscover->pfnUpdateCallback)
            pDiscover->pfnUpdateCallback(pDiscover,
                                   pDiscover->pvCallbackArg);
    }
    /* FIXME: could use AAAA type for ipv6 */

    free(cbdata);

    return -1; /* remove query */
}

static SDiscover_HostList *DISC_host_is_in_queue(SDiscover *pDiscover,
                                                 const char *sharename)
{
    SDiscover_HostList *cur;

#define CHECK_CUR \
    do { while (cur) \
    { \
        if (strcmp(sharename, cur->sharename) == 0) return cur; \
        cur = cur->next; \
    } } while (0)
    cur = pDiscover->have;
    CHECK_CUR;
    cur = pDiscover->pending;
    CHECK_CUR;
    cur = pDiscover->prenamed;
    CHECK_CUR;
#undef CHECK_CUR

    return NULL;
}

static int DeadHost(SDiscover *pDiscover, SDiscover_HostList *host)
{
#define DELETE_IF_IN_LIST(_host) \
    do { SDiscover_HostList *prev = NULL; cur = *list; \
    while (cur) { \
        if (cur == _host) { \
            if (prev) prev->next = cur->next; \
            else *list = cur->next; \
            break; \
        } \
        prev = cur; cur = cur->next; \
    } } while (0)
    SDiscover_HostList **list;
    SDiscover_HostList *cur;

    list = &(pDiscover->have);
    DELETE_IF_IN_LIST(host);
    if (cur)
    {
        free(cur);
        /* tell app */
        return 1;
    }
    list = &(pDiscover->pending);
    DELETE_IF_IN_LIST(host);
    if (cur)
    {
        /* remove query. FIXME: cbdata leaked */
        mdnsd_query(pDiscover->mdnsd_info, cur->sharename, QTYPE_A, NULL, NULL);
        free(cur);
        return 0;
    }
    list = &(pDiscover->prenamed);
    DELETE_IF_IN_LIST(host);
    if (cur)
    {
        /* remove query. FIXME: cbdata leaked */
        mdnsd_query(pDiscover->mdnsd_info, cur->sharename, QTYPE_SRV, NULL, NULL);
        free(cur);
        return 0;
    }
    return 0; /* not there now??? */
}

static int NameCallback(mdnsda answer, void *arg, int addrecord)
{
    SDiscover *pDiscover = (SDiscover *)arg;

    if (answer->type == QTYPE_PTR)
    {
        SDiscover_HostList *new;
        SDiscover_HostList *old;
        int sharename_len;
        char c = 0;

        ts_mutex_lock(pDiscover->mtObjectLock);

        new = malloc(sizeof(SDiscover_HostList));
        memset(new, 0, sizeof(SDiscover_HostList));

        if (!addrecord)
        {
            /* FIXME */
            new->lost = 1;
        }

        TRACE("got a new name callback. sharename '%s' (lost: %i)\n", answer->rdname, new->lost);

        /* check if it's in the queue..
         * mdnsd has a habbit of continuesly reporting that
         * a host exists. yay. */
        if ((old = DISC_host_is_in_queue(pDiscover, answer->rdname)))
        {
            if (new->lost)
            {
                if (DeadHost(pDiscover, old))
                {
                    /* tell app */
                    if (pDiscover->pfnUpdateCallback)
                        pDiscover->pfnUpdateCallback(pDiscover,
                                               pDiscover->pvCallbackArg);
                }
            }
            ts_mutex_unlock(pDiscover->mtObjectLock);
            free(new);
            return 0;
        }

        if (new->lost)
        {
            /* lost but not in the queue, yay mdnsd! */
            ts_mutex_unlock(pDiscover->mtObjectLock);
            free(new);
            return 0;
        }

        new->next = pDiscover->prenamed;
        pDiscover->prenamed = new;

        strcpy(new->sharename, answer->rdname);

        sharename_len = strlen(answer->rdname) - strlen(answer->name) - 1;
        strncpy(new->sharename_friendly, answer->rdname, sharename_len);
        new->sharename_friendly[sharename_len] = 0;

#if 1
        new->queried = -1;
        if (!write(pDiscover->newquery_pipe[1], &c, sizeof(c)))
            ERR("failed to write to pipe\n");
#endif

        pDiscover->pending_hosts++;

        ts_mutex_unlock(pDiscover->mtObjectLock);
    }

    return 0;
}

/* mdnsd requires that we set up the socket */
static int msock()
{
    int s, flag = 1, ittl = 255;
    struct sockaddr_in in;
    struct ip_mreq mc;
    char ttl = 255;

    bzero(&in, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(5353);
    in.sin_addr.s_addr = 0;

    if((s = socket(AF_INET,SOCK_DGRAM,0)) < 0) return 0;
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (char*)&flag, sizeof(flag));
#endif
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag));
    if(bind(s,(struct sockaddr*)&in,sizeof(in))) { close(s); return 0; }

    mc.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
    mc.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mc, sizeof(mc)); 
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ittl, sizeof(ittl));

    flag =  fcntl(s, F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(s, F_SETFL, flag);

    return s;
}

static void DISC_add_pending_queries(SDiscover *pDiscover)
{
    SDiscover_HostList *cur;
    char c;
#define POP_READPIPE_1 do { ssize_t ret; c = 255; \
                            ret = read(pDiscover->newquery_pipe[0], &c, sizeof(c)); \
                            if (c != 0 || ret != 1) ERR("unexpected pipe value!\n"); } while (0)

    cur = pDiscover->prenamed;
    while (cur)
    {
        struct infocb_data *cbdata;
        if (cur->queried != -1)
        {
            /* FIXME: remove ones that have timed out?? */
            cur = cur->next;
            continue;
        }
        cbdata = malloc(sizeof(struct infocb_data));
        cbdata->pDiscover = pDiscover;
        cbdata->host = cur;
        mdnsd_query(pDiscover->mdnsd_info, cur->sharename, QTYPE_SRV, InfoCallback, cbdata);
        cur->queried = time(0);
        POP_READPIPE_1;

        cur = cur->next;
    }
    cur = pDiscover->pending;
    while (cur)
    {
        struct infocb_data *cbdata;
        if (cur->queried != -1)
        {
            /* FIXME: remove ones that have timed out?? */
            cur = cur->next;
            continue;
        }
        cbdata = malloc(sizeof(struct infocb_data));
        cbdata->pDiscover = pDiscover;
        cbdata->host = cur;

        TRACE("quering '%s' QTYPE_A\n", cur->hostname);

        mdnsd_query(pDiscover->mdnsd_info, cur->hostname, QTYPE_A, InfoCallback, cbdata);
        cur->queried = time(0);
        POP_READPIPE_1;

        cur = cur->next;
    }

    if (read(pDiscover->newquery_pipe[0], &c, sizeof(c)) != -1 &&
            errno != EAGAIN)
    {
        ERR("oh no! pipe wasn't empty!!\n");
    }
}

static void DISC_ioiteration(SDiscover *pDiscover)
{
    struct timeval *tv;
    fd_set fds;
    int max_fd;

    struct message m;
    unsigned long int ip;
    unsigned short int port;

    tv = mdnsd_sleep(pDiscover->mdnsd_info);
    FD_ZERO(&fds);
    FD_SET(pDiscover->socket, &fds);
    max_fd = pDiscover->socket;

    FD_SET(pDiscover->newquery_pipe[0], &fds);
    if (pDiscover->newquery_pipe[0] > max_fd)
        max_fd = pDiscover->newquery_pipe[0];

    select(max_fd + 1, &fds, 0, 0, tv);

    if (FD_ISSET(pDiscover->socket, &fds))
    {
        int bsize, ssize = sizeof(struct sockaddr_in);
        unsigned char buf[MAX_PACKET_LEN];
        struct sockaddr_in from;

        while((bsize = recvfrom(pDiscover->socket, buf,
                                MAX_PACKET_LEN, 0,
                                (struct sockaddr*)&from,
                                &ssize)) > 0)
        {
            bzero(&m,sizeof(struct message));
            message_parse(&m,buf);
            mdnsd_in(pDiscover->mdnsd_info, &m,
                     (unsigned long int)from.sin_addr.s_addr,
                     from.sin_port);
            ssize = sizeof(struct sockaddr_in);
        }
        if (bsize < 0 && errno != EAGAIN)
        {
            ERR("couldn't read from socket: %s\n", strerror(errno));
        }
    }
    if (FD_ISSET(pDiscover->newquery_pipe[0], &fds))
    {
        DISC_add_pending_queries(pDiscover);
    }
    while (mdnsd_out(pDiscover->mdnsd_info, &m, &ip, &port))
    {
        struct sockaddr_in to;
        bzero(&to, sizeof(to));
        to.sin_family = AF_INET;
         /* FIXME endian? */
        to.sin_port = port;
        to.sin_addr.s_addr = ip;

        if (sendto(pDiscover->socket, message_packet(&m), message_packet_len(&m), 0,
                   (struct sockaddr*)&to, sizeof(struct sockaddr_in)) != message_packet_len(&m))
        {
            ERR("couldn't write to socket: %s\n", strerror(errno));
        }
    }
}

/* discover thread. */
static void DISC_DiscoverHosts(void *pvDiscoverThis, void *arg2)
{
    SDiscover *pDiscover = (SDiscover *)pvDiscoverThis;

    ts_mutex_lock(pDiscover->mtObjectLock);

    /* start a query to search for hosts */
    mdnsd_query(pDiscover->mdnsd_info,
                "_daap._tcp.local.", QTYPE_PTR,
                NameCallback, (void*)pDiscover);

    ts_mutex_unlock(pDiscover->mtObjectLock);

    while (pDiscover->uiRef > 1)
    {
        DISC_ioiteration(pDiscover);
    }
}

/* public interface */

SDiscover *Discover_Create(CP_SThreadPool *pThreadPool,
                           fnDiscUpdated pfnCallback,
                           void *arg)
{
    int flag;

    SDiscover *pDiscoverNew = malloc(sizeof(SDiscover));
    memset(pDiscoverNew, 0, sizeof(SDiscover));

    pDiscoverNew->uiRef = 1;

    pDiscoverNew->pfnUpdateCallback = pfnCallback;
    pDiscoverNew->pvCallbackArg = arg;

    pDiscoverNew->mdnsd_info = mdnsd_new(0x8000 | 1,1000);
    pDiscoverNew->socket = msock();

    if (pDiscoverNew->socket == 0)
    {
        ERR("an error occured\n");
        return NULL;
    }

    pipe(pDiscoverNew->newquery_pipe);
    flag =  fcntl(pDiscoverNew->newquery_pipe[0], F_GETFL, 0);
    flag |= O_NONBLOCK;
    fcntl(pDiscoverNew->newquery_pipe[0], F_SETFL, flag);

    ts_mutex_create(pDiscoverNew->mtObjectLock);
    ts_mutex_create(pDiscoverNew->mtWorkerLock);
    CP_ThreadPool_AddRef(pThreadPool);

    pDiscoverNew->tp = pThreadPool;

    Discover_AddRef(pDiscoverNew); /* for the worker thread */

    CP_ThreadPool_QueueWorkItem(pThreadPool, DISC_DiscoverHosts,
                                (void *)pDiscoverNew, NULL);

    return pDiscoverNew;
}

unsigned int Discover_AddRef(SDiscover *pDiscover)
{
    unsigned int ret;
    ret = ++pDiscover->uiRef;
    return ret;
}

unsigned int Discover_Release(SDiscover *pDiscover)
{
    if (--pDiscover->uiRef)
    {
        return pDiscover->uiRef;
    }

    mdnsd_shutdown(pDiscover->mdnsd_info);
    mdnsd_free(pDiscover->mdnsd_info);

    close(pDiscover->newquery_pipe[0]);
    close(pDiscover->newquery_pipe[1]);

    free(pDiscover);
    return 0;
}

unsigned int Discover_GetHosts(SDiscover *pDiscThis,
                               SDiscover_HostList **hosts)
{
    *hosts = pDiscThis->have;
    return 0;
}

