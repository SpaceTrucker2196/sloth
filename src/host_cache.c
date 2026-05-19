#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "host_cache.h"

/* Flat array, linear scan. HOST_CACHE_CAP is 1k; lookup is O(n) but
 * still negligible at the rates we operate (~hundreds of packets per
 * second, scan happens once per draw frame on at most a few hundred
 * rows). If profiling ever shows this matters, swap in an open-address
 * hash table keyed on the IP string. */
struct slot {
    char ip[HOST_CACHE_IPLEN];
    char host[HOST_CACHE_HOSTLEN];
};

static struct slot      g_tbl[HOST_CACHE_CAP];
static int              g_n      = 0;
static int              g_next   = 0;   /* next slot for ring overwrite */
static pthread_mutex_t  g_mu     = PTHREAD_MUTEX_INITIALIZER;

void host_cache_add(const char *ip, const char *host)
{
    if (!ip || !ip[0] || !host || !host[0]) return;
    /* Drop sentinel "NXDOMAIN" + empty / partial answers. */
    if (strcmp(host, "NXDOMAIN") == 0) return;

    pthread_mutex_lock(&g_mu);
    /* Update if already present so the most recent qname for an IP
     * sticks (CDNs / shared IPs naturally re-resolve under different
     * names; we keep whichever we saw last). */
    for (int i = 0; i < g_n; i++) {
        if (strcmp(g_tbl[i].ip, ip) == 0) {
            snprintf(g_tbl[i].host, sizeof(g_tbl[i].host), "%s", host);
            pthread_mutex_unlock(&g_mu);
            return;
        }
    }
    int slot;
    if (g_n < HOST_CACHE_CAP) {
        slot = g_n++;
    } else {
        slot   = g_next;
        g_next = (g_next + 1) % HOST_CACHE_CAP;
    }
    snprintf(g_tbl[slot].ip,   sizeof(g_tbl[slot].ip),   "%s", ip);
    snprintf(g_tbl[slot].host, sizeof(g_tbl[slot].host), "%s", host);
    pthread_mutex_unlock(&g_mu);
}

int host_cache_lookup(const char *ip, char *out, int out_sz)
{
    if (out && out_sz > 0) out[0] = '\0';
    if (!ip || !ip[0] || !out || out_sz <= 0) return 0;

    int hit = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_n; i++) {
        if (strcmp(g_tbl[i].ip, ip) == 0) {
            snprintf(out, out_sz, "%s", g_tbl[i].host);
            hit = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
    return hit;
}

int host_cache_count(void)
{
    pthread_mutex_lock(&g_mu);
    int n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void host_cache_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_n    = 0;
    g_next = 0;
    pthread_mutex_unlock(&g_mu);
}
