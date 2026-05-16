#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "dns.h"

/* ── Tunables ────────────────────────────────────────────── */

#define DNS_CACHE_SIZE 256
#define DNS_QUEUE_SIZE  64
#define DNS_TTL_SEC    300   /* re-resolve after 5 minutes */

/* ── Cache ───────────────────────────────────────────────── */

typedef enum {
    DNS_EMPTY    = 0,
    DNS_PENDING  = 1,
    DNS_RESOLVED = 2,
    DNS_FAILED   = 3,
} dns_state_t;

typedef struct {
    char        ip[46];
    char        host[256];
    dns_state_t state;
    time_t      ts;
} dns_entry_t;

static dns_entry_t g_cache[DNS_CACHE_SIZE];

/* ── Work queue ──────────────────────────────────────────── */

static char g_queue[DNS_QUEUE_SIZE][46];
static int  g_queue_head = 0;
static int  g_queue_len  = 0;

/* ── Thread state ────────────────────────────────────────── */

static pthread_t       g_thread;
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv  = PTHREAD_COND_INITIALIZER;
static volatile int    g_running = 0;

/* ── Internal helpers ────────────────────────────────────── */

/* Find cache slot for ip. Returns index or -1. Caller holds g_mu. */
static int cache_find(const char *ip) {
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (g_cache[i].state != DNS_EMPTY &&
            strcmp(g_cache[i].ip, ip) == 0)
            return i;
    }
    return -1;
}

/* Evict the best slot for reuse. Caller holds g_mu. */
static int cache_evict(void) {
    time_t now = time(NULL);
    int oldest = 0;
    /* prefer an empty slot */
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (g_cache[i].state == DNS_EMPTY) return i;
    }
    /* prefer expired failed/resolved entries */
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (g_cache[i].state != DNS_PENDING &&
            now - g_cache[i].ts > DNS_TTL_SEC)
            return i;
    }
    /* fall back to oldest entry by timestamp */
    for (int i = 1; i < DNS_CACHE_SIZE; i++) {
        if (g_cache[i].ts < g_cache[oldest].ts)
            oldest = i;
    }
    return oldest;
}

/* Queue ip for async resolution. Caller holds g_mu. */
static void enqueue(const char *ip) {
    if (g_queue_len >= DNS_QUEUE_SIZE) return;  /* drop if full */
    int tail = (g_queue_head + g_queue_len) % DNS_QUEUE_SIZE;
    strncpy(g_queue[tail], ip, 45);
    g_queue[tail][45] = '\0';
    g_queue_len++;
    pthread_cond_signal(&g_cv);
}

/* ── Worker thread ───────────────────────────────────────── */

static void resolve_ip(const char *ip, char *host, int hostsz) {
    host[0] = '\0';
    struct sockaddr_storage ss;
    socklen_t slen;
    memset(&ss, 0, sizeof(ss));

    struct sockaddr_in  *sa4 = (struct sockaddr_in  *)&ss;
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&ss;

    if (inet_pton(AF_INET, ip, &sa4->sin_addr) == 1) {
        sa4->sin_family = AF_INET;
        slen = sizeof(*sa4);
    } else if (inet_pton(AF_INET6, ip, &sa6->sin6_addr) == 1) {
        sa6->sin6_family = AF_INET6;
        slen = sizeof(*sa6);
    } else {
        return;
    }

    getnameinfo((struct sockaddr *)&ss, slen,
                host, (socklen_t)hostsz, NULL, 0,
                NI_NOFQDN | NI_NAMEREQD);
    /* NI_NAMEREQD: fails (clears host) if no PTR record exists */
}

static void *dns_worker(void *arg) {
    (void)arg;
    while (g_running) {
        pthread_mutex_lock(&g_mu);
        while (g_queue_len == 0 && g_running)
            pthread_cond_wait(&g_cv, &g_mu);
        if (!g_running) { pthread_mutex_unlock(&g_mu); break; }

        char ip[46];
        strncpy(ip, g_queue[g_queue_head], 45); ip[45] = '\0';
        g_queue_head = (g_queue_head + 1) % DNS_QUEUE_SIZE;
        g_queue_len--;
        pthread_mutex_unlock(&g_mu);

        /* Resolve outside the lock — this can block for seconds */
        char host[256];
        resolve_ip(ip, host, sizeof(host));

        pthread_mutex_lock(&g_mu);
        int idx = cache_find(ip);
        if (idx >= 0 && g_cache[idx].state == DNS_PENDING) {
            if (host[0]) {
                snprintf(g_cache[idx].host, sizeof(g_cache[idx].host), "%s", host);
                g_cache[idx].state = DNS_RESOLVED;
            } else {
                g_cache[idx].state = DNS_FAILED;
            }
            g_cache[idx].ts = time(NULL);
        }
        pthread_mutex_unlock(&g_mu);
    }
    return NULL;
}

/* ── Public API ──────────────────────────────────────────── */

void dns_init(void) {
    memset(g_cache, 0, sizeof(g_cache));
    g_queue_head = 0;
    g_queue_len  = 0;
    g_running    = 1;
    pthread_create(&g_thread, NULL, dns_worker, NULL);
}

void dns_cleanup(void) {
    if (!g_running) return;
    pthread_mutex_lock(&g_mu);
    g_running = 0;
    pthread_cond_signal(&g_cv);
    pthread_mutex_unlock(&g_mu);
    pthread_join(g_thread, NULL);
}

void dns_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_cache, 0, sizeof(g_cache));
    g_queue_head = 0;
    g_queue_len  = 0;
    pthread_mutex_unlock(&g_mu);
}

void dns_set_resolved(const char *ip, const char *host) {
    pthread_mutex_lock(&g_mu);
    int idx = cache_find(ip);
    if (idx < 0) idx = cache_evict();
    strncpy(g_cache[idx].ip,   ip,   sizeof(g_cache[idx].ip)   - 1);
    strncpy(g_cache[idx].host, host, sizeof(g_cache[idx].host) - 1);
    g_cache[idx].ip[sizeof(g_cache[idx].ip) - 1]     = '\0';
    g_cache[idx].host[sizeof(g_cache[idx].host) - 1] = '\0';
    g_cache[idx].state = DNS_RESOLVED;
    g_cache[idx].ts    = time(NULL);
    pthread_mutex_unlock(&g_mu);
}

const char *dns_lookup(const char *ip) {
    static char result[256];
    time_t now = time(NULL);

    pthread_mutex_lock(&g_mu);
    int idx = cache_find(ip);

    if (idx >= 0) {
        dns_entry_t *e = &g_cache[idx];
        if (e->state == DNS_RESOLVED) {
            if (now - e->ts < DNS_TTL_SEC) {
                strncpy(result, e->host, sizeof(result) - 1);
                result[sizeof(result) - 1] = '\0';
                pthread_mutex_unlock(&g_mu);
                return result;
            }
            /* TTL expired — re-queue */
            e->state = DNS_PENDING;
            e->ts    = now;
            enqueue(ip);
        }
        /* PENDING or FAILED: return raw IP */
        pthread_mutex_unlock(&g_mu);
        return ip;
    }

    /* Not in cache: claim a slot and submit */
    idx = cache_evict();
    strncpy(g_cache[idx].ip, ip, sizeof(g_cache[idx].ip) - 1);
    g_cache[idx].ip[sizeof(g_cache[idx].ip) - 1] = '\0';
    g_cache[idx].host[0] = '\0';
    g_cache[idx].state   = DNS_PENDING;
    g_cache[idx].ts      = now;
    enqueue(ip);

    pthread_mutex_unlock(&g_mu);
    return ip;
}

void dns_fmt_addr(const char *ip, uint16_t port, char *buf, int sz) {
    const char *host = dns_lookup(ip);
    snprintf(buf, sz, "%s:%u", host, (unsigned)port);
}
