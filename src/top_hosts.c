#include <stdio.h>
#include <string.h>
#include <time.h>
#include "top_hosts.h"
#include "dns.h"
#include "ip_owner.h"
#include "geo.h"
#include "bandwidth.h"

/* Persistent table — first_seen and the resolved hostname survive
 * across polls so we can track "how long has this host been around". */
#define TOP_HOSTS_CAP 64

static top_host_t g_tbl[TOP_HOSTS_CAP];
static int        g_count;

/* ── Helpers ─────────────────────────────────────────────── */

/* Is this IP one we should skip — RFC1918 / loopback / link-local /
 * multicast / IPv6 link-local? Uses the existing geo classifier:
 *   "--" = private/reserved, "LO" = loopback, "MC" = multicast,
 *   anything else = a public RIR region. */
static int skip_ip(const char *ip) {
    if (!ip || !ip[0]) return 1;
    /* IPv6 fast paths */
    if (strchr(ip, ':')) {
        if (strncmp(ip, "fe80", 4) == 0) return 1;  /* link-local */
        if (strncmp(ip, "ff",   2) == 0) return 1;  /* multicast  */
        if (strcmp (ip, "::1") == 0)     return 1;  /* loopback   */
        if (strcmp (ip, "::")  == 0)     return 1;  /* unspec     */
        return 0;  /* assume routable for everything else */
    }
    const char *r = geo_lookup_str(ip);
    if (!r) return 1;
    if (r[0] == '-' || r[0] == 'L' || r[0] == 'M') return 1;
    return 0;
}

static int find(const char *ip) {
    for (int i = 0; i < g_count; i++)
        if (strcmp(g_tbl[i].ip, ip) == 0) return i;
    return -1;
}

static int evict_oldest_or_quietest(time_t now) {
    /* Prefer to evict the entry with the oldest last_seen; ties broken
     * by lowest activity (rate sum). */
    int worst = 0;
    for (int i = 1; i < g_count; i++) {
        if (g_tbl[i].last_seen < g_tbl[worst].last_seen) {
            worst = i;
        } else if (g_tbl[i].last_seen == g_tbl[worst].last_seen) {
            double a = g_tbl[i].rx_rate + g_tbl[i].tx_rate;
            double b = g_tbl[worst].rx_rate + g_tbl[worst].tx_rate;
            if (a < b) worst = i;
        }
    }
    (void)now;
    return worst;
}

static top_host_t *upsert(const char *ip, time_t now) {
    int i = find(ip);
    if (i >= 0) {
        g_tbl[i].last_seen = now;
        return &g_tbl[i];
    }
    int slot;
    if (g_count < TOP_HOSTS_CAP) {
        slot = g_count++;
    } else {
        slot = evict_oldest_or_quietest(now);
    }
    memset(&g_tbl[slot], 0, sizeof(g_tbl[slot]));
    snprintf(g_tbl[slot].ip, sizeof(g_tbl[slot].ip), "%s", ip);
    g_tbl[slot].first_seen = now;
    g_tbl[slot].last_seen  = now;
    return &g_tbl[slot];
}

static void reset_counters(void) {
    for (int i = 0; i < g_count; i++) {
        g_tbl[i].conn_count = 0;
        g_tbl[i].rx_rate    = 0.0;
        g_tbl[i].tx_rate    = 0.0;
    }
}

static void resolve_one(top_host_t *h) {
    if (h->hostname[0] == '\0') {
        const char *name = dns_lookup(h->ip);
        if (name && name[0] && strcmp(name, h->ip) != 0)
            snprintf(h->hostname, sizeof(h->hostname), "%s", name);
    }
    if (h->owner[0] == '\0') {
        const char *o = ip_owner_lookup_str(h->ip);
        if (o && o[0])
            snprintf(h->owner, sizeof(h->owner), "%s", o);
    }
}

static double activity(const top_host_t *h) {
    return h->rx_rate + h->tx_rate + (double)h->conn_count;
}

/* ── Public ──────────────────────────────────────────────── */

void top_hosts_clear(void) {
    g_count = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
}

void top_hosts_update(sloth_state_t *s) {
    if (!s) return;
    time_t now = time(NULL);

    reset_counters();

    /* (1) Walk current conns — bump conn_count and last_seen. */
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        if (skip_ip(c->remote_addr)) continue;
        top_host_t *h = upsert(c->remote_addr, now);
        h->conn_count++;
    }

    /* (2) Walk bw table — sum rates per remote IP. */
    for (int i = 0; i < s->conn_bw_count; i++) {
        const conn_bw_t *b = &s->conn_bw[i];
        if (skip_ip(b->remote_addr)) continue;
        top_host_t *h = upsert(b->remote_addr, now);
        h->rx_rate += b->rx_rate;
        h->tx_rate += b->tx_rate;
    }

    /* (3) Drop stale entries — not seen for TOP_HOST_STALE_S seconds. */
    for (int i = 0; i < g_count; ) {
        if (now - g_tbl[i].last_seen > TOP_HOST_STALE_S) {
            g_tbl[i] = g_tbl[g_count - 1];
            g_count--;
        } else {
            i++;
        }
    }

    /* (4) Resolve hostname + owner for any entry that's still missing one.
     *     dns_lookup is non-blocking — it kicks the async resolver and
     *     returns "" or the IP back; we only cache real names. */
    for (int i = 0; i < g_count; i++) resolve_one(&g_tbl[i]);

    /* (5) Sort g_tbl[] descending by activity; selection sort is fine
     *     for <=64 entries and keeps top-N at the front. */
    for (int i = 0; i < g_count - 1 && i < MAX_TOP_HOSTS; i++) {
        int best = i;
        for (int j = i + 1; j < g_count; j++)
            if (activity(&g_tbl[j]) > activity(&g_tbl[best])) best = j;
        if (best != i) {
            top_host_t tmp = g_tbl[i]; g_tbl[i] = g_tbl[best]; g_tbl[best] = tmp;
        }
    }

    /* (6) Snapshot the top MAX_TOP_HOSTS into state. */
    int n = g_count < MAX_TOP_HOSTS ? g_count : MAX_TOP_HOSTS;
    for (int i = 0; i < n; i++) s->top_hosts[i] = g_tbl[i];
    s->top_host_count = n;
}
