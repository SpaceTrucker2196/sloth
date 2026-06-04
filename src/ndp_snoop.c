#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "ndp_snoop.h"

/* Tracker state. Tiny: at most MAX_NDP_RAS distinct router source IPs.
 * Each RA observation either updates an existing entry (same src_ip,
 * unchanged in 99% of normal cases) or appends a new one. */
static ndp_ra_event_t  g_ras[MAX_NDP_RAS];
static int             g_n  = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* ── Helpers ──────────────────────────────────────────────── */

static uint16_t u16be(const uint8_t *p) {
    return (uint16_t)(((unsigned)p[0] << 8) | p[1]);
}

static int find_or_alloc(const char *src_ip) {
    for (int i = 0; i < g_n; i++) {
        if (strcmp(g_ras[i].src_ip, src_ip) == 0) return i;
    }
    int slot;
    if (g_n < MAX_NDP_RAS) {
        slot = g_n++;
    } else {
        /* Evict the oldest entry by last_seen. */
        slot = 0;
        for (int i = 1; i < g_n; i++) {
            if (g_ras[i].last_seen < g_ras[slot].last_seen) slot = i;
        }
    }
    memset(&g_ras[slot], 0, sizeof(g_ras[slot]));
    snprintf(g_ras[slot].src_ip, sizeof(g_ras[slot].src_ip), "%s", src_ip);
    return slot;
}

/* Format an IPv6 prefix as "ADDR/LEN" into out. Returns 0 if the
 * formatting succeeded, -1 on inet_ntop failure. */
static int fmt_prefix(const uint8_t prefix[16], uint8_t plen,
                      char *out, int outsz) {
    if (outsz < 6) return -1;
    char addr[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, prefix, addr, sizeof(addr))) return -1;
    if (snprintf(out, (size_t)outsz, "%s/%u", addr, plen) >= outsz) return -1;
    return 0;
}

/* ── Public API ────────────────────────────────────────────── */

int ndp_snoop_ra(const char *src_ip, const uint8_t *payload, int len) {
    /* RFC 4861 §4.2: RA message minimum 16 bytes (type + code + checksum
     * + cur hop limit + flags + lifetime + reachable + retrans). */
    if (!src_ip || !payload || len < 16) return 0;
    if (payload[0] != 134 || payload[1] != 0) return 0;

    uint8_t  cur_hop_limit  = payload[4];
    uint8_t  flags          = payload[5];
    uint16_t router_lifetime = u16be(payload + 6);
    /* Reachable Time (payload+8..11) and Retrans Timer (payload+12..15)
     * are not retained — they aren't relevant to rogue-RA detection. */

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);

    int idx = find_or_alloc(src_ip);
    ndp_ra_event_t *e = &g_ras[idx];
    if (e->first_seen == 0) e->first_seen = now;
    e->last_seen        = now;
    e->cur_hop_limit    = cur_hop_limit;
    e->flags            = flags;
    e->router_lifetime  = router_lifetime;
    e->count++;
    /* Don't accumulate prefixes across observations — replace each
     * tick so the snapshot reflects what the router is currently
     * advertising. */
    e->prefix_count = 0;
    e->has_src_mac  = 0;
    memset(e->src_mac, 0, sizeof(e->src_mac));

    /* Walk the option list. Options follow at payload + 16; each
     * option is type(1) + len(1, in units of 8 bytes) + body. */
    int off = 16;
    while (off + 2 <= len) {
        uint8_t opt_type = payload[off];
        uint8_t opt_len8 = payload[off + 1];
        if (opt_len8 == 0) break;                /* RFC 4861: len 0 = bad */
        int opt_bytes = (int)opt_len8 * 8;
        if (off + opt_bytes > len) break;

        if (opt_type == 1 && opt_bytes == 8) {
            /* Source Link-Layer Address — Ethernet form is 8 bytes
             * (type+len+6 MAC). */
            memcpy(e->src_mac, payload + off + 2, 6);
            e->has_src_mac = 1;
        } else if (opt_type == 3 && opt_bytes == 32) {
            /* Prefix Information Option (RFC 4861 §4.6.2).
             *   off+2: Prefix Length (bits)
             *   off+3: L+A+R+reserved flags
             *   off+4..7: Valid Lifetime
             *   off+8..11: Preferred Lifetime
             *   off+12..15: Reserved
             *   off+16..31: Prefix (16 bytes) */
            if (e->prefix_count < NDP_RA_MAX_PREFIXES) {
                uint8_t plen = payload[off + 2];
                if (plen <= 128) {
                    fmt_prefix(payload + off + 16, plen,
                               e->prefixes[e->prefix_count],
                               (int)sizeof(e->prefixes[0]));
                    e->prefix_count++;
                }
            }
        }
        /* Other option types (MTU, Route Information, RDNSS, etc.) are
         * silently skipped — sloth doesn't need them for the rogue-RA
         * trigger. The forwarder / iOS client gets the SLLA + prefixes
         * which are the operationally interesting fields. */

        off += opt_bytes;
    }

    pthread_mutex_unlock(&g_mu);
    return 1;
}

void ndp_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_NDP_RAS ? g_n : MAX_NDP_RAS;
    for (int i = 0; i < n; i++) s->ndp_ras[i] = g_ras[i];
    s->ndp_ra_count = n;
    pthread_mutex_unlock(&g_mu);
}

void ndp_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_ras, 0, sizeof(g_ras));
    pthread_mutex_unlock(&g_mu);
}
