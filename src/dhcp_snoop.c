#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "sloth.h"
#include "dhcp_snoop.h"
#include "dns.h"

/* ── Internal table ──────────────────────────────────────── */

static dhcp_event_t    g_events[MAX_DHCP_EVENTS];
static int             g_count = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── DHCP wire format constants (RFC 2131) ───────────────── */

#define DHCP_MAGIC  0x63825363u  /* options magic cookie */

/* DHCP options we care about */
#define OPT_MSGTYPE  53
#define OPT_HOSTNAME 12

static const char *msg_type_str(uint8_t t) {
    switch (t) {
    case 1: return "DISCOVER";
    case 2: return "OFFER";
    case 3: return "REQUEST";
    case 4: return "DECLINE";
    case 5: return "ACK";
    case 6: return "NAK";
    case 7: return "RELEASE";
    case 8: return "INFORM";
    default: return "DHCP";
    }
}

/* ── Table helpers ───────────────────────────────────────── */

static dhcp_event_t *find_or_create(const char *mac) {
    for (int i = 0; i < g_count; i++) {
        if (strcmp(g_events[i].mac, mac) == 0)
            return &g_events[i];
    }
    if (g_count >= MAX_DHCP_EVENTS) {
        /* evict oldest */
        int oldest = 0;
        for (int i = 1; i < g_count; i++)
            if (g_events[i].last_seen < g_events[oldest].last_seen)
                oldest = i;
        memset(&g_events[oldest], 0, sizeof(g_events[oldest]));
        snprintf(g_events[oldest].mac, sizeof(g_events[oldest].mac), "%s", mac);
        return &g_events[oldest];
    }
    dhcp_event_t *e = &g_events[g_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->mac, sizeof(e->mac), "%s", mac);
    return e;
}

/* Format raw 6-byte MAC into "aa:bb:cc:dd:ee:ff". */
static void fmt_mac(const uint8_t *raw, char *out) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5]);
}

/* ── Public API ──────────────────────────────────────────── */

int dhcp_snoop(const uint8_t *data, int len, char *info, int infosz) {
    /* DHCP header through magic cookie is 240 bytes minimum */
    if (len < 240) return 0;

    uint8_t op    = data[0];
    uint8_t htype = data[1];
    uint8_t hlen  = data[2];
    if ((op != 1 && op != 2) || htype != 1 || hlen != 6) return 0;

    /* Verify magic cookie at offset 236 */
    uint32_t magic = ((uint32_t)data[236] << 24) | ((uint32_t)data[237] << 16) |
                     ((uint32_t)data[238] <<  8) |  (uint32_t)data[239];
    if (magic != DHCP_MAGIC) return 0;

    /* Extract addresses */
    char yiaddr[INET_ADDRSTRLEN] = "";  /* offered/assigned IP (reply) */
    char ciaddr[INET_ADDRSTRLEN] = "";  /* client IP (request) */
    inet_ntop(AF_INET, data + 12, ciaddr, sizeof(ciaddr));
    inet_ntop(AF_INET, data + 16, yiaddr, sizeof(yiaddr));

    char mac[18];
    fmt_mac(data + 28, mac);

    /* Walk TLV options starting at offset 240 */
    uint8_t  msg_type = 0;
    char     hostname[64] = "";

    const uint8_t *p   = data + 240;
    const uint8_t *end = data + len;
    while (p < end) {
        uint8_t tag = *p++;
        if (tag == 0) continue;         /* pad */
        if (tag == 255) break;          /* end */
        if (p >= end) break;
        uint8_t olen = *p++;
        if (p + olen > end) break;

        if (tag == OPT_MSGTYPE && olen >= 1)
            msg_type = p[0];
        else if (tag == OPT_HOSTNAME && olen > 0 && olen < 64) {
            memcpy(hostname, p, olen);
            hostname[olen] = '\0';
        }
        p += olen;
    }

    if (msg_type == 0) return 0;   /* not a recognised DHCP message */

    /* Determine which IP to use: yiaddr for replies, ciaddr for requests */
    const char *assigned = (yiaddr[0] && strcmp(yiaddr, "0.0.0.0") != 0)
                           ? yiaddr : ciaddr;

    pthread_mutex_lock(&g_mu);
    dhcp_event_t *e = find_or_create(mac);
    e->msg_type  = msg_type;
    e->last_seen = time(NULL);
    if (hostname[0])
        snprintf(e->hostname, sizeof(e->hostname), "%s", hostname);
    if (assigned[0] && strcmp(assigned, "0.0.0.0") != 0)
        snprintf(e->ip, sizeof(e->ip), "%s", assigned);
    /* Feed DNS cache on ACK when we have both hostname and IP */
    if (msg_type == 5 && e->ip[0] && e->hostname[0])
        dns_set_resolved(e->ip, e->hostname);
    pthread_mutex_unlock(&g_mu);

    /* Build info string */
    if (info && infosz > 0) {
        if (hostname[0] && assigned[0] && strcmp(assigned, "0.0.0.0") != 0)
            snprintf(info, (size_t)infosz, "DHCP %s %s -> %s",
                     msg_type_str(msg_type), hostname, assigned);
        else if (hostname[0])
            snprintf(info, (size_t)infosz, "DHCP %s %s",
                     msg_type_str(msg_type), hostname);
        else if (assigned[0] && strcmp(assigned, "0.0.0.0") != 0)
            snprintf(info, (size_t)infosz, "DHCP %s -> %s",
                     msg_type_str(msg_type), assigned);
        else
            snprintf(info, (size_t)infosz, "DHCP %s %s",
                     msg_type_str(msg_type), mac);
    }
    return 1;
}

void dhcp_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_DHCP_EVENTS ? g_count : MAX_DHCP_EVENTS;
    memcpy(s->dhcp_events, g_events, (size_t)n * sizeof(dhcp_event_t));
    s->dhcp_event_count = n;
    pthread_mutex_unlock(&g_mu);
}

void dhcp_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_events, 0, sizeof(g_events));
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
