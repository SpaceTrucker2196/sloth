#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "sloth.h"
#include "sloth_clock.h"
#include "netstr.h"
#include "dhcp_snoop.h"
#include "sensor_health.h"
#include "dns.h"
#include "stab.h"

/* ── Internal table ──────────────────────────────────────── */

static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

static int event_key_eq(const void *row, const void *key) {
    return strcmp(((const dhcp_event_t *)row)->mac, (const char *)key) == 0;
}

/* Already tallied since #91 slice 3; stab_t since #110 so the eviction
 * and its count are the shared code's, not a private copy. */
STAB_DECL(g_events, dhcp_event_t, MAX_DHCP_EVENTS, last_seen, STAB_OLDEST,
          SH_EVICT_DHCP_EVENT, NULL, event_key_eq);

/* ── DHCP wire format constants (RFC 2131) ───────────────── */

#define DHCP_MAGIC  0x63825363u  /* options magic cookie */

/* DHCP options we care about */
#define OPT_MSGTYPE   53
#define OPT_HOSTNAME  12
#define OPT_SERVER_ID 54

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

/* `now` 0: the caller stamps last_seen from its own clock read under the
 * same g_mu hold, before any other lookup can see the row. That read is
 * left exactly where it was — moving modules onto an injected clock is
 * its own slice, not this one. */
static dhcp_event_t *event_get(const char *mac) {
    int created;
    dhcp_event_t *e = stab_get(&g_events, mac, 0, &created);
    if (created) snprintf(e->mac, sizeof(e->mac), "%s", mac);
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
    char     hostname[64]  = "";
    char     server_ip[46] = "";

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
            netstr_copy(hostname, sizeof(hostname), p, olen);   /* #138 */
        }
        else if (tag == OPT_SERVER_ID && olen == 4) {
            inet_ntop(AF_INET, p, server_ip, sizeof(server_ip));
        }
        p += olen;
    }

    if (msg_type == 0) return 0;   /* not a recognised DHCP message */

    /* Determine which IP to use: yiaddr for replies, ciaddr for requests */
    const char *assigned = (yiaddr[0] && strcmp(yiaddr, "0.0.0.0") != 0)
                           ? yiaddr : ciaddr;

    pthread_mutex_lock(&g_mu);
    dhcp_event_t *e = event_get(mac);
    e->msg_type  = msg_type;
    e->last_seen = sloth_wall();
    if (hostname[0])
        snprintf(e->hostname, sizeof(e->hostname), "%s", hostname);
    if (assigned[0] && strcmp(assigned, "0.0.0.0") != 0)
        snprintf(e->ip, sizeof(e->ip), "%s", assigned);
    /* Server identifier — only present on server replies. Replace any
     * prior value; rogue-DHCP detection later cross-references across
     * events so a flapping server identity surfaces. */
    if (server_ip[0])
        snprintf(e->server_ip, sizeof(e->server_ip), "%s", server_ip);
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
    s->dhcp_event_count = stab_snapshot(&g_events, s->dhcp_events,
                                        MAX_DHCP_EVENTS);
    pthread_mutex_unlock(&g_mu);
}

void dhcp_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_events);
    pthread_mutex_unlock(&g_mu);
}
