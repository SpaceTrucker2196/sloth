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
#include "lan_role.h"

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
#define OPT_PRL       55   /* Parameter Request List, RFC 2132 §9.8   */
#define OPT_VCI       60   /* Vendor Class Identifier, RFC 2132 §9.13 */

/* RFC 2131 §4.1: servers send from, and clients to, UDP 67. */
#define DHCP_SERVER_PORT 67

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

/* Option 55 as its codes in wire order, "1,3,6,15". Cut at a whole
 * code, never mid-number, when the list outgrows the field. */
static void fmt_prl(const uint8_t *p, int n, char *out, size_t outsz) {
    size_t o = 0;
    out[0] = '\0';
    for (int i = 0; i < n; i++) {
        char tok[8];
        int k = snprintf(tok, sizeof(tok), "%s%u", i ? "," : "",
                         (unsigned)p[i]);
        if (k < 0 || o + (size_t)k + 1 > outsz) break;
        memcpy(out + o, tok, (size_t)k + 1);
        o += (size_t)k;
    }
}

int dhcp_snoop(const char *src_ip, uint16_t src_port,
               const uint8_t *data, int len, char *info, int infosz) {
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
    char     prl[sizeof(((dhcp_event_t *)0)->prl)] = "";
    char     vci[sizeof(((dhcp_event_t *)0)->vci)] = "";
    int      have_prl = 0, have_vci = 0;

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
        else if (tag == OPT_PRL && olen > 0) {
            fmt_prl(p, olen, prl, sizeof(prl));
            have_prl = 1;
        }
        else if (tag == OPT_VCI && olen > 0) {
            netstr_copy(vci, sizeof(vci), p, olen);              /* #138 */
            have_vci = 1;
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
    /* Options 55 / 60 are the client's (RFC 2132 §9.8, §9.13): kept from
     * BOOTREQUESTs only, so a server's echo cannot overwrite them. */
    if (op == 1 && have_prl)
        snprintf(e->prl, sizeof(e->prl), "%s", prl);
    if (op == 1 && have_vci)
        snprintf(e->vci, sizeof(e->vci), "%s", vci);
    /* Feed DNS cache on ACK when we have both hostname and IP */
    if (msg_type == 5 && e->ip[0] && e->hostname[0])
        dns_set_resolved(e->ip, e->hostname);
    pthread_mutex_unlock(&g_mu);

    /* Router-role evidence for the camera classifier (#155), outside
     * g_mu: lan_role has its own lock and the two never nest. A
     * BOOTREPLY from the server port is the sender acting as a server
     * or relay (RFC 2131 §4.1); option 54 names a server whichever side
     * wrote it — a client's REQUEST names the one that offered, and on
     * a switched port that broadcast is often all sloth sees of it. */
    if (op == 2 && src_port == DHCP_SERVER_PORT && src_ip)
        lan_role_note_dhcp(src_ip, LAN_ROLE_DHCP_REPLY);
    if (server_ip[0])
        lan_role_note_dhcp(server_ip, LAN_ROLE_DHCP_SID);

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
