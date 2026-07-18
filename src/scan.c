#include <string.h>
#include <stdio.h>
#include <time.h>

#include "sloth.h"
#include "scan.h"

/* ── Routable-IP filter ──────────────────────────────────
   Skip RFC1918, loopback, link-local, and multicast — only
   public IPs can be external scanners.
   ──────────────────────────────────────────────────────── */

static int scan_is_routable(const char *ip) {
    unsigned a = 0, b = 0;
    if (sscanf(ip, "%u.%u", &a, &b) < 2) return 0;
    if (a == 0 || a >= 224) return 0;   /* unspecified / multicast / reserved */
    if (a == 10) return 0;              /* RFC1918 10.0.0.0/8 */
    if (a == 127) return 0;             /* loopback */
    if (a == 169 && b == 254) return 0; /* link-local */
    if (a == 172 && b >= 16 && b <= 31) return 0; /* RFC1918 172.16.0.0/12 */
    if (a == 192 && b == 168) return 0; /* RFC1918 192.168.0.0/16 */
    if (a == 100 && b >= 64 && b <= 127) return 0; /* CGNAT */
    return 1;
}

/* ── Core functions ──────────────────────────────────────── */

/* ── Local listening-port set ─────────────────────────────
   Bitmap over the 65536 TCP ports, one bit per port we LISTEN on.
   A remote peer that reaches one of these ports connected *to us*;
   those are the only connections that can be a scan. Ephemeral source
   ports we open for our own outbound flows (e.g. many parallel sockets
   to a CDN like Cloudflare/Discord) are never in this set, so outbound
   traffic can no longer masquerade as an inbound scan. See issue #41.
   ──────────────────────────────────────────────────────── */

static void scan_build_listen_set(const sloth_state_t *s, unsigned char bm[8192]) {
    memset(bm, 0, 8192);
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        if (c->proto != PROTO_TCP) continue;
        if (c->state != TCP_STATE_LISTEN) continue;
        bm[c->local_port >> 3] |= (unsigned char)(1u << (c->local_port & 7));
    }
}

static int scan_port_is_local_service(const unsigned char bm[8192], uint16_t port) {
    return (bm[port >> 3] >> (port & 7)) & 1u;
}

void scan_update(sloth_state_t *s) {
    time_t now = time(NULL);

    unsigned char listen_bm[8192];
    scan_build_listen_set(s, listen_bm);

    /* Walk TCP connections: for each remote peer that reached one of our
       listening ports, track the distinct local (service) ports it hit. */
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        if (c->proto != PROTO_TCP) continue;
        if (c->state == TCP_STATE_LISTEN) continue;   /* the listener itself */
        if (c->remote_addr[0] == '\0') continue;
        if (!scan_is_routable(c->remote_addr)) continue;
        /* Only count when the local side is the destination — i.e. the
           remote connected to a port we listen on (remote → us), not a
           local ephemeral source port from an outbound flow. */
        if (!scan_port_is_local_service(listen_bm, c->local_port)) continue;

        /* find or create entry */
        int found = -1;
        for (int j = 0; j < s->scan_count; j++) {
            if (strcmp(s->scan_entries[j].ip, c->remote_addr) == 0) {
                found = j; break;
            }
        }
        if (found < 0) {
            if (s->scan_count >= MAX_SCAN_ENTRIES) continue;
            found = s->scan_count++;
            memset(&s->scan_entries[found], 0, sizeof(s->scan_entries[found]));
            snprintf(s->scan_entries[found].ip,
                     sizeof(s->scan_entries[found].ip), "%s", c->remote_addr);
            s->scan_entries[found].first_seen = now;
        }

        scan_entry_t *e = &s->scan_entries[found];
        e->last_seen = now;

        /* union local_port into the port set */
        int dup = 0;
        for (int k = 0; k < e->port_count; k++) {
            if (e->ports[k] == c->local_port) { dup = 1; break; }
        }
        if (!dup && e->port_count < MAX_SCAN_PORTS) {
            e->ports[e->port_count++] = c->local_port;
            if (e->port_count >= SCAN_PORT_THRESH)
                e->flagged = 1;
        }
    }

    /* expire entries not refreshed within TTL */
    int new_n = 0;
    for (int i = 0; i < s->scan_count; i++) {
        if (now - s->scan_entries[i].last_seen < SCAN_TTL_SECS)
            s->scan_entries[new_n++] = s->scan_entries[i];
    }
    s->scan_count = new_n;
}

int scan_is_flagged(const sloth_state_t *s, const char *ip) {
    for (int i = 0; i < s->scan_count; i++) {
        const scan_entry_t *e = &s->scan_entries[i];
        if (e->flagged && strcmp(e->ip, ip) == 0)
            return e->port_count;
    }
    return 0;
}
