#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "views/osi.h"

/* Box-drawing glyphs (UTF-8). Same as the dashboard's set; duplicated
 * here so this view doesn't reach into dashboard_internal.h. */
#define G_HORIZ "\xe2\x94\x80"   /* ─  U+2500 */
#define G_VERT  "\xe2\x94\x82"   /* │  U+2502 */
#define G_TL    "\xe2\x94\x8c"   /* ┌  U+250C */
#define G_TR    "\xe2\x94\x90"   /* ┐  U+2510 */
#define G_BL    "\xe2\x94\x94"   /* └  U+2514 */
#define G_BR    "\xe2\x94\x98"   /* ┘  U+2518 */
#define G_LT    "\xe2\x94\x9c"   /* ├  U+251C */
#define G_RT    "\xe2\x94\xa4"   /* ┤  U+2524 */

/* Per-layer presentation: label column on the left, observations on the
 * right. Layers are drawn top→bottom L7→L1, the way packets stack down
 * the wire view. */

/* Each call counts unique (remote_addr) strings, IPv4 vs IPv6 split. */
static void count_remote_hosts(const sloth_state_t *s,
                                int *out_v4, int *out_v6) {
    int v4 = 0, v6 = 0;
    char seen[MAX_CONNS][46];
    int  n_seen = 0;
    for (int i = 0; i < s->conn_count; i++) {
        const char *ip = s->conns[i].remote_addr;
        if (!ip[0]) continue;
        int dup = 0;
        for (int j = 0; j < n_seen; j++)
            if (strcmp(seen[j], ip) == 0) { dup = 1; break; }
        if (dup) continue;
        if (n_seen < MAX_CONNS) {
            snprintf(seen[n_seen], sizeof(seen[n_seen]), "%s", ip);
            n_seen++;
        }
        if (strchr(ip, ':')) v6++; else v4++;
    }
    *out_v4 = v4;
    *out_v6 = v6;
}

/* Sum conns by IP protocol number — L4 split. */
static void count_proto(const sloth_state_t *s,
                         int *out_tcp_est, int *out_tcp_lis,
                         int *out_tcp_other, int *out_udp) {
    int est = 0, lis = 0, other = 0, udp = 0;
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        if (c->proto == PROTO_TCP) {
            if      (c->state == 1)  est++;   /* ESTABLISHED */
            else if (c->state == 10) lis++;   /* LISTEN      */
            else                     other++;
        } else if (c->proto == PROTO_UDP) {
            udp++;
        }
    }
    *out_tcp_est   = est;
    *out_tcp_lis   = lis;
    *out_tcp_other = other;
    *out_udp       = udp;
}

/* TLS-version histogram from the rolling tls_log. Returns count of
 * (TLS 1.3, TLS 1.2, legacy <= 1.1) seen in the log window. */
static void count_tls_versions(const sloth_state_t *s,
                                int *v13, int *v12, int *legacy) {
    int t13 = 0, t12 = 0, leg = 0;
    for (int i = 0; i < s->tls_log_count; i++) {
        const char *v = s->tls_log[i].tls_ver;
        if      (strcmp(v, "TLS 1.3") == 0) t13++;
        else if (strcmp(v, "TLS 1.2") == 0) t12++;
        else if (strcmp(v, "TLS 1.1") == 0 ||
                 strcmp(v, "TLS 1.0") == 0 ||
                 strcmp(v, "SSL 3.0") == 0 ||
                 strcmp(v, "SSL 2.0") == 0) leg++;
    }
    *v13    = t13;
    *v12    = t12;
    *legacy = leg;
}

/* Number of distinct JA3 fingerprints seen — a rough "TLS client
 * diversity" metric at the session layer. */
static int count_distinct_ja3(const sloth_state_t *s) {
    char seen[MAX_TLS_LOG][33];
    int  n = 0;
    for (int i = 0; i < s->tls_log_count; i++) {
        const char *ja3 = s->tls_log[i].ja3;
        if (!ja3[0]) continue;
        int dup = 0;
        for (int j = 0; j < n; j++)
            if (strcmp(seen[j], ja3) == 0) { dup = 1; break; }
        if (dup) continue;
        if (n < MAX_TLS_LOG) {
            snprintf(seen[n], sizeof(seen[n]), "%s", ja3);
            n++;
        }
    }
    return n;
}

/* Pad a string with spaces to exactly width characters; truncates if
 * too long. Used to keep the left "layer label" column flush. */
static void draw_padded(const char *str, int width) {
    int n = (int)strlen(str);
    if (n >= width) {
        for (int i = 0; i < width - 1; i++) TPRINT("%c", str[i]);
        TPRINT(" ");
    } else {
        TPRINT("%s", str);
        for (int i = n; i < width; i++) TPRINT(" ");
    }
}

/* Horizontal bracket rule used to bracket the stack grid. We don't
 * draw side borders per row — the data column has variable width per
 * layer and we'd need per-cell column tracking to close it cleanly.
 * Bracketed rules + the internal label/data │ are enough to read as
 * a grid. */
static void hrule(int width) {
    tui_dim();
    TPRINT(" ");
    for (int i = 0; i < width; i++) TPRINT(G_HORIZ);
    TPRINT("\n");
    tui_normal();
}

void view_osi_draw(const sloth_state_t *s) {
    /* Header line. */
    tui_normal();
    TPRINT(" OSI / TCP-IP stack \xe2\x80\x94 passive observation per layer");
    tui_dim();
    TPRINT("   conns:");
    tui_bright(); TPRINT("%d ", s->conn_count);
    tui_dim();    TPRINT("ifaces:");
    tui_bright(); TPRINT("%d", s->iface_count);
    tui_normal(); TPRINT("\n");
    TPRINT("\n");

    /* Box width — wide enough for content; min terminal 100 (per
     * project rule) keeps this readable. */
    const int box_w   = 88;
    const int label_w = 18;    /* "L7  Application    " */

    /* Pre-compute per-layer numbers so each row is one TPRINT block. */
    int v4 = 0, v6 = 0;
    count_remote_hosts(s, &v4, &v6);

    int tcp_est = 0, tcp_lis = 0, tcp_other = 0, udp = 0;
    count_proto(s, &tcp_est, &tcp_lis, &tcp_other, &udp);

    int v13 = 0, v12 = 0, vleg = 0;
    count_tls_versions(s, &v13, &v12, &vleg);
    int ja3_distinct = count_distinct_ja3(s);

    /* Top bracket. */
    hrule(box_w);

    /* L7 — Application protocols. Counts come from the per-protocol
     * log ring buffers; ssdp_count / dhcp_count are device sightings,
     * dhcp_event_count is the protocol-level message log. */
    TPRINT("  ");
    tui_bright(); draw_padded("L7 Application", label_w);
    tui_dim();    TPRINT("%s ", G_VERT);
    tui_normal();
    TPRINT("DNS:%d  HTTP:%d  TLS:%d  QUIC:%d  mDNS:%d  NBNS:%d  NTP:%d",
           s->dns_log_count, s->http_log_count, s->tls_log_count,
           s->quic_log_count, s->mdns_count, s->nbns_count,
           s->ntp_log_count);
    TPRINT("\n");

    /* L6 — Presentation. TLS-version distribution lives here: same
     * record, different lens. Legacy (TLS 1.1 or below) is also tagged
     * by ALERT_TYPE_WEAK_TLS so the colour echoes the alert palette. */
    TPRINT("  ");
    tui_bright(); draw_padded("L6 Presentation", label_w);
    tui_dim();    TPRINT("%s ", G_VERT);
    tui_normal();
    TPRINT("TLS 1.3:%d  TLS 1.2:%d  ", v13, v12);
    if (vleg > 0) { tui_heat(0.8); TPRINT("legacy:%d ", vleg); tui_normal(); }
    else          { tui_dim();      TPRINT("legacy:0 ");       tui_normal(); }
    TPRINT(" JA3:%d distinct", ja3_distinct);
    TPRINT("\n");

    /* L5 — Session. TLS sessions, QUIC streams, EAPOL handshakes. */
    TPRINT("  ");
    tui_bright(); draw_padded("L5 Session", label_w);
    tui_dim();    TPRINT("%s ", G_VERT);
    tui_normal();
    TPRINT("TLS sessions:%d  QUIC:%d  EAPOL:%d",
           s->tls_log_count, s->quic_log_count, s->eapol_count);
    TPRINT("\n");

    /* L4 — Transport. TCP split by state (E=ESTABLISHED, L=LISTEN),
     * UDP single bucket, ICMP from the dedicated log. */
    TPRINT("  ");
    tui_bright(); draw_padded("L4 Transport", label_w);
    tui_dim();    TPRINT("%s ", G_VERT);
    tui_normal();
    TPRINT("TCP:%d (E:%d L:%d ?:%d)  UDP:%d  ICMP:%d",
           tcp_est + tcp_lis + tcp_other, tcp_est, tcp_lis, tcp_other,
           udp, s->icmp_log_count);
    TPRINT("\n");

    /* L3 — Network. Distinct remote hosts split by family. ARP
     * mappings count as L2/L3 boundary — also surface here so the
     * operator sees "how many hosts on this segment". */
    TPRINT("  ");
    tui_bright(); draw_padded("L3 Network", label_w);
    tui_dim();    TPRINT("%s ", G_VERT);
    tui_normal();
    TPRINT("IPv4 hosts:%d  IPv6 hosts:%d  ARP mappings:%d",
           v4, v6, s->arp_count);
    TPRINT("\n");

    /* L2 — Data Link. Interface count + visible APs + WiFi stations +
     * device-table size (multi-source merged endpoints). */
    TPRINT("  ");
    tui_bright(); draw_padded("L2 Data Link", label_w);
    tui_dim();    TPRINT("%s ", G_VERT);
    tui_normal();
    TPRINT("ifaces:%d  APs:%d  STAs:%d  devices:%d  beacons:%d",
           s->iface_count, s->ap_count, s->wifi_sta_count,
           s->device_count, s->beacon_count);
    TPRINT("\n");

    /* L1 — Physical. Probe iface details (signal/channel/encryption)
     * when in monitor mode; otherwise fall back to enumerating the
     * first up iface. */
    TPRINT("  ");
    tui_bright(); draw_padded("L1 Physical", label_w);
    tui_dim();    TPRINT("%s ", G_VERT);
    tui_normal();
    if (s->probe_iface[0]) {
        TPRINT("probe iface: %s (monitor mode)", s->probe_iface);
    } else if (s->iface_count > 0) {
        TPRINT("primary iface: %s", s->ifaces[0].name);
    } else {
        tui_dim();
        TPRINT("(no iface — start sloth with -i <iface> or run as root)");
        tui_normal();
    }
    TPRINT("\n");

    /* Bottom bracket. */
    hrule(box_w);

    /* Legend / footer. */
    TPRINT("\n");
    tui_dim();
    TPRINT(" Tip: this is a synthesis view \xe2\x80\x94 drill into any layer\n");
    TPRINT("      via its own view (DNS [r], HTTP [h], TLS [t], conns [2], ...).\n");
    tui_normal();
}

void view_osi_key(sloth_state_t *s, int key) {
    (void)s; (void)key;
    /* Synthesis view: no per-row state, no navigation. Key routing
     * stays at the global level (tab/numeric/letter to switch views). */
}
