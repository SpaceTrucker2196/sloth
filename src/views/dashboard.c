#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/dashboard.h"
#include "bandwidth.h"

/* Compact byte-count formatter — kept local. */
static void fmt_bytes(uint64_t b, char *buf, int sz) {
    if      (b >= (uint64_t)1 << 30)
        snprintf(buf, sz, "%.1fGB", (double)b / (double)((uint64_t)1 << 30));
    else if (b >= (uint64_t)1 << 20)
        snprintf(buf, sz, "%.1fMB", (double)b / (double)((uint64_t)1 << 20));
    else if (b >= (uint64_t)1 << 10)
        snprintf(buf, sz, "%.1fKB", (double)b / (double)((uint64_t)1 << 10));
    else
        snprintf(buf, sz, "%lluB",  (unsigned long long)b);
}

static const char *proto_short(int p) {
    if (p == PROTO_TCP) return "TCP";
    if (p == PROTO_UDP) return "UDP";
    return "?";
}

/* DHCP message-type name (RFC 2132 §9.6). */
static const char *dhcp_msg_name(uint8_t t) {
    switch (t) {
    case 1: return "DISCOVER";
    case 2: return "OFFER";
    case 3: return "REQUEST";
    case 4: return "DECLINE";
    case 5: return "ACK";
    case 6: return "NAK";
    case 7: return "RELEASE";
    case 8: return "INFORM";
    default: return "?";
    }
}

/* Find the rate-history record for an iface by name. */
static const iface_hist_t *hist_lookup(const sloth_state_t *s, const char *name) {
    for (int i = 0; i < MAX_IFACES; i++) {
        if (s->iface_hist[i].name[0] &&
            strcmp(s->iface_hist[i].name, name) == 0)
            return &s->iface_hist[i];
    }
    return NULL;
}

#ifndef WITH_NCURSES
/* Build a plain-ASCII / UTF-8 sparkline into a string buffer. Only used by
 * the ANSI fallback — the ncurses path uses draw_sparkline_at() which
 * renders directly with per-glyph color attributes. */
static void sparkline(const double *vals, int head, int n,
                      int width, char *out, int outsz) {
    double max = 0.0;
    for (int i = 0; i < n && i < HIST_LEN; i++)
        if (vals[i] > max) max = vals[i];

    static const char *glyph[9] = {
        "_",                /* level 0 — emitted directly below */
        "\xe2\x96\x81",     /* ▁ */
        "\xe2\x96\x82",     /* ▂ */
        "\xe2\x96\x83",     /* ▃ */
        "\xe2\x96\x84",     /* ▄ */
        "\xe2\x96\x85",     /* ▅ */
        "\xe2\x96\x86",     /* ▆ */
        "\xe2\x96\x87",     /* ▇ */
        "\xe2\x96\x88",     /* █ */
    };

    int pos = 0;
    out[0] = '\0';
    for (int i = 0; i < width; i++) {
        int age = (width - 1) - i;  /* 0 = newest, width-1 = oldest */
        if (age >= n) {
            if (pos + 1 < outsz) out[pos++] = '_';
            continue;
        }
        int slot = (head - 1 - age + HIST_LEN) % HIST_LEN;
        double v = vals[slot];
        if (v <= 0.0 || max <= 0.0) {
            if (pos + 1 < outsz) out[pos++] = '_';
        } else {
            int lvl = (int)((v / max) * 8.0 + 0.5);
            if (lvl < 1) lvl = 1;
            if (lvl > 8) lvl = 8;
            if (pos + 3 < outsz) {
                out[pos++] = glyph[lvl][0];
                out[pos++] = glyph[lvl][1];
                out[pos++] = glyph[lvl][2];
            }
        }
    }
    out[pos] = '\0';
}
#endif /* !WITH_NCURSES */

/* sparkline width in glyph cells — used by both builds. */
#define SPARK_W 24

#ifdef WITH_NCURSES

#define DASH_TOP_Y     2        /* below tabbar + hline */
#define MIN_PANEL_H    4        /* title + header + 2 data rows */

/* Render a sparkline directly to (y,x) with heat-graded colors per glyph.
 * Levels:
 *   0      -> CP_DIM '_'
 *   1..2   -> CP_NORMAL  (cool phosphor — quiet)
 *   3..4   -> CP_HEAT_MID
 *   5..6   -> CP_HEAT_HI
 *   7..8   -> CP_HEAT_PEAK */
static void draw_sparkline_at(int y, int x, int width,
                              const double *vals, int head, int n) {
    double max = 0.0;
    for (int i = 0; i < n && i < HIST_LEN; i++)
        if (vals[i] > max) max = vals[i];

    static const char *glyph[9] = {
        "_",
        "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83",
        "\xe2\x96\x84", "\xe2\x96\x85", "\xe2\x96\x86",
        "\xe2\x96\x87", "\xe2\x96\x88",
    };

    move(y, x);
    for (int i = 0; i < width; i++) {
        int age = (width - 1) - i;
        int lvl = 0;
        if (age < n) {
            int slot = (head - 1 - age + HIST_LEN) % HIST_LEN;
            double v = vals[slot];
            if (v > 0.0 && max > 0.0) {
                lvl = (int)((v / max) * 8.0 + 0.5);
                if (lvl < 1) lvl = 1;
                if (lvl > 8) lvl = 8;
            }
        }
        if      (lvl == 0)  attrset(COLOR_PAIR(CP_DIM));
        else if (lvl <= 2)  attrset(COLOR_PAIR(CP_NORMAL));
        else if (lvl <= 4)  attrset(COLOR_PAIR(CP_HEAT_MID));
        else if (lvl <= 6)  attrset(COLOR_PAIR(CP_HEAT_HI));
        else                attrset(COLOR_PAIR(CP_HEAT_PEAK));
        addstr(glyph[lvl]);
    }
}

/* Position then print one line, padded to `w` chars. ASCII / single-byte. */
static void clipline(int y, int x, int w, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int n = (int)strlen(buf);
    if (n > w) n = w;
    move(y, x);
    addnstr(buf, n);
    for (int i = n; i < w; i++) addch(' ');
}

static void panel_title(int y, int x, int w, const char *name) {
    attrset(COLOR_PAIR(CP_DIM));
    move(y, x);
    int filled = 0;
    int len = (int)strlen(name);
    for (int i = 0; i < 3  && filled < w; i++, filled++) addch('-');
    if (filled < w) { addch(' '); filled++; }
    for (int i = 0; i < len && filled < w; i++, filled++) addch(name[i]);
    if (filled < w) { addch(' '); filled++; }
    for (; filled < w; filled++) addch('-');
}

/* ── Interfaces row with sparklines ──────────────────────── */

/* Column geometry: 2 (margin) + 8 (name) + 10 (rx/s) + 10 (tx/s) +
 * 10 (rx tot) + 10 (tx tot) + 2 (sep) + SPARK_W + 2 (sep) + SPARK_W
 * + trailing fill. With SPARK_W=24 the fixed-width prefix ends at col 54
 * and each sparkline occupies the next 24 cols. */
#define IFACE_FIXED_W   54
#define IFACE_RX_X      IFACE_FIXED_W
#define IFACE_TX_X      (IFACE_FIXED_W + SPARK_W + 2)
#define IFACE_END_X     (IFACE_TX_X + SPARK_W)

static void draw_iface_band(const sloth_state_t *s, int y0, int h, int w) {
    panel_title(y0, 0, w, "Interfaces");

    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, 0, IFACE_FIXED_W,
             "  %-8s  %10s  %10s  %10s  %10s",
             "iface", "rx/s", "tx/s", "rx total", "tx total");
    /* sparkline column headers */
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, IFACE_RX_X, SPARK_W,     "rx graph");
    clipline(y0 + 1, IFACE_TX_X, SPARK_W,     "tx graph");
    /* clear remainder of the header line so the full-width band stays clean */
    if (IFACE_END_X < w)
        clipline(y0 + 1, IFACE_END_X, w - IFACE_END_X, "");

    int rows = h - 2;
    int n    = s->iface_count < rows ? s->iface_count : rows;
    for (int i = 0; i < n; i++) {
        const iface_stat_t *I = &s->ifaces[i];
        char rxr[16], txr[16], rxt[16], txt[16];
        bw_fmt_rate(I->rx_rate, rxr, sizeof(rxr));
        bw_fmt_rate(I->tx_rate, txr, sizeof(txr));
        fmt_bytes(I->rx_bytes, rxt, sizeof(rxt));
        fmt_bytes(I->tx_bytes, txt, sizeof(txt));

        int y = y0 + 2 + i;
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y, 0, IFACE_FIXED_W,
                 "  %-8.8s  %10s  %10s  %10s  %10s",
                 I->name, rxr, txr, rxt, txt);

        const iface_hist_t *H = hist_lookup(s, I->name);
        if (H) {
            draw_sparkline_at(y, IFACE_RX_X, SPARK_W, H->rx, H->head, H->count);
            draw_sparkline_at(y, IFACE_TX_X, SPARK_W, H->tx, H->head, H->count);
        } else {
            /* no history yet — paint underscores */
            attrset(COLOR_PAIR(CP_DIM));
            move(y, IFACE_RX_X);
            for (int j = 0; j < SPARK_W; j++) addch('_');
            move(y, IFACE_TX_X);
            for (int j = 0; j < SPARK_W; j++) addch('_');
        }
        /* erase trailing cols so the full-width band stays clean */
        if (IFACE_END_X < w) {
            attrset(COLOR_PAIR(CP_NORMAL));
            clipline(y, IFACE_END_X, w - IFACE_END_X, "");
        }
    }
    /* erase any unused iface rows so prior frames don't leak through */
    for (int i = n; i < rows; i++) {
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, 0, w, "");
    }
}

/* ── Connections (scrollable, follows conn_sel) ──────────── */

static void draw_conn_band(const sloth_state_t *s, int y0, int h, int w) {
    panel_title(y0, 0, w, "Connections");

    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, 0, w, "  %-21s -> %-25s %-5s %5s %5s  %s",
             "Local", "Remote", "Proto", "St", "PID", "Process");

    int rows = h - 2;
    if (rows < 1) return;

    int n = s->conn_count;
    int top = s->conn_sel - rows / 2;
    if (top + rows > n) top = n - rows;
    if (top < 0)        top = 0;
    int end = top + rows;
    if (end > n)        end = n;

    for (int i = top; i < end; i++) {
        const conn_t *c = &s->conns[i];
        char local[64], remote[64];
        snprintf(local,  sizeof(local),  "%s:%u",
                 c->local_addr,  (unsigned)c->local_port);
        snprintf(remote, sizeof(remote), "%s:%u",
                 c->remote_addr, (unsigned)c->remote_port);

        if (i == s->conn_sel)
            attrset(A_REVERSE | COLOR_PAIR(CP_BRIGHT));
        else
            attrset(COLOR_PAIR(CP_NORMAL));

        clipline(y0 + 2 + (i - top), 0, w,
                 "  %-21.21s -> %-25.25s %-5s %5d %5d  %.16s",
                 local, remote, proto_short(c->proto),
                 c->state, c->pid, c->proc);
    }
    /* Erase any trailing rows so the conn band can shrink without
       leaving stale entries behind. */
    for (int i = end - top; i < rows; i++) {
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, 0, w, "");
    }
}

/* ── Packets (real-time scroll: newest at top each frame) ── */

static void draw_packets_band(const sloth_state_t *s, int y0, int h, int w) {
    panel_title(y0, 0, w, "Packets (live)");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, 0, w, "  %-8s  %-21s -> %-21s  %-5s  %s",
             "time", "src", "dst", "proto", "info");

    int rows = h - 2;
    if (rows < 1) return;

    int show = s->pkt_count < rows ? s->pkt_count : rows;
    for (int i = 0; i < rows; i++) {
        if (i >= show) {
            attrset(COLOR_PAIR(CP_NORMAL));
            clipline(y0 + 2 + i, 0, w, "");
            continue;
        }
        /* newest first */
        int slot = (s->pkt_head - 1 - i + MAX_PACKETS) % MAX_PACKETS;
        const packet_info_t *p = &s->packets[slot];

        char ts_buf[12];
        time_t t = (time_t)p->ts_sec;
        struct tm *tm = localtime(&t);
        if (tm) strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        else    snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

        char src[28], dst[28];
        snprintf(src, sizeof(src), "%s:%u", p->src, (unsigned)p->src_port);
        snprintf(dst, sizeof(dst), "%s:%u", p->dst, (unsigned)p->dst_port);

        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, 0, w,
                 "  %-8s  %-21.21s -> %-21.21s  %-5s  %.*s",
                 ts_buf, src, dst, proto_short(p->proto),
                 w - 70 > 0 ? w - 70 : 8, p->info);
    }
}

/* ── Bottom panels ───────────────────────────────────────── */

static void draw_wifi_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "WiFi APs");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-18s %4s %3s", "SSID", "sig", "ch");
    int rows = h - 2;
    int n = s->ap_count < rows ? s->ap_count : rows;
    for (int i = 0; i < n; i++) {
        const wifi_ap_t *a = &s->aps[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-18.18s %4d %3d",
                 a->ssid[0] ? a->ssid : "(hidden)",
                 a->signal_dbm, a->channel);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_probe_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "Probe clients");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-17s %-12s %4s",
             "MAC", "SSID", "sig");
    int rows = h - 2;
    int n = s->probe_count < rows ? s->probe_count : rows;
    for (int i = 0; i < n; i++) {
        const probe_client_t *p = &s->probe_clients[i];
        char mac[20];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 p->mac[0], p->mac[1], p->mac[2],
                 p->mac[3], p->mac[4], p->mac[5]);
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-17s %-12.12s %4d",
                 mac, p->ssid[0] ? p->ssid : "(any)",
                 p->signal_dbm);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_beacon_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "Beacons");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-18s %4s %3s", "SSID", "sig", "ch");
    int rows = h - 2;
    int n = s->beacon_count < rows ? s->beacon_count : rows;
    for (int i = 0; i < n; i++) {
        const beacon_ap_t *b = &s->beacon_aps[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-18.18s %4d %3d",
                 b->ssid[0] ? b->ssid : "(hidden)",
                 b->signal_dbm, b->channel);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_mdns_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "mDNS services");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-22s %-6s", "instance", "port");
    int rows = h - 2;
    int n = s->mdns_count < rows ? s->mdns_count : rows;
    for (int i = 0; i < n; i++) {
        const mdns_service_t *m = &s->mdns_services[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-22.22s %-6u",
                 m->instance[0] ? m->instance : m->service,
                 (unsigned)m->port);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_dhcp_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "DHCP events");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-9s %-15s %s", "msg", "ip", "host");
    int rows = h - 2;
    /* Newest first across the live-event ring. */
    int n = s->dhcp_event_count < rows ? s->dhcp_event_count : rows;
    for (int i = 0; i < n; i++) {
        int slot = s->dhcp_event_count - 1 - i;
        if (slot < 0) break;
        const dhcp_event_t *e = &s->dhcp_events[slot];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-9s %-15.15s %s",
                 dhcp_msg_name(e->msg_type),
                 e->ip[0] ? e->ip : "-",
                 e->hostname[0] ? e->hostname : "");
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_arp_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "ARP table");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-15s %-17s", "ip", "mac");
    int rows = h - 2;
    int n = s->arp_count < rows ? s->arp_count : rows;
    for (int i = 0; i < n; i++) {
        const arp_entry_t *a = &s->arp_entries[i];
        char mac[20];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 a->mac[0], a->mac[1], a->mac[2],
                 a->mac[3], a->mac[4], a->mac[5]);
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-15.15s %-17s", a->ip, mac);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_deauth_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "Deauth");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-17s %5s %s",
             "target", "rsn", "flood");
    int rows = h - 2;
    int n = s->deauth_count < rows ? s->deauth_count : rows;
    for (int i = 0; i < n; i++) {
        const deauth_event_t *e = &s->deauth_events[i];
        char dst[20];
        snprintf(dst, sizeof(dst), "%02x:%02x:%02x:%02x:%02x:%02x",
                 e->dst[0], e->dst[1], e->dst[2],
                 e->dst[3], e->dst[4], e->dst[5]);
        if (e->flood) attrset(COLOR_PAIR(CP_HEAT_PEAK));
        else          attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-17s %5u %s",
                 dst, (unsigned)e->reason, e->flood ? "FLOOD" : "");
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_stats_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "Summary");
    /* Compose a few summary counters. */
    int crit_n = 0, warn_n = 0;
    for (int i = 0; i < s->alert_count; i++) {
        if (s->alerts[i].sev == ALERT_SEV_CRIT) crit_n++;
        else if (s->alerts[i].sev == ALERT_SEV_WARN) warn_n++;
    }
    int tcp_n = 0, udp_n = 0;
    for (int i = 0; i < s->conn_count; i++) {
        if (s->conns[i].proto == PROTO_TCP)      tcp_n++;
        else if (s->conns[i].proto == PROTO_UDP) udp_n++;
    }

    struct { const char *label; char val[40]; } rows_data[6];
    int rc = 0;
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d / %d", s->iface_count, s->ap_count); rows_data[rc++].label = "iface/ap ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d (TCP %d, UDP %d)", s->conn_count, tcp_n, udp_n);
                                                       rows_data[rc++].label = "conns    ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d", s->device_count);                  rows_data[rc++].label = "devices  ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d (DNS %d / TLS %d)",
             s->dns_log_count + s->tls_log_count +
             s->quic_log_count + s->http_log_count,
             s->dns_log_count, s->tls_log_count);     rows_data[rc++].label = "log evts ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d crit %d warn", crit_n, warn_n);      rows_data[rc++].label = "alerts   ";
    snprintf(rows_data[rc].val, sizeof(rows_data[rc].val),
             "%d", s->scan_count);                     rows_data[rc++].label = "scanners ";

    int rows = h - 1;          /* no header line — just the panel title */
    int n = rc < rows ? rc : rows;
    for (int i = 0; i < n; i++) {
        attrset(COLOR_PAIR(CP_DIM));
        clipline(y0 + 1 + i, x, w, "  %-9s", rows_data[i].label);
        attrset(COLOR_PAIR(CP_NORMAL));
        /* overprint the value to the right of the label */
        move(y0 + 1 + i, x + 2 + 9 + 1);
        addstr(rows_data[i].val);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 1 + i, x, w, "");
}

static void draw_ssdp_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "SSDP / UPnP");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-15s %s", "ip", "type");
    int rows = h - 2;
    int n = s->ssdp_count < rows ? s->ssdp_count : rows;
    for (int i = 0; i < n; i++) {
        const ssdp_device_t *d = &s->ssdp_devices[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-15.15s %.*s",
                 d->ip, w - 18 > 0 ? w - 18 : 8, d->type);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

#endif /* WITH_NCURSES */

/* ── Public draw / key ───────────────────────────────────── */

void view_dashboard_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int lines = LINES;
    int cols  = COLS;

    /* Minimum viable layout:
     *   header(2) + iface(3, =2 hdr + 1 iface)
     *   + 5 panel rows each MIN_PANEL_H (=4) (3 bottom rows + 2 doubles for
     *     conn + packets, but conn/packets each are 2*MIN_PANEL_H=8)
     *   = 2 + 3 + 3*4 + 2*8 = 33 lines */
    int min_lines = 2 + 3 + 3 * MIN_PANEL_H + 2 * (2 * MIN_PANEL_H);
    if (lines < min_lines || cols < IFACE_END_X + 2) {
        tui_dim();
        TPRINT(" Dashboard: terminal too small "
               "(need >=%d cols, >=%d rows; this is %dx%d)\n",
               IFACE_END_X + 2, min_lines, cols, lines);
        tui_normal();
        return;
    }

    int iface_y = DASH_TOP_Y;
    /* iface band expands as needed to show every iface (title + header +
     * one row per iface). Cap at a third of the screen so a host with
     * 20 ifaces can't smother the rest of the dashboard. */
    int iface_cap = lines / 3;
    int desired_iface = 2 + (s->iface_count > 0 ? s->iface_count : 1);
    int iface_h = desired_iface < iface_cap ? desired_iface : iface_cap;

    /* Remaining space split among 5 bands:
     *   conn    = 2H   (twice the bottom rows)
     *   packets = 2H
     *   bot1    = H
     *   bot2    = H
     *   bot3    = H
     *   total   = 7H
     * Spare rows from the integer divide go to conn and packets so the
     * dashboard fills the terminal exactly. */
    int avail = lines - iface_y - iface_h;
    int H = avail / 7;
    if (H < MIN_PANEL_H) H = MIN_PANEL_H;

    int bot1_h    = H;
    int bot2_h    = H;
    int bot3_h    = H;
    int conn_h    = 2 * H;
    int packets_h = 2 * H;
    int used      = conn_h + packets_h + bot1_h + bot2_h + bot3_h;
    int extra     = avail - used;
    if (extra > 0) {
        conn_h    += extra / 2;
        packets_h += extra - extra / 2;
    }

    int conn_y    = iface_y + iface_h;
    int packets_y = conn_y    + conn_h;
    int bot1_y    = packets_y + packets_h;
    int bot2_y    = bot1_y    + bot1_h;
    int bot3_y    = bot2_y    + bot2_h;

    draw_iface_band  (s, iface_y,   iface_h,   cols);
    draw_conn_band   (s, conn_y,    conn_h,    cols);
    draw_packets_band(s, packets_y, packets_h, cols);

    int pw1 = cols / 3;
    int pw2 = cols / 3;
    int pw3 = cols - pw1 - pw2;
    draw_wifi_panel  (s, bot1_y, bot1_h, 0,                 pw1);
    draw_probe_panel (s, bot1_y, bot1_h, pw1,               pw2);
    draw_beacon_panel(s, bot1_y, bot1_h, pw1 + pw2,         pw3);

    draw_mdns_panel  (s, bot2_y, bot2_h, 0,                 pw1);
    draw_dhcp_panel  (s, bot2_y, bot2_h, pw1,               pw2);
    draw_ssdp_panel  (s, bot2_y, bot2_h, pw1 + pw2,         pw3);

    draw_arp_panel   (s, bot3_y, bot3_h, 0,                 pw1);
    draw_deauth_panel(s, bot3_y, bot3_h, pw1,               pw2);
    draw_stats_panel (s, bot3_y, bot3_h, pw1 + pw2,         pw3);

    attrset(COLOR_PAIR(CP_NORMAL));
#else
    /* ANSI fallback: stacked sections, no tiling. Sparklines still render. */
    tui_normal(); TPRINT(" Dashboard ");
    tui_dim();    TPRINT("(stacked layout - ncurses build tiles into bands)\n\n");

    tui_dim();    TPRINT(" -- Interfaces --\n");
    tui_normal();
    for (int i = 0; i < s->iface_count && i < 4; i++) {
        const iface_stat_t *I = &s->ifaces[i];
        char rxr[16], txr[16], rxt[16], txt[16];
        bw_fmt_rate(I->rx_rate, rxr, sizeof(rxr));
        bw_fmt_rate(I->tx_rate, txr, sizeof(txr));
        fmt_bytes(I->rx_bytes, rxt, sizeof(rxt));
        fmt_bytes(I->tx_bytes, txt, sizeof(txt));
        char spark[SPARK_W * 3 + 1] = "____________";
        const iface_hist_t *H = NULL;
        for (int j = 0; j < MAX_IFACES; j++) {
            if (s->iface_hist[j].name[0] &&
                strcmp(s->iface_hist[j].name, I->name) == 0) {
                H = &s->iface_hist[j]; break;
            }
        }
        if (H) sparkline(H->rx, H->head, H->count,
                         SPARK_W, spark, sizeof(spark));
        TPRINT("  %-10s  rx/s=%-10s  tx/s=%-10s  rx=%-10s  tx=%-10s  rx:%s\n",
               I->name, rxr, txr, rxt, txt, spark);
    }

    tui_dim();    TPRINT("\n -- Connections --\n");
    tui_normal();
    int cn = s->conn_count < 6 ? s->conn_count : 6;
    for (int i = 0; i < cn; i++) {
        const conn_t *c = &s->conns[i];
        TPRINT("  %s:%u -> %s:%u  %s pid=%d %s\n",
               c->local_addr,  (unsigned)c->local_port,
               c->remote_addr, (unsigned)c->remote_port,
               proto_short(c->proto), c->pid, c->proc);
    }

    tui_dim();    TPRINT("\n -- Packets (live) --\n");
    tui_normal();
    int pn = s->pkt_count < 5 ? s->pkt_count : 5;
    for (int i = 0; i < pn; i++) {
        int slot = (s->pkt_head - 1 - i + MAX_PACKETS) % MAX_PACKETS;
        const packet_info_t *p = &s->packets[slot];
        TPRINT("  %s:%u -> %s:%u  %s  %s\n",
               p->src, (unsigned)p->src_port,
               p->dst, (unsigned)p->dst_port,
               proto_short(p->proto), p->info);
    }

    tui_dim();    TPRINT("\n -- WiFi / Probe / Beacons --\n");
    tui_normal();
    for (int i = 0; i < s->ap_count && i < 3; i++)
        TPRINT("  AP   %-20s sig=%d ch=%d\n",
               s->aps[i].ssid[0] ? s->aps[i].ssid : "(hidden)",
               s->aps[i].signal_dbm, s->aps[i].channel);
    for (int i = 0; i < s->probe_count && i < 3; i++) {
        const probe_client_t *p = &s->probe_clients[i];
        TPRINT("  Probe %02x:%02x:%02x:%02x:%02x:%02x  %s\n",
               p->mac[0], p->mac[1], p->mac[2],
               p->mac[3], p->mac[4], p->mac[5],
               p->ssid[0] ? p->ssid : "(any)");
    }
    for (int i = 0; i < s->beacon_count && i < 3; i++)
        TPRINT("  Bcn  %-20s sig=%d ch=%d\n",
               s->beacon_aps[i].ssid[0] ? s->beacon_aps[i].ssid : "(hidden)",
               s->beacon_aps[i].signal_dbm, s->beacon_aps[i].channel);

    tui_dim();    TPRINT("\n -- mDNS / DHCP / SSDP --\n");
    tui_normal();
    for (int i = 0; i < s->mdns_count && i < 3; i++)
        TPRINT("  mDNS  %s  port=%u\n",
               s->mdns_services[i].instance[0]
                 ? s->mdns_services[i].instance
                 : s->mdns_services[i].service,
               (unsigned)s->mdns_services[i].port);
    for (int i = 0; i < s->dhcp_event_count && i < 3; i++) {
        int slot = s->dhcp_event_count - 1 - i;
        const dhcp_event_t *e = &s->dhcp_events[slot];
        TPRINT("  DHCP  %s  ip=%s  host=%s\n",
               dhcp_msg_name(e->msg_type),
               e->ip[0] ? e->ip : "-",
               e->hostname[0] ? e->hostname : "");
    }
    for (int i = 0; i < s->ssdp_count && i < 3; i++)
        TPRINT("  SSDP  %s  %s\n",
               s->ssdp_devices[i].ip, s->ssdp_devices[i].type);

    tui_dim();    TPRINT("\n -- ARP / Deauth / Stats --\n");
    tui_normal();
    for (int i = 0; i < s->arp_count && i < 3; i++) {
        const arp_entry_t *a = &s->arp_entries[i];
        TPRINT("  ARP   %-15s  %02x:%02x:%02x:%02x:%02x:%02x\n",
               a->ip,
               a->mac[0], a->mac[1], a->mac[2],
               a->mac[3], a->mac[4], a->mac[5]);
    }
    for (int i = 0; i < s->deauth_count && i < 3; i++) {
        const deauth_event_t *e = &s->deauth_events[i];
        TPRINT("  Deauth dst=%02x:%02x:%02x:%02x:%02x:%02x rsn=%u %s\n",
               e->dst[0], e->dst[1], e->dst[2],
               e->dst[3], e->dst[4], e->dst[5],
               (unsigned)e->reason, e->flood ? "FLOOD" : "");
    }
    TPRINT("  Summary: ifaces=%d aps=%d conns=%d devices=%d alerts=%d\n",
           s->iface_count, s->ap_count, s->conn_count,
           s->device_count, s->alert_count);
#endif
}

void view_dashboard_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->conn_sel > 0) s->conn_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->conn_count > 0 && s->conn_sel < s->conn_count - 1)
            s->conn_sel++;
        break;
    default:
        break;
    }
}
