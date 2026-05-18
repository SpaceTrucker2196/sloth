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

/* Build a UTF-8 sparkline of `width` glyphs from the most recent samples
 * in `vals` (a ring of capacity HIST_LEN with `head` pointing to the next
 * write slot, `n` samples populated).
 *
 *   0           -> '_'  (single byte, per request)
 *   >0..max     -> '▁'..'█' (block-eighths, 3 UTF-8 bytes each)
 *   missing     -> '_'  (no data that far back)
 *
 * `out` should be at least width*3+1 bytes. */
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

/* sparkline width in glyph cells — used by both builds. */
#define SPARK_W 12

#ifdef WITH_NCURSES

#define DASH_TOP_Y     2        /* below tabbar + hline */
#define IFACE_BAND_H   7
#define BOTTOM_BAND_H  7

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

static void draw_iface_band(const sloth_state_t *s, int y0, int h, int w) {
    panel_title(y0, 0, w, "Interfaces");

    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, 0, w,
             "  %-10s  %10s  %10s  %10s  %10s   %-*s  %-*s",
             "iface", "rx/s", "tx/s", "rx total", "tx total",
             SPARK_W, "rx graph", SPARK_W, "tx graph");

    int rows = h - 2;
    int n    = s->iface_count < rows ? s->iface_count : rows;
    for (int i = 0; i < n; i++) {
        const iface_stat_t *I = &s->ifaces[i];
        char rxr[16], txr[16], rxt[16], txt[16];
        bw_fmt_rate(I->rx_rate, rxr, sizeof(rxr));
        bw_fmt_rate(I->tx_rate, txr, sizeof(txr));
        fmt_bytes(I->rx_bytes, rxt, sizeof(rxt));
        fmt_bytes(I->tx_bytes, txt, sizeof(txt));

        char rx_spark[SPARK_W * 3 + 1] = "____________";
        char tx_spark[SPARK_W * 3 + 1] = "____________";
        const iface_hist_t *H = hist_lookup(s, I->name);
        if (H) {
            sparkline(H->rx, H->head, H->count,
                      SPARK_W, rx_spark, sizeof(rx_spark));
            sparkline(H->tx, H->head, H->count,
                      SPARK_W, tx_spark, sizeof(tx_spark));
        }

        attrset(COLOR_PAIR(CP_NORMAL));
        int y = y0 + 2 + i;
        /* Fixed-width portion via clipline. */
        clipline(y, 0, 64,
                 "  %-10.10s  %10s  %10s  %10s  %10s   ",
                 I->name, rxr, txr, rxt, txt);
        /* Sparklines via raw addstr (UTF-8 is multi-byte; mvprintw
           would miscount columns). */
        move(y, 64);  addstr(rx_spark);
        move(y, 64 + SPARK_W + 2); addstr(tx_spark);
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

    /* Reserve fixed bands: header(2) + iface(7) + bottom_r1(7) + bottom_r2(7)
     * = 23, plus at least 3 each for conn and packets. So minimum is 29. */
    if (lines < 29 || cols < 90) {
        tui_dim();
        TPRINT(" Dashboard: terminal too small "
               "(need >=90 cols, >=29 rows; this is %dx%d)\n",
               cols, lines);
        tui_normal();
        return;
    }

    int iface_y = DASH_TOP_Y;
    int iface_h = IFACE_BAND_H;

    int bot1_h = BOTTOM_BAND_H;
    int bot2_h = BOTTOM_BAND_H;

    int bot2_y = lines - bot2_h;
    int bot1_y = bot2_y - bot1_h;

    int middle_y = iface_y + iface_h;
    int middle_h = bot1_y - middle_y;
    /* Split middle into Connections (top) and Packets (bottom). */
    int conn_h    = middle_h / 2;
    int packets_h = middle_h - conn_h;
    int conn_y    = middle_y;
    int packets_y = conn_y + conn_h;

    draw_iface_band  (s, iface_y,   iface_h,   cols);
    draw_conn_band   (s, conn_y,    conn_h,    cols);
    draw_packets_band(s, packets_y, packets_h, cols);

    int pw = cols / 3;
    draw_wifi_panel  (s, bot1_y, bot1_h, 0,            pw);
    draw_probe_panel (s, bot1_y, bot1_h, pw,           pw);
    draw_beacon_panel(s, bot1_y, bot1_h, pw * 2,       cols - pw * 2);

    draw_mdns_panel  (s, bot2_y, bot2_h, 0,            pw);
    draw_dhcp_panel  (s, bot2_y, bot2_h, pw,           pw);
    draw_ssdp_panel  (s, bot2_y, bot2_h, pw * 2,       cols - pw * 2);

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
