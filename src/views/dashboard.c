/* Dashboard orchestrator: layout algorithm, ANSI fallback, and the
 * cross-frame state shared between panels. The per-panel renderers
 * live in dashboard_primitives.c (drawing helpers), dashboard_bands.c
 * (wide bands), and dashboard_grid.c (smaller equal-column panels).
 * The contract between the four files is dashboard_internal.h. */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/dashboard.h"
#include "views/dashboard_internal.h"
#include "bandwidth.h"
#include "ip_color.h"

/* ── Per-frame shared state ───────────────────────────────────────
 * Defined here (the orchestrator is what populates and consumes
 * them); declared in views/dashboard_internal.h for the panels. */
int g_dash_focus;
int g_conn_order_buf[MAX_CONNS];
int g_conn_order_n;

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
        int lvl = 0;
        if (n > 0) {
            /* Stretch n samples across width screen columns.
             * i=0 is oldest (leftmost); i=width-1 is newest (rightmost). */
            int age;
            if (width <= 1) age = 0;
            else            age = ((width - 1 - i) * (n - 1)) / (width - 1);
            if (age < 0)   age = 0;
            if (age >= n)  age = n - 1;
            int slot = (head - 1 - age + HIST_LEN) % HIST_LEN;
            double v = vals[slot];
            if (v > 0.0 && max > 0.0) {
                lvl = (int)((v / max) * 8.0 + 0.5);
                if (lvl < 1) lvl = 1;
                if (lvl > 8) lvl = 8;
            }
        }
        if (lvl == 0) {
            if (pos + 1 < outsz) out[pos++] = '_';
        } else {
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

/* Map a focused panel to the view it deep-dives into when Enter is hit. */
static view_t panel_to_view(int p) {
    switch (p) {
    case DASH_PANEL_IFACE:     return VIEW_IFACE;
    case DASH_PANEL_SUMMARY:   return VIEW_STATS;
    case DASH_PANEL_CONN:      return VIEW_CONNS;
    case DASH_PANEL_TOP_HOSTS: return VIEW_CONNS;   /* no dedicated view */
    case DASH_PANEL_PACKETS:   return VIEW_PACKETS;
    case DASH_PANEL_WIFI:      return VIEW_WIFI;
    case DASH_PANEL_ROAMING:   return VIEW_PROBE;
    case DASH_PANEL_BEACONS:   return VIEW_BEACON;
    case DASH_PANEL_MDNS:      return VIEW_MDNS;
    case DASH_PANEL_DHCP:      return VIEW_DHCP;
    case DASH_PANEL_SSDP:      return VIEW_SSDP;
    case DASH_PANEL_ARP:       return VIEW_ARP;
    case DASH_PANEL_DEAUTH:    return VIEW_DEAUTH;
    case DASH_PANEL_DNS:       return VIEW_DNS;
    case DASH_PANEL_ICMP:      return VIEW_ICMP;
    case DASH_PANEL_CRIT_ALERTS: return VIEW_ALERTS;
    default:                   return VIEW_DASH;
    }
}

#ifdef WITH_NCURSES

#define DASH_TOP_Y     1        /* 1-row top margin around the dashboard */
#define DASH_BOT_PAD   1        /* matching 1-row bottom margin */
#define MIN_PANEL_H    4        /* title + header + 2 data rows */

#endif /* WITH_NCURSES */

void view_dashboard_draw(const sloth_state_t *s) {
    /* Cache focused panel so panel_title can read it without threading
     * the state through every panel helper. */
    g_dash_focus = s->dash_focus;
    if (g_dash_focus < 0 || g_dash_focus >= DASH_PANEL_COUNT)
        g_dash_focus = 0;

    /* Per-frame index: which IPs appear across multiple panels. Used by
     * tui_ip_addstr() inside every panel below for the bold flag. */
    ip_index_build(s);

    /* Per-frame conn sort by combined rx+tx rate (descending).
     * Shared via g_conn_order_buf so the conn band and the cross-panel
     * highlight both see the same order. */
    {
        int n = s->conn_count;
        static double rates[MAX_CONNS];
        for (int i = 0; i < n; i++) {
            g_conn_order_buf[i] = i;
            const conn_t *c = &s->conns[i];
            double r = 0.0;
            for (int b = 0; b < s->conn_bw_count; b++) {
                const conn_bw_t *bw = &s->conn_bw[b];
                if (bw->proto       == c->proto       &&
                    bw->local_port  == c->local_port  &&
                    bw->remote_port == c->remote_port &&
                    strcmp(bw->local_addr,  c->local_addr)  == 0 &&
                    strcmp(bw->remote_addr, c->remote_addr) == 0) {
                    r = bw->rx_rate + bw->tx_rate;
                    break;
                }
            }
            rates[i] = r;
        }
        for (int i = 0; i < n - 1; i++) {
            int best = i;
            for (int j = i + 1; j < n; j++)
                if (rates[g_conn_order_buf[j]] >
                    rates[g_conn_order_buf[best]]) best = j;
            if (best != i) {
                int tmp = g_conn_order_buf[i];
                g_conn_order_buf[i] = g_conn_order_buf[best];
                g_conn_order_buf[best] = tmp;
            }
        }
        g_conn_order_n = n;
    }

    /* Cross-panel highlight: when the conn panel has focus and a row is
     * selected, light up that row's local+remote IPs everywhere else.
     * conn_sel is the ordinal in the sorted view — translate via
     * g_conn_order_buf. */
    if (s->dash_focus == DASH_PANEL_CONN &&
        s->conn_count > 0 &&
        s->conn_sel >= 0 && s->conn_sel < g_conn_order_n) {
        const conn_t *cc = &s->conns[g_conn_order_buf[s->conn_sel]];
        tui_set_highlight_ips(cc->local_addr, cc->remote_addr);
    } else {
        tui_set_highlight_ips(NULL, NULL);
    }
#ifdef WITH_NCURSES
    int lines = LINES;
    int cols  = COLS;

    /* Bands in vertical order:
     *   iface           (2 + iface_count, capped)
     *   conn            = 2H
     *   bot1: wifi/probe/beacons    = H
     *   bot2: mdns/dhcp/ssdp        = H
     *   bot3: arp/deauth/stats      = H
     *   bot4: dns log / icmp log    = H   (added 2026-05-18)
     *   packets         = 2H         (now at the very bottom)
     *   total           = 7H + iface */
    int min_lines = 2 + 3 + 5 * MIN_PANEL_H + 2 * (2 * MIN_PANEL_H);
    /* iface band minimum: text 50 + 2*8 spark + 4 sep = 70 cols. It
     * gets 70% of (cols - 2 side pad), so we need cols >= 70 / 0.7 + 2
     * = 102. */
    int iface_band_min = IFACE_FIXED_W + 2 + 8 + 2 + 8;
    int min_cols       = (iface_band_min * 10 + 6) / 7 + 2;
    if (lines < min_lines || cols < min_cols) {
        tui_dim();
        TPRINT(" Dashboard: terminal too small "
               "(need >=%d cols, >=%d rows; this is %dx%d)\n",
               min_cols, min_lines, cols, lines);
        tui_normal();
        return;
    }

    int iface_y = DASH_TOP_Y;
    int iface_cap = lines / 3;
    int desired_iface = 2 + (s->iface_count > 0 ? s->iface_count : 1);
    int iface_h = desired_iface < iface_cap ? desired_iface : iface_cap;

    /* CRIT band gets a fixed height sized to the actual CRIT count,
     * clamped to [1, CRIT_MAX_ROWS]. When the count exceeds the cap
     * the band scrolls (see draw_crit_alerts_band). Always shows at
     * least the title + one row so the operator can tell "quiet" from
     * "off-screen". */
    int crit_n    = crit_alerts_count(s);
    int crit_rows = crit_n < 1 ? 1
                  : (crit_n > CRIT_MAX_ROWS ? CRIT_MAX_ROWS : crit_n);
    int crit_h    = 1 + crit_rows;

    /* Reserve DASH_BOT_PAD rows at the bottom so the last band doesn't
     * touch the terminal edge; subtract the fixed CRIT band too. */
    int avail = lines - iface_y - iface_h - DASH_BOT_PAD - crit_h;
    /* 2H + H + H + H/2 + H + 2H = 7.5H (conn, bot1..bot4, packets).
     * Divide by 8 — the bot3 H/2 slack lands in `extra` below. */
    int H = avail / 8;
    if (H < MIN_PANEL_H) H = MIN_PANEL_H;

    int bot1_h    = H;
    int bot2_h    = H;
    /* bot3 (ARP / Deauth) is the least-frequently-active row — shrunk
     * to half-height to give the busier bands more breathing room. */
    int bot3_h    = H / 2;
    if (bot3_h < 3) bot3_h = 3;   /* title + header + 1 data row */
    int bot4_h    = H;
    int conn_h    = 2 * H;
    int packets_h = 2 * H;
    int used      = conn_h + packets_h + bot1_h + bot2_h + bot3_h + bot4_h;
    int extra     = avail - used;
    /* Spare rows: prefer to grow conn first, then packets so the bottom
     * band always reaches the last line of the terminal. */
    if (extra > 0) {
        conn_h    += extra / 2;
        packets_h += extra - extra / 2;
    }

    /* CRIT alerts moved up to row 2 (right after iface+summary) so the
     * worst stuff lives at eye level. Everything else slides down by
     * crit_h relative to the previous layout. */
    int crit_y    = iface_y + iface_h;
    int conn_y    = crit_y  + crit_h;
    int bot1_y    = conn_y  + conn_h;
    int bot2_y    = bot1_y  + bot1_h;
    int bot3_y    = bot2_y  + bot2_h;
    int bot4_y    = bot3_y  + bot3_h;
    int packets_y = bot4_y  + bot4_h;

    /* 1-col margin on left + right (matches the 1-row top/bottom
     * margins). The dashboard sits inside a clean 1-char frame on
     * every side. */
    const int DASH_PAD_X = 1;
    int usable = cols - 2 * DASH_PAD_X;
    int x0     = DASH_PAD_X;

    /* Top row: Interfaces (70%) + Summary (30%). */
    int iface_w   = (usable * 7) / 10;
    int summary_w = usable - iface_w;
    draw_iface_band (s, iface_y, iface_h, x0,          iface_w);
    draw_stats_panel(s, iface_y, iface_h, x0 + iface_w, summary_w);
    /* Vertical divider after each panel column (skip the title row). */
    attrset(COLOR_PAIR(CP_DIM));
    for (int dy = 1; dy < iface_h; dy++) mvaddstr(iface_y + dy, x0 + iface_w, G_VERT);

    /* Row 2: CRIT alerts (full width). */
    draw_crit_alerts_band(s, crit_y, crit_h, x0, usable);

    /* Connections row: 60% conn table + 40% top hosts. */
    int conn_w  = (usable * 6) / 10;
    int hosts_w = usable - conn_w;
    /* When a monitor interface is active, this band reflects the RF world
     * (STA<->AP associations) instead of the host's IP connections. */
    if (s->probe_iface[0])
        draw_assoc_band (s, conn_y, conn_h, x0,          conn_w);
    else
        draw_conn_band  (s, conn_y, conn_h, x0,          conn_w);
    draw_top_hosts_panel(s, conn_y, conn_h, x0 + conn_w, hosts_w);
    attrset(COLOR_PAIR(CP_DIM));
    for (int dy = 1; dy < conn_h; dy++) mvaddstr(conn_y + dy, x0 + conn_w, G_VERT);

    int pw1 = usable / 3;
    int pw2 = usable / 3;
    int pw3 = usable - pw1 - pw2;
    /* bot1: WiFi | Roaming clients | Beacons. */
    draw_wifi_panel         (s, bot1_y, bot1_h, x0,             pw1);
    draw_radio_clients_panel(s, bot1_y, bot1_h, x0 + pw1,       pw2);
    draw_beacon_panel       (s, bot1_y, bot1_h, x0 + pw1 + pw2, pw3);
    attrset(COLOR_PAIR(CP_DIM));
    for (int dy = 1; dy < bot1_h; dy++) {
        mvaddstr(bot1_y + dy, x0 + pw1,       G_VERT);
        mvaddstr(bot1_y + dy, x0 + pw1 + pw2, G_VERT);
    }

    draw_mdns_panel(s, bot2_y, bot2_h, x0,             pw1);
    draw_dhcp_panel(s, bot2_y, bot2_h, x0 + pw1,       pw2);
    draw_ssdp_panel(s, bot2_y, bot2_h, x0 + pw1 + pw2, pw3);
    attrset(COLOR_PAIR(CP_DIM));
    for (int dy = 1; dy < bot2_h; dy++) {
        mvaddstr(bot2_y + dy, x0 + pw1,       G_VERT);
        mvaddstr(bot2_y + dy, x0 + pw1 + pw2, G_VERT);
    }

    /* bot3: 50/50 split for ARP + Deauth. */
    int arp_w    = usable / 2;
    int deauth_w = usable - arp_w;
    draw_arp_panel   (s, bot3_y, bot3_h, x0,         arp_w);
    draw_deauth_panel(s, bot3_y, bot3_h, x0 + arp_w, deauth_w);
    attrset(COLOR_PAIR(CP_DIM));
    for (int dy = 1; dy < bot3_h; dy++) mvaddstr(bot3_y + dy, x0 + arp_w, G_VERT);

    /* DNS log + ICMP log: two equal half-width panels. */
    int half1 = usable / 2;
    int half2 = usable - half1;
    draw_dns_log_panel (s, bot4_y, bot4_h, x0,         half1);
    draw_icmp_log_panel(s, bot4_y, bot4_h, x0 + half1, half2);
    attrset(COLOR_PAIR(CP_DIM));
    for (int dy = 1; dy < bot4_h; dy++) mvaddstr(bot4_y + dy, x0 + half1, G_VERT);

    draw_packets_band(s, packets_y, packets_h, x0, usable);

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
        const iface_hist_t *H = hist_lookup(s, I->name);
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

    tui_dim();    TPRINT("\n -- DNS log / ICMP log --\n");
    tui_normal();
    for (int i = 0; i < s->dns_log_count && i < 3; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        TPRINT("  DNS  %s %-5s %s -> %s\n",
               e->is_resp ? "R" : "Q", e->qtype,
               e->qname, e->answer[0] ? e->answer : "-");
    }
    for (int i = 0; i < s->icmp_log_count && i < 3; i++) {
        const icmp_log_entry_t *e = &s->icmp_log[i];
        TPRINT("  ICMP %s %s -> %s  %s\n",
               e->is_v6 ? "v6" : "v4", e->src, e->dst, e->desc);
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
    case '\t':
        s->dash_focus = (s->dash_focus + 1) % DASH_PANEL_COUNT;
        break;
    case '\r': case '\n':
        /* The connections panel drills to the Assoc view when it's
         * showing RF associations (monitor active), else to Connections. */
        if (s->dash_focus == DASH_PANEL_CONN && s->probe_iface[0])
            s->active_view = VIEW_ASSOC;
        else
            s->active_view = panel_to_view(s->dash_focus);
        break;
    default:
        break;
    }
}
