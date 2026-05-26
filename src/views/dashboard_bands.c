/* Dashboard wide bands: interfaces, connections, top hosts, packets,
 * critical alerts. These bands span the full terminal width (or a
 * 60/40/70/30 split) and carry the busiest data. ncurses only. */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/dashboard.h"
#include "views/dashboard_internal.h"
#include "bandwidth.h"
#include "ip_color.h"
#include "ip_owner.h"
#include "host_cache.h"
#include "geo.h"

#ifdef WITH_NCURSES

static int iface_spark_w(int w) {
    /* Fill the rest of the row after the text columns. No HIST_LEN cap —
     * draw_sparkline_at / sparkline() now stretch n samples across any
     * width, so a 200-col terminal gets two ~72-col graphs rather than
     * leaving the row half-empty. */
    int sw = (w - IFACE_FIXED_W - 4) / 2;  /* 4 cols for separators */
    if (sw < 8) sw = 8;
    return sw;
}


void draw_iface_band(const sloth_state_t *s, int y0, int h, int x0, int w) {
    int spark_w = iface_spark_w(w);
    int rx_x = x0 + IFACE_FIXED_W + 2;
    int tx_x = rx_x + spark_w + 2;
    int end_x = tx_x + spark_w;

    panel_title(y0, x0, w, "Interfaces", DASH_PANEL_IFACE);

    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x0, IFACE_FIXED_W,
             "  %-8s  %10s  %10s  %10s  %10s",
             "iface", "rx/s", "tx/s", "rx total", "tx total");
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, rx_x, spark_w, "rx graph");
    clipline(y0 + 1, tx_x, spark_w, "tx graph");
    if (end_x < x0 + w)
        clipline(y0 + 1, end_x, x0 + w - end_x, "");

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
        clipline(y, x0, IFACE_FIXED_W,
                 "  %-8.8s  %10s  %10s  %10s  %10s",
                 I->name, rxr, txr, rxt, txt);

        const iface_hist_t *H = hist_lookup(s, I->name);
        if (H) {
            draw_sparkline_at(y, rx_x, spark_w, H->rx, H->head, H->count);
            draw_sparkline_at(y, tx_x, spark_w, H->tx, H->head, H->count);
        } else {
            /* no history yet — paint underscores */
            attrset(COLOR_PAIR(CP_DIM));
            move(y, rx_x);
            for (int j = 0; j < spark_w; j++) addch('_');
            move(y, tx_x);
            for (int j = 0; j < spark_w; j++) addch('_');
        }
        /* erase trailing cols so the full-width band stays clean */
        if (end_x < x0 + w) {
            attrset(COLOR_PAIR(CP_NORMAL));
            clipline(y, end_x, x0 + w - end_x, "");
        }
    }
    /* erase any unused iface rows so prior frames don't leak through */
    for (int i = n; i < rows; i++) {
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x0, w, "");
    }
}

/* ── Connections (scrollable, follows conn_sel) ──────────── */

void draw_conn_band(const sloth_state_t *s, int y0, int h, int x0, int w) {
    panel_title(y0, x0, w, "Connections", DASH_PANEL_CONN);

    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x0, w,
             "  %-21s " G_ARROW " %-25s %-5s %5s %5s  %s",
             "Local", "Remote", "Proto", "St", "PID", "Process");
    /* Overprint the sparkline-column header at the right edge. */
    {
        int spark_w     = 6;
        int sparks_room = 2 * spark_w + 1;
        int gap         = 2;
        if ((w - 72) >= (8 + gap + sparks_room)) {
            int rx_x = x0 + w - sparks_room;
            int tx_x = rx_x + spark_w + 1;
            attrset(COLOR_PAIR(CP_HEAT_PEAK));
            mvprintw(y0 + 1, rx_x, "%-*s", spark_w, "  rx");
            attrset(COLOR_PAIR(CP_NORMAL));
            mvprintw(y0 + 1, tx_x, "%-*s", spark_w, "  tx");
            attrset(COLOR_PAIR(CP_DIM));
        }
    }

    int rows = h - 2;
    if (rows < 1) return;

    int n = s->conn_count;
    /* Sort is computed up-front in view_dashboard_draw and shared via
     * g_conn_order_buf so the cross-panel highlight can use it too. */
    int *order = g_conn_order_buf;

    int top = s->conn_sel - rows / 2;
    if (top + rows > n) top = n - rows;
    if (top < 0)        top = 0;
    int end = top + rows;
    if (end > n)        end = n;

    /* Column geometry: fixed prefix = 2 + 21 + 4 + 25 + 1 + 5 + 1 + 5 + 1 + 5 + 2 = 72.
     * Process column gets the remainder, minus a reserved budget at the
     * right edge for two activity sparklines (rx red + tx green). If the
     * panel is too narrow for the sparklines and a usable proc column we
     * skip the sparklines and let proc fill the rest. */
    int spark_w     = 6;
    int sparks_room = 2 * spark_w + 1;   /* 13 cols: 6 + 1 sep + 6 */
    int gap         = 2;                  /* gap between proc and sparks */
    int show_sparks = ((w - 72) >= (8 + gap + sparks_room));
    int proc_w      = show_sparks ? (w - 72 - gap - sparks_room) : (w - 72);
    if (proc_w < 8) proc_w = 8;

    for (int i = top; i < end; i++) {
        const conn_t *c = &s->conns[order[i]];
        int cat = (int)pkt_categorize(c->proto, c->local_port, c->remote_port);

        /* Paint full-row bg first */
        if (i == s->conn_sel) tui_sel();
        else                  attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + (i - top), x0, w, "");

        int xc = x0;
        move(y0 + 2 + (i - top), xc);
        if (i == s->conn_sel) tui_sel();
        else                  attrset(COLOR_PAIR(CP_NORMAL));
        printw("  ");
        xc += 2;
        /* local IP (coloured) */
        if (i != s->conn_sel) tui_ip_addstr(c->local_addr, cat);
        else                  addstr(c->local_addr);
        if (i == s->conn_sel) tui_sel();
        else                  attrset(COLOR_PAIR(CP_NORMAL));
        {
            int llen = (int)strlen(c->local_addr);
            printw(":%-5u", (unsigned)c->local_port);
            int pad = 21 - (llen + 1 + 5);
            for (int j = 0; j < pad; j++) addch(' ');
        }
        xc += 21;
        move(y0 + 2 + (i - top), xc);
        printw(" " G_ARROW " ");
        xc += 3;
        if (i != s->conn_sel) tui_ip_addstr(c->remote_addr, cat);
        else                  addstr(c->remote_addr);
        if (i == s->conn_sel) tui_sel();
        else                  attrset(COLOR_PAIR(CP_NORMAL));
        {
            int rlen = (int)strlen(c->remote_addr);
            printw(":%-5u", (unsigned)c->remote_port);
            int pad = 25 - (rlen + 1 + 5);
            if (pad > 0) for (int j = 0; j < pad; j++) addch(' ');
        }
        xc += 25;
        move(y0 + 2 + (i - top), xc);
        printw(" %-5s %5d %5d  %-*.*s",
               proto_short(c->proto),
               c->state, c->pid, proc_w, proc_w, c->proc);

        if (show_sparks) {
            int rx_x = x0 + w - sparks_room;
            int tx_x = rx_x + spark_w + 1;
            int yrow = y0 + 2 + (i - top);

            /* Find the matching per-conn bw history (linear scan; n is
             * typically small). */
            const conn_bw_t *bw = NULL;
            for (int b = 0; b < s->conn_bw_count; b++) {
                const conn_bw_t *e = &s->conn_bw[b];
                if (e->proto       == c->proto       &&
                    e->local_port  == c->local_port  &&
                    e->remote_port == c->remote_port &&
                    strcmp(e->local_addr,  c->local_addr)  == 0 &&
                    strcmp(e->remote_addr, c->remote_addr) == 0) {
                    bw = e; break;
                }
            }

            if (bw) {
                /* rx (download) — red bars; tx (upload) — green phosphor */
                draw_sparkline_solid_at(yrow, rx_x, spark_w,
                                        bw->rx_hist, bw->hist_head,
                                        bw->hist_count, CP_HEAT_PEAK);
                draw_sparkline_solid_at(yrow, tx_x, spark_w,
                                        bw->tx_hist, bw->hist_head,
                                        bw->hist_count, CP_NORMAL);
            } else {
                attrset(COLOR_PAIR(CP_DIM));
                move(yrow, rx_x);
                for (int j = 0; j < spark_w; j++) addch('_');
                move(yrow, tx_x);
                for (int j = 0; j < spark_w; j++) addch('_');
            }
        }
    }
    /* Erase any trailing rows so the conn band can shrink without
       leaving stale entries behind. */
    for (int i = end - top; i < rows; i++) {
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x0, w, "");
    }
}

/* Render a "5m20s" / "1h23m" / "2d4h" age, capped at 9999 in each unit. */
static void fmt_age(time_t now, time_t first_seen, char *buf, int sz) {
    long secs = (long)(now - first_seen);
    if (secs < 0)     secs = 0;
    if (secs > 99999) secs = 99999;
    if      (secs < 60)       snprintf(buf, sz, "%lds",   secs);
    else if (secs < 3600)     snprintf(buf, sz, "%ldm%02lds",
                                       secs / 60, secs % 60);
    else if (secs < 86400)    snprintf(buf, sz, "%ldh%02ldm",
                                       secs / 3600, (secs % 3600) / 60);
    else                       snprintf(buf, sz, "%ldd%02ldh",
                                       secs / 86400, (secs % 86400) / 3600);
}

/* ── Top hosts panel (sits next to the connections panel) ── */

void draw_top_hosts_panel(const sloth_state_t *s, int y0, int h,
                                  int x0, int w) {
    panel_title(y0, x0, w, "Top hosts", DASH_PANEL_TOP_HOSTS);
    attrset(COLOR_PAIR(CP_DIM));
    /* Reserve: ip(15) + geo(3) + host(var) + owner(var) + age(7) +
     * cnt(4) + tx(7) + rx(7) + 8 sep */
    int spare = w - (15 + 3 + 7 + 4 + 7 + 7 + 8);
    int host_w  = spare * 6 / 10;
    int owner_w = spare - host_w;
    if (host_w  < 8) host_w  = 8;
    if (owner_w < 6) owner_w = 6;

    clipline(y0 + 1, x0, w, "  %-15s %-3s %-*s %-*s %-7s %4s %7s %7s",
             "ip", "geo", host_w, "host", owner_w, "owner",
             "age", "conn", "tx", "rx");

    int rows = h - 2;
    int n = s->top_host_count < rows ? s->top_host_count : rows;
    time_t now = time(NULL);

    for (int i = 0; i < n; i++) {
        const top_host_t *e = &s->top_hosts[i];
        char age[12];
        fmt_age(now, e->first_seen, age, sizeof(age));

        /* paint a clean line first */
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x0, w, "");

        int xc = x0;
        move(y0 + 2 + i, xc);
        attrset(COLOR_PAIR(CP_NORMAL));
        addstr("  ");
        xc += 2;

        /* IP — coloured + bold if cross-panel */
        tui_ip_addstr(e->ip, (int)PKT_CAT_OTHER);
        attrset(COLOR_PAIR(CP_NORMAL));
        {
            int ip_len = (int)strlen(e->ip);
            for (int j = ip_len; j < 15; j++) addch(' ');
            addch(' ');
        }
        xc += 16;

        /* Geo — RIR region from per-/8 table. Bright for foreign,
         * dim for private / loopback / multicast. */
        {
            const char *region = geo_lookup_str(e->ip);
            const char *r_show = region ? region : "??";
            move(y0 + 2 + i, xc);
            if (region && region[0] != '-' && region[0] != 'L' &&
                region[0] != 'M') attrset(COLOR_PAIR(CP_BRIGHT));
            else                  attrset(COLOR_PAIR(CP_DIM));
            printw("%-3s ", r_show);
        }
        xc += 4;

        /* hostname — brand-coloured, OR deep-red if the underlying IP
         * has been flagged in a recent CRIT alert (matches the override
         * tui_ip_addstr applied to the ip column on this same row). */
        move(y0 + 2 + i, xc);
        {
            char buf[64];
            snprintf(buf, sizeof(buf), "%-*.*s",
                     host_w, host_w, e->hostname[0] ? e->hostname : "-");
            int hot_sev = tui_alert_hot_check(e->ip);
            if (hot_sev >= 0) {
                tui_alert_hot_attr(hot_sev);
                addstr(buf);
            } else {
                tui_brand_addstr(buf, (int)PKT_CAT_OTHER);
            }
        }
        xc += host_w;
        attrset(COLOR_PAIR(CP_NORMAL));
        move(y0 + 2 + i, xc);
        addch(' ');
        xc += 1;

        /* owner — dim if unknown */
        if (e->owner[0]) attrset(COLOR_PAIR(CP_BRIGHT));
        else             attrset(COLOR_PAIR(CP_DIM));
        printw("%-*.*s", owner_w, owner_w, e->owner[0] ? e->owner : "?");
        xc += owner_w;

        attrset(COLOR_PAIR(CP_NORMAL));
        printw(" %-7s %4d", age, e->conn_count);

        /* Cumulative bytes — tx then rx. Bright when there's traffic,
         * dim "0B" when the conn is idle. */
        char tx_buf[12], rx_buf[12];
        fmt_bytes(e->tx_bytes, tx_buf, sizeof(tx_buf));
        fmt_bytes(e->rx_bytes, rx_buf, sizeof(rx_buf));
        if (e->tx_bytes > 0) attrset(COLOR_PAIR(CP_BRIGHT));
        else                 attrset(COLOR_PAIR(CP_DIM));
        printw(" %7s", tx_buf);
        if (e->rx_bytes > 0) attrset(COLOR_PAIR(CP_BRIGHT));
        else                 attrset(COLOR_PAIR(CP_DIM));
        printw(" %7s", rx_buf);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x0, w, "");
}

/* ── Packets (real-time scroll: newest at top each frame) ── */

/* Build the packets band title with capture iface + WiFi network so the
 * operator can tell at a glance where the packets are coming from. */
static void draw_packets_title(const sloth_state_t *s, int y, int x0, int w) {
    char title[160];
    int n = snprintf(title, sizeof(title), "Packets (live)");
    if (s->pkt_iface[0])
        n += snprintf(title + n, sizeof(title) - n,
                      "  iface=%s", s->pkt_iface);
#ifdef WITH_WIFI
    for (int i = 0; i < s->ap_count; i++) {
        if (s->aps[i].status == WIFI_STATUS_ASSOC && s->aps[i].ssid[0]) {
            n += snprintf(title + n, sizeof(title) - n,
                          "  ssid=%.24s", s->aps[i].ssid);
            break;
        }
    }
#endif
    panel_title(y, x0, w, title, DASH_PANEL_PACKETS);
}

/* Print one row of the packets band: time | src(IP-color) : port -> dst(IP-color) : port | proto | info.
 * The full row uses the per-category grey bg; the IP substrings carry their own colour pairs. */
static void draw_packet_row(int y, int x0, int w, const packet_info_t *p) {
    int cat = (int)pkt_categorize(p->proto, p->src_port, p->dst_port);

    char ts_buf[12];
    time_t t = (time_t)p->ts_sec;
    struct tm *tm = localtime(&t);
    if (tm) strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
    else    snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

    /* Paint the full-row grey bg first. */
    tui_pkt_bg_cat(cat);
    clipline(y, x0, w, "");

    /* Now overprint structured content with column positions. */
    int row_end = x0 + w;
    int x = x0;
    move(y, x); x += 2;
    tui_pkt_bg_cat(cat); printw("  %-8s  ", ts_buf); x += 10;  /* "  HH:MM:SS  " is 12 cols */

    /* src column: 21 cols wide */
    /* src column: 21 cols. Same hostname-resolution logic as the dst
     * column — peers that initiate inbound flows (e.g. mDNS responders,
     * NTP servers replying with payload) show up by qname when the
     * cache has one. */
    int src_w = 21;
    move(y, x);
    char src_host[HOST_CACHE_HOSTLEN];
    if (host_cache_lookup(p->src, src_host, sizeof(src_host))) {
        char port_buf[8];
        snprintf(port_buf, sizeof(port_buf), ":%u", (unsigned)p->src_port);
        int port_len = (int)strlen(port_buf);
        int host_room = src_w - port_len;
        if (host_room < 1) host_room = 1;
        char host_trunc[HOST_CACHE_HOSTLEN];
        snprintf(host_trunc, sizeof(host_trunc), "%-*.*s",
                 host_room, host_room, src_host);
        /* Alert-hot override wins over brand colour: the underlying IP
         * is flagged so the hostname renders in the severity's hue too. */
        int hot_sev = tui_alert_hot_check(p->src);
        if (hot_sev >= 0) {
            tui_alert_hot_attr(hot_sev);
            addstr(host_trunc);
        } else {
            tui_brand_addstr(host_trunc, cat);
        }
        tui_pkt_bg_cat(cat);
        addstr(port_buf);
    } else {
        tui_ip_addstr(p->src, cat);
        tui_pkt_bg_cat(cat);
        printw(":%-5u", (unsigned)p->src_port);
        int used = (int)strlen(p->src) + 1 + 5;
        while (used++ < src_w) addch(' ');
    }
    x += src_w;

    move(y, x); tui_pkt_bg_cat(cat); printw(" " G_ARROW " "); x += 3;

    /* dst column: 21 cols. If we've observed a DNS A/AAAA answer that
     * names this IP, show the qname (brand-coloured) instead of the
     * raw IP so the operator can read flows at a glance. The IP is
     * still discoverable in the connections panel + drill-downs. */
    int dst_w = 21;
    move(y, x);
    char dst_host[HOST_CACHE_HOSTLEN];
    if (host_cache_lookup(p->dst, dst_host, sizeof(dst_host))) {
        /* hostname:port, truncated to dst_w. Hostname gets brand colour;
         * the ":port" suffix uses the row's category bg colour.
         * Alert-hot override wins over brand colour. */
        char port_buf[8];
        snprintf(port_buf, sizeof(port_buf), ":%u", (unsigned)p->dst_port);
        int port_len = (int)strlen(port_buf);
        int host_room = dst_w - port_len;
        if (host_room < 1) host_room = 1;
        char host_trunc[HOST_CACHE_HOSTLEN];
        snprintf(host_trunc, sizeof(host_trunc), "%-*.*s",
                 host_room, host_room, dst_host);
        int hot_sev = tui_alert_hot_check(p->dst);
        if (hot_sev >= 0) {
            tui_alert_hot_attr(hot_sev);
            addstr(host_trunc);
        } else {
            tui_brand_addstr(host_trunc, cat);
        }
        tui_pkt_bg_cat(cat);
        addstr(port_buf);
    } else {
        tui_ip_addstr(p->dst, cat);
        tui_pkt_bg_cat(cat);
        printw(":%-5u", (unsigned)p->dst_port);
        int used = (int)strlen(p->dst) + 1 + 5;
        while (used++ < dst_w) addch(' ');
    }
    x += dst_w;

    /* proto column */
    move(y, x); tui_pkt_bg_cat(cat); printw("  %-5s  ", proto_short(p->proto)); x += 9;

    /* info column: capped at info_max so the hex dump has room. If we
     * captured no raw bytes for this packet, info gets the full
     * remainder like before. */
    int info_max = 28;
    int info_w;
    if (p->raw_len > 0) {
        info_w = row_end - x;
        if (info_w > info_max) info_w = info_max;
    } else {
        info_w = row_end - x;
    }
    if (info_w < 1) info_w = 1;
    move(y, x);
    /* Earth-tone hashed palette: same info string -> same colour so
     * repeating values are visually grouped. */
    tui_info_color(p->info);
    /* %-*.*s pads + truncates to exactly info_w columns so hex starts
     * at a predictable x. */
    printw("%-*.*s", info_w, info_w, p->info);
    x += info_w;

    /* Hex dump fills the remaining width — up to raw_len bytes, 3 cols
     * each ("XX "). Each byte is coloured by its value via the
     * Fallout-flavoured earth-tone palette (CP_INFO_BASE + byte%8) so
     * repeated bytes (0x00 runs, ASCII text, padding) form visible
     * stripes without dominating the row. */
    int hex_room = row_end - x;
    if (hex_room > 0 && p->raw_len > 0) {
        int hex_bytes = hex_room / 3;
        if (hex_bytes > p->raw_len) hex_bytes = p->raw_len;
        move(y, x);
        for (int b = 0; b < hex_bytes; b++) {
            unsigned byte = (unsigned)p->raw[b];
            attrset(COLOR_PAIR(CP_INFO_BASE + (byte & 7)));
            printw("%02x ", byte);
        }
    }
}

/* Cumulative info-frequency table — populated incrementally from the
 * packet ring across the entire session, NOT just the last ring window.
 * Each new packet (identified by a timestamp greater than the highest
 * we've seen) increments its info slot. Stays at module scope so it
 * survives frame-to-frame. */
enum { INFO_TBL_CAP = 96 };
static struct info_slot { char info[40]; int count; } g_info_tbl[INFO_TBL_CAP];
static int      g_info_n = 0;
static uint64_t g_last_pkt_us = 0;

static void update_cumulative_info_counts(const sloth_state_t *s) {
    int pkt_n = s->pkt_count < MAX_PACKETS ? s->pkt_count : MAX_PACKETS;
    uint64_t newest = g_last_pkt_us;
    for (int i = 0; i < pkt_n; i++) {
        const packet_info_t *p = &s->packets[i];
        uint64_t ts = (uint64_t)p->ts_sec * 1000000ULL + (uint64_t)p->ts_usec;
        if (ts <= g_last_pkt_us) continue;
        if (ts > newest) newest = ts;
        if (!p->info[0]) continue;
        int found = -1;
        for (int j = 0; j < g_info_n; j++)
            if (strcmp(g_info_tbl[j].info, p->info) == 0) { found = j; break; }
        if (found >= 0) {
            g_info_tbl[found].count++;
        } else if (g_info_n < INFO_TBL_CAP) {
            snprintf(g_info_tbl[g_info_n].info,
                     sizeof(g_info_tbl[g_info_n].info), "%s", p->info);
            g_info_tbl[g_info_n].count = 1;
            g_info_n++;
        }
        /* Table full — silently drop new info strings, keep counting
         * the ones we already track. */
    }
    g_last_pkt_us = newest;
}

/* Non-scrolling row at the bottom of the packets band: cumulative
 * bargraphs of the top-N most-frequent info strings since launch.
 *
 * Each cell layout:
 *
 *   ┌─ cell_w cols ──────────────────┐
 *   │ ████████████░░░░░░░░░░░░░░░    │   <-- bar (dim filled + dim empty)
 *   │ TLS google.com           42    │   <-- bright text + count overprinted
 *   └────────────────────────────────┘
 *
 * The bar is painted first across the full cell width, then the bright
 * label + count is written on top of it. ncurses takes the later writes,
 * so the eye reads the text as foreground with the bar as backdrop. */
static void draw_info_bargraph_row(const sloth_state_t *s,
                                    int y, int x0, int w) {
    enum { TOP_N = 5 };
    update_cumulative_info_counts(s);

    /* Find the top-N by count without touching the storage order — we
     * use a small ordering array of indices into g_info_tbl. */
    int order[INFO_TBL_CAP];
    for (int i = 0; i < g_info_n; i++) order[i] = i;
    int top = TOP_N < g_info_n ? TOP_N : g_info_n;
    for (int i = 0; i < top; i++) {
        int best = i;
        for (int j = i + 1; j < g_info_n; j++)
            if (g_info_tbl[order[j]].count > g_info_tbl[order[best]].count)
                best = j;
        if (best != i) { int t = order[i]; order[i] = order[best]; order[best] = t; }
    }
    int max = top > 0 ? g_info_tbl[order[0]].count : 1;
    if (max < 1) max = 1;

    /* Wipe the row. */
    attrset(COLOR_PAIR(CP_NORMAL));
    move(y, x0);
    for (int j = 0; j < w; j++) addch(' ');

    if (top <= 0) {
        attrset(COLOR_PAIR(CP_DIM));
        mvprintw(y, x0 + 2, "(no packets yet \xe2\x80\x94 bargraph builds as traffic arrives)");
        return;
    }

    int cell_w = w / top;
    if (cell_w < 18) cell_w = 18;
    for (int i = 0; i < top; i++) {
        int cx = x0 + i * cell_w;
        if (cx + cell_w > x0 + w) break;
        const char *label = g_info_tbl[order[i]].info;
        int count        = g_info_tbl[order[i]].count;

        int bar_w = cell_w - 1;   /* 1 col gutter between cells */
        int filled = (int)((double)count / (double)max * bar_w + 0.5);
        if (filled > bar_w) filled = bar_w;
        if (filled < 0)     filled = 0;

        /* Step 1: paint the bar across the full cell in dim — filled
         * portion as solid █, empty portion as light ░. The whole bar
         * is dim so it reads as backdrop. */
        attrset(COLOR_PAIR(CP_DIM));
        move(y, cx);
        for (int b = 0; b < filled;       b++) addstr("\xe2\x96\x88");  /* █ */
        for (int b = filled; b < bar_w;   b++) addstr("\xe2\x96\x91");  /* ░ */
        addch(' ');

        /* Step 2: overlay bright label + count on top of the bar.
         * Same starting column; ncurses overwrites the bar cells the
         * text covers, leaving the rest of the bar visible to the right. */
        char overlay[80];
        snprintf(overlay, sizeof(overlay), " %s  %d ", label, count);
        int overlay_w = (int)strlen(overlay);
        if (overlay_w > bar_w) overlay_w = bar_w;
        tui_info_color(label);
        attron(A_BOLD);
        move(y, cx);
        addnstr(overlay, overlay_w);
        attroff(A_BOLD);
    }
}

/* Count CRIT-only alerts. Hoisted so the layout code in
 * view_dashboard_draw can size the band before rendering. */
int crit_alerts_count(const sloth_state_t *s) {
    int n = 0;
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].sev == ALERT_SEV_CRIT) n++;
    return n;
}

/* Compact CRIT-only alerts band. Sized to between 1 and CRIT_MAX_ROWS
 * visible alerts. Sorted newest-first by last_seen. If more CRITs exist
 * than rows, the visible window rotates by one slot every ~2 seconds so
 * everything cycles into view without eating screen real estate.
 * Each row shows HH:MM:SS [age] title  n=N  detail. */
void draw_crit_alerts_band(const sloth_state_t *s,
                                   int y0, int h, int x0, int w) {
    enum { MAX_CRIT_LIST = 64 };
    int crit_idx[MAX_CRIT_LIST];
    int crit_n = 0;
    for (int i = 0; i < s->alert_count && crit_n < MAX_CRIT_LIST; i++)
        if (s->alerts[i].sev == ALERT_SEV_CRIT)
            crit_idx[crit_n++] = i;

    /* Newest first. Selection sort — crit_n is small (<=64). */
    for (int i = 0; i < crit_n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < crit_n; j++)
            if (s->alerts[crit_idx[j]].last_seen >
                s->alerts[crit_idx[best]].last_seen) best = j;
        if (best != i) {
            int t = crit_idx[i]; crit_idx[i] = crit_idx[best]; crit_idx[best] = t;
        }
    }

    /* Title shows the total so the operator knows when alerts are
     * scrolling off-screen. */
    char title[48];
    if (crit_n > 0) snprintf(title, sizeof(title),
                             "Critical alerts (%d)", crit_n);
    else            snprintf(title, sizeof(title), "Critical alerts");
    panel_title(y0, x0, w, title, DASH_PANEL_CRIT_ALERTS);

    int rows = h - 1;
    if (rows < 1) return;

    if (crit_n == 0) {
        attrset(COLOR_PAIR(CP_DIM));
        mvprintw(y0 + 1, x0 + 2,
                 "(no critical alerts \xe2\x80\x94 system is quiet)");
        attrset(COLOR_PAIR(CP_NORMAL));
        for (int i = 1; i < rows; i++) clipline(y0 + 1 + i, x0, w, "");
        return;
    }

    /* Rotate the visible window when there are more alerts than rows.
     * Static state survives across frames; reset when the list shrinks
     * back to fitting. */
    static int    s_off    = 0;
    static time_t s_advance = 0;
    time_t now_t = time(NULL);
    if (crit_n > rows) {
        if (now_t - s_advance >= 2) {
            s_off     = (s_off + 1) % crit_n;
            s_advance = now_t;
        }
        if (s_off >= crit_n) s_off = 0;
    } else {
        s_off     = 0;
        s_advance = now_t;
    }

    int paint = rows < crit_n ? rows : crit_n;
    int now   = (int)now_t;
    for (int p = 0; p < paint; p++) {
        const alert_t *a = &s->alerts[crit_idx[(s_off + p) % crit_n]];

        char ts_buf[12];
        time_t ts = a->last_seen;
        struct tm *tm = localtime(&ts);
        if (tm) strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        else    snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

        int age_s = now - (int)a->last_seen;
        if (age_s < 0)     age_s = 0;
        if (age_s > 99999) age_s = 99999;
        char age_buf[16];
        if      (age_s < 60)   snprintf(age_buf, sizeof(age_buf), "%ds", age_s);
        else if (age_s < 3600) snprintf(age_buf, sizeof(age_buf), "%dm", age_s/60);
        else                   snprintf(age_buf, sizeof(age_buf), "%dh", age_s/3600);

        attrset(COLOR_PAIR(CP_HEAT_PEAK) | A_BOLD);
        clipline(y0 + 1 + p, x0, w,
                 "  %s  [%-4s ago] %-15.15s  n=%-4d  %s",
                 ts_buf, age_buf, a->title, a->count, a->detail);
    }
    attrset(COLOR_PAIR(CP_NORMAL));
    for (int i = paint; i < rows; i++)
        clipline(y0 + 1 + i, x0, w, "");
}

void draw_packets_band(const sloth_state_t *s, int y0, int h, int x0, int w) {
    draw_packets_title(s, y0, x0, w);
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x0, w,
             "  %-8s  %-21s " G_ARROW " %-21s  %-5s  %s",
             "time", "src", "dst", "proto", "info");

    /* Reserve the last row of the band for the non-scrolling info
     * bargraph. Title + header + N data rows + bargraph = h. */
    int rows = h - 3;
    if (rows < 1) rows = 1;

    int show = s->pkt_count < rows ? s->pkt_count : rows;
    for (int i = 0; i < rows; i++) {
        if (i >= show) {
            attrset(COLOR_PAIR(CP_NORMAL));
            clipline(y0 + 2 + i, x0, w, "");
            continue;
        }
        /* newest first */
        int slot = (s->pkt_head - 1 - i + MAX_PACKETS) % MAX_PACKETS;
        draw_packet_row(y0 + 2 + i, x0, w, &s->packets[slot]);
    }
    /* Bottom-of-band bargraph (live frequency of info values). */
    if (h >= 4)
        draw_info_bargraph_row(s, y0 + h - 1, x0, w);
}

#endif /* WITH_NCURSES */
