#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "sloth.h"
#include "tui.h"
#include "views/dashboard.h"
#include "bandwidth.h"
#include "ip_color.h"
#include "ip_owner.h"
#include "oui.h"
#include "host_cache.h"

/* Box-drawing / arrow glyphs used by the dashboard. UTF-8 byte sequences;
 * each occupies exactly one terminal column when the font supports them
 * (Fira Code, DejaVu Sans Mono, anything reasonable). */
#define G_HORIZ   "\xe2\x94\x80"   /* ─  U+2500 */
#define G_VERT    "\xe2\x94\x82"   /* │  U+2502 */
#define G_TL      "\xe2\x94\x8c"   /* ┌  U+250C */
#define G_TR      "\xe2\x94\x90"   /* ┐  U+2510 */
#define G_BL      "\xe2\x94\x94"   /* └  U+2514 */
#define G_BR      "\xe2\x94\x98"   /* ┘  U+2518 */
#define G_ARROW   "\xe2\x86\x92"   /* →  U+2192 */

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

/* sparkline width in glyph cells — used by both builds. */
#define SPARK_W 24

/* Tab-cycle order. Visible to both builds because view_dashboard_key
 * (outside the ncurses guard) needs DASH_PANEL_COUNT. */
typedef enum {
    DASH_PANEL_IFACE = 0,
    DASH_PANEL_SUMMARY,
    DASH_PANEL_CONN,
    DASH_PANEL_TOP_HOSTS,
    DASH_PANEL_PACKETS,
    DASH_PANEL_WIFI,
    DASH_PANEL_ROAMING,
    DASH_PANEL_BEACONS,
    DASH_PANEL_MDNS,
    DASH_PANEL_DHCP,
    DASH_PANEL_SSDP,
    DASH_PANEL_ARP,
    DASH_PANEL_DEAUTH,
    DASH_PANEL_DNS,
    DASH_PANEL_ICMP,
    DASH_PANEL_CRIT_ALERTS,
    DASH_PANEL_COUNT
} dash_panel_t;

/* Set at the top of view_dashboard_draw so panel_title can read it without
 * needing the sloth_state_t pointer threaded through every panel call.
 * Visible to both builds for the same reason as the enum above. */
static int g_dash_focus;

/* Connections sort order — populated by draw_conn_band each frame,
 * read by the cross-panel highlight in view_dashboard_draw so
 * s->conn_sel (the ordinal in the sorted view) resolves back to the
 * underlying conn index. */
int g_conn_order_buf[MAX_CONNS];
int g_conn_order_n;

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
        int lvl = 0;
        if (n > 0) {
            /* Stretch n samples across width screen columns. */
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
        if      (lvl == 0)  attrset(COLOR_PAIR(CP_DIM));
        else if (lvl <= 2)  attrset(COLOR_PAIR(CP_NORMAL));
        else if (lvl <= 4)  attrset(COLOR_PAIR(CP_HEAT_MID));
        else if (lvl <= 6)  attrset(COLOR_PAIR(CP_HEAT_HI));
        else                attrset(COLOR_PAIR(CP_HEAT_PEAK));
        addstr(glyph[lvl]);
    }
}

/* Solid-colour sparkline for per-connection bw history. Single colour for
 * every non-zero glyph; zero / missing samples render as a dim '_'.
 * Operates on float arrays (the conn_bw_t hist) instead of doubles. */
static void draw_sparkline_solid_at(int y, int x, int width,
                                     const float *vals, int head, int n,
                                     int color_pair) {
    double max = 0.0;
    for (int i = 0; i < n && i < CONN_BW_HIST; i++)
        if ((double)vals[i] > max) max = (double)vals[i];

    static const char *glyph[9] = {
        "_",
        "\xe2\x96\x81", "\xe2\x96\x82", "\xe2\x96\x83",
        "\xe2\x96\x84", "\xe2\x96\x85", "\xe2\x96\x86",
        "\xe2\x96\x87", "\xe2\x96\x88",
    };
    move(y, x);
    for (int i = 0; i < width; i++) {
        int lvl = 0;
        if (n > 0) {
            int age;
            if (width <= 1) age = 0;
            else            age = ((width - 1 - i) * (n - 1)) / (width - 1);
            if (age < 0)   age = 0;
            if (age >= n)  age = n - 1;
            int slot = (head - 1 - age + CONN_BW_HIST) % CONN_BW_HIST;
            double v = (double)vals[slot];
            if (v > 0.0 && max > 0.0) {
                lvl = (int)((v / max) * 8.0 + 0.5);
                if (lvl < 1) lvl = 1;
                if (lvl > 8) lvl = 8;
            }
        }
        if (lvl == 0) attrset(COLOR_PAIR(CP_DIM));
        else          attrset(COLOR_PAIR(color_pair));
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

/* Internal: panel title with optional right-edge "P" marker for panels
 * whose data is gathered by passive RF sniffing (monitor-mode probes,
 * beacons, deauth). The marker is a small dim "P" before the trailing
 * horizontals so the eye reads it as a chip on the frame. */
static void panel_title_ex(int y, int x, int w, const char *name,
                            int panel_id, int passive) {
    int focused = (panel_id == g_dash_focus);
    /* Reserve "─ P ─" (5 cols) at the right edge when passive. */
    int reserve = passive ? 5 : 0;
    attrset(COLOR_PAIR(CP_DIM));
    move(y, x);
    int filled = 0;
    int len = (int)strlen(name);
    if (filled + 2 <= w) { addstr(G_HORIZ); addstr(G_HORIZ); filled += 2; }
    if (filled     <  w) { addch(' '); filled++; }
    /* Title text — bright + bold for extra pop; inverted if focused. */
    attr_t name_attr = COLOR_PAIR(CP_BRIGHT) | A_BOLD;
    if (focused) name_attr |= A_REVERSE;
    attrset(name_attr);
    for (int i = 0; i < len && filled < w - reserve; i++, filled++)
        addch((chtype)(unsigned char)name[i]);
    attrset(COLOR_PAIR(CP_DIM));
    if (filled < w - reserve) { addch(' '); filled++; }
    while (filled < w - reserve) { addstr(G_HORIZ); filled++; }
    if (passive && filled + reserve <= w) {
        /* "─ P ─" at the right edge, P in dim. */
        addstr(G_HORIZ); filled++;
        addch(' ');      filled++;
        addch('P');      filled++;
        addch(' ');      filled++;
        addstr(G_HORIZ); filled++;
    }
}

static void panel_title(int y, int x, int w, const char *name, int panel_id) {
    panel_title_ex(y, x, w, name, panel_id, 0);
}

static void panel_title_passive(int y, int x, int w, const char *name, int panel_id) {
    panel_title_ex(y, x, w, name, panel_id, 1);
}

/* ── Interfaces row with sparklines ──────────────────────── */

/* Fixed text portion: 2 (margin) + 8 (name) + 10 + 10 + 10 + 10 = 50 cols.
 * Each sparkline expands to fill half the remaining width, capped at
 * HIST_LEN since that's the depth of the history ring. */
#define IFACE_FIXED_W   50

static int iface_spark_w(int w) {
    /* Fill the rest of the row after the text columns. No HIST_LEN cap —
     * draw_sparkline_at / sparkline() now stretch n samples across any
     * width, so a 200-col terminal gets two ~72-col graphs rather than
     * leaving the row half-empty. */
    int sw = (w - IFACE_FIXED_W - 4) / 2;  /* 4 cols for separators */
    if (sw < 8) sw = 8;
    return sw;
}

#define IFACE_END_X(w)  (IFACE_FIXED_W + 2 + iface_spark_w(w) + 2 + iface_spark_w(w))

static void draw_iface_band(const sloth_state_t *s, int y0, int h, int x0, int w) {
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

static void draw_conn_band(const sloth_state_t *s, int y0, int h, int x0, int w) {
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

static void draw_top_hosts_panel(const sloth_state_t *s, int y0, int h,
                                  int x0, int w) {
    panel_title(y0, x0, w, "Top hosts", DASH_PANEL_TOP_HOSTS);
    attrset(COLOR_PAIR(CP_DIM));
    /* Reserve: ip(15) + host(var) + owner(var) + age(7) + cnt(4) +
     * tx(7) + rx(7) + 7 sep */
    int spare = w - (15 + 7 + 4 + 7 + 7 + 7);
    int host_w  = spare * 6 / 10;
    int owner_w = spare - host_w;
    if (host_w  < 8) host_w  = 8;
    if (owner_w < 6) owner_w = 6;

    clipline(y0 + 1, x0, w, "  %-15s %-*s %-*s %-7s %4s %7s %7s",
             "ip", host_w, "host", owner_w, "owner",
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

        /* hostname — brand-coloured, OR deep-red if the underlying IP
         * has been flagged in a recent CRIT alert (matches the override
         * tui_ip_addstr applied to the ip column on this same row). */
        move(y0 + 2 + i, xc);
        {
            char buf[64];
            snprintf(buf, sizeof(buf), "%-*.*s",
                     host_w, host_w, e->hostname[0] ? e->hostname : "-");
            if (tui_alert_hot_check(e->ip)) {
                attrset(COLOR_PAIR(CP_ALERT_HOT) | A_BOLD);
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
         * is flagged so the hostname renders in deep red too. */
        if (tui_alert_hot_check(p->src)) {
            attrset(COLOR_PAIR(CP_ALERT_HOT) | A_BOLD);
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
        if (tui_alert_hot_check(p->dst)) {
            attrset(COLOR_PAIR(CP_ALERT_HOT) | A_BOLD);
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
static int crit_alerts_count(const sloth_state_t *s) {
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
#define CRIT_MAX_ROWS 5

static void draw_crit_alerts_band(const sloth_state_t *s,
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

static void draw_packets_band(const sloth_state_t *s, int y0, int h, int x0, int w) {
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

/* ── Bottom panels ───────────────────────────────────────── */

static void draw_wifi_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    /* Title includes the scanning adapter and (if associated) the SSID
     * the adapter is currently on, so the operator knows whose
     * neighbourhood this scan is from. */
    char title[80];
    const char *iface = s->pkt_iface[0] ? s->pkt_iface : "?";
    const char *assoc_ssid = NULL;
#ifdef WITH_WIFI
    for (int i = 0; i < s->ap_count; i++) {
        if (s->aps[i].status == WIFI_STATUS_ASSOC && s->aps[i].ssid[0]) {
            assoc_ssid = s->aps[i].ssid; break;
        }
    }
#endif
    if (assoc_ssid)
        snprintf(title, sizeof(title), "WiFi APs (%s \xc2\xb7 %.24s)",
                 iface, assoc_ssid);
    else
        snprintf(title, sizeof(title), "WiFi APs (%s)", iface);
    panel_title_passive(y0, x, w, title, DASH_PANEL_WIFI);
    attrset(COLOR_PAIR(CP_DIM));
    clipline(y0 + 1, x, w, "  %-*s %4s %3s",
             w - 12 > 8 ? w - 12 : 8, "SSID", "sig", "ch");
    int rows = h - 2;
    int n = s->ap_count < rows ? s->ap_count : rows;
    int ssid_w = w - 12;
    if (ssid_w < 8) ssid_w = 8;
    for (int i = 0; i < n; i++) {
        const wifi_ap_t *a = &s->aps[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "");
        move(y0 + 2 + i, x);
        attrset(COLOR_PAIR(CP_NORMAL));
        addstr("  ");
        const char *ssid = a->ssid[0] ? a->ssid : "(hidden)";
        char buf[40];
        snprintf(buf, sizeof(buf), "%-*.*s", ssid_w, ssid_w, ssid);
        tui_ssid_addstr(buf, (int)PKT_CAT_OTHER);
        attrset(COLOR_PAIR(CP_NORMAL));
        printw(" %4d %3d", a->signal_dbm, a->channel);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

/* Estimate distance from RSSI using the log-distance path-loss model:
 *     P(d) = P(d0) - 10 * n * log10(d / d0)
 *   -> d  = d0 * 10^((P(d0) - P) / (10*n))
 * Defaults: P(d0) = -30 dBm at d0 = 1 m, n = 3.0 (typical indoor with walls).
 *
 * This is wildly environment-dependent — real-world distance depends on
 * obstacles, antennas, frequency, multipath. Treat the number as a rough
 * order-of-magnitude hint, not a metric measurement. */
static double rssi_to_meters(int8_t rssi) {
    if (rssi >= -30) return 1.0;
    double exponent = ((-30.0) - (double)rssi) / 30.0;  /* 10 * n=3 */
    if (exponent > 5.0) exponent = 5.0;
    return pow(10.0, exponent);
}

/* "Roaming clients" panel: enhanced Probe view with vendor + estimated
 * distance. Pulls from the same probe_clients[] source the old Probe
 * panel used. Replaces draw_probe_panel — the data is identical, this
 * just exposes more of the radio metadata. */
static void draw_radio_clients_panel(const sloth_state_t *s,
                                      int y0, int h, int x, int w) {
    /* Roaming clients comes from monitor-mode probe capture — show the
     * monitor adapter so it's clear what radio is listening. */
    char rtitle[64];
    const char *miface = s->probe_iface[0] ? s->probe_iface
                       : s->pkt_iface[0]   ? s->pkt_iface : "?";
    snprintf(rtitle, sizeof(rtitle), "Roaming clients (%s)", miface);
    panel_title_passive(y0, x, w, rtitle, DASH_PANEL_ROAMING);
    attrset(COLOR_PAIR(CP_DIM));
    /* Geometry: 2 (margin) + 17 (MAC) + 1 + 14 (vendor) + 1 + ssid +
     *           1 + 4 (sig) + 1 + 5 (dist) = 46 + ssid_w. */
    int ssid_w = w - 46;
    if (ssid_w < 6) ssid_w = 6;
    clipline(y0 + 1, x, w, "  %-17s %-14s %-*s %4s %5s",
             "MAC", "vendor", ssid_w, "ssid", "sig", "dist");

    int rows = h - 2;
    int n = s->probe_count < rows ? s->probe_count : rows;
    for (int i = 0; i < n; i++) {
        const probe_client_t *p = &s->probe_clients[i];

        char mac[20];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 p->mac[0], p->mac[1], p->mac[2],
                 p->mac[3], p->mac[4], p->mac[5]);

        /* Locally-administered (random) MAC: low bit of the U/L flag */
        const char *vendor;
        int is_random = (p->mac[0] & 0x02) != 0;
        if (is_random)              vendor = "(random)";
        else                        vendor = oui_lookup(p->mac);
        if (!vendor || !vendor[0])  vendor = "?";

        double dist = rssi_to_meters(p->signal_dbm);
        char dist_buf[12];
        if      (dist >= 100.0)  snprintf(dist_buf, sizeof(dist_buf), ">99m");
        else if (dist >= 10.0)   snprintf(dist_buf, sizeof(dist_buf), "%.0fm", dist);
        else                     snprintf(dist_buf, sizeof(dist_buf), "%.1fm", dist);

        /* paint full row first */
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "");
        int xc = x;
        move(y0 + 2 + i, xc);
        attrset(COLOR_PAIR(CP_NORMAL));
        printw("  %-17s ", mac);
        xc += 2 + 17 + 1;

        /* vendor: dim for "?" / "(random)", bright for known */
        move(y0 + 2 + i, xc);
        if (is_random || vendor[0] == '?') attrset(COLOR_PAIR(CP_DIM));
        else                                attrset(COLOR_PAIR(CP_BRIGHT));
        printw("%-14.14s ", vendor);
        xc += 14 + 1;

        /* SSID column - coloured via hash palette */
        const char *ssid = p->ssid[0] ? p->ssid : "(any)";
        char ssid_buf[40];
        snprintf(ssid_buf, sizeof(ssid_buf), "%-*.*s", ssid_w, ssid_w, ssid);
        move(y0 + 2 + i, xc);
        tui_ssid_addstr(ssid_buf, (int)PKT_CAT_OTHER);
        xc += ssid_w + 1;

        /* sig: heat-colour by signal strength.
         *   >= -50 dBm  = bright (very close / strong)
         *   -50..-65    = normal phosphor
         *   -65..-80    = heat-mid
         *   < -80       = heat-hi (almost out of range) */
        move(y0 + 2 + i, xc);
        if      (p->signal_dbm >= -50) attrset(COLOR_PAIR(CP_BRIGHT));
        else if (p->signal_dbm >= -65) attrset(COLOR_PAIR(CP_NORMAL));
        else if (p->signal_dbm >= -80) attrset(COLOR_PAIR(CP_HEAT_MID));
        else                            attrset(COLOR_PAIR(CP_HEAT_HI));
        printw("%4d ", p->signal_dbm);
        xc += 4 + 1;

        /* dist: dim, since it's a rough estimate */
        move(y0 + 2 + i, xc);
        attrset(COLOR_PAIR(CP_DIM));
        printw("%-5s", dist_buf);
    }
    for (int i = n; i < rows; i++) {
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "");
    }
}

static void draw_beacon_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    char btitle[64];
    const char *biface = s->probe_iface[0] ? s->probe_iface
                       : s->pkt_iface[0]   ? s->pkt_iface : "?";
    snprintf(btitle, sizeof(btitle), "Beacons (%s)", biface);
    panel_title_passive(y0, x, w, btitle, DASH_PANEL_BEACONS);
    attrset(COLOR_PAIR(CP_DIM));
    int ssid_w = w - 12;
    if (ssid_w < 8) ssid_w = 8;
    clipline(y0 + 1, x, w, "  %-*s %4s %3s", ssid_w, "SSID", "sig", "ch");
    int rows = h - 2;
    int n = s->beacon_count < rows ? s->beacon_count : rows;
    for (int i = 0; i < n; i++) {
        const beacon_ap_t *b = &s->beacon_aps[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "");
        move(y0 + 2 + i, x);
        attrset(COLOR_PAIR(CP_NORMAL));
        addstr("  ");
        const char *ssid = b->ssid[0] ? b->ssid : "(hidden)";
        char buf[40];
        snprintf(buf, sizeof(buf), "%-*.*s", ssid_w, ssid_w, ssid);
        tui_ssid_addstr(buf, (int)PKT_CAT_OTHER);
        attrset(COLOR_PAIR(CP_NORMAL));
        printw(" %4d %3d", b->signal_dbm, b->channel);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_mdns_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "mDNS services", DASH_PANEL_MDNS);
    attrset(COLOR_PAIR(CP_DIM));
    /* Layout: 2 (margin) + instance_w + 1 (sep) + 6 (port) = w. Instance
     * column is capped at 32 chars so even on a wide terminal the column
     * stays tight and doesn't dominate the panel. */
    int instance_w = w - 9;
    if (instance_w < 8)  instance_w = 8;
    if (instance_w > 32) instance_w = 32;
    clipline(y0 + 1, x, w, "  %-*s %-6s", instance_w, "instance", "port");
    int rows = h - 2;
    int n = s->mdns_count < rows ? s->mdns_count : rows;
    for (int i = 0; i < n; i++) {
        const mdns_service_t *m = &s->mdns_services[i];
        attrset(COLOR_PAIR(CP_NORMAL));
        clipline(y0 + 2 + i, x, w, "  %-*.*s %-6u",
                 instance_w, instance_w,
                 m->instance[0] ? m->instance : m->service,
                 (unsigned)m->port);
    }
    for (int i = n; i < rows; i++) clipline(y0 + 2 + i, x, w, "");
}

static void draw_dhcp_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "DHCP events", DASH_PANEL_DHCP);
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
    panel_title(y0, x, w, "ARP table", DASH_PANEL_ARP);
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
    char dtitle[64];
    const char *diface = s->probe_iface[0] ? s->probe_iface
                       : s->pkt_iface[0]   ? s->pkt_iface : "?";
    snprintf(dtitle, sizeof(dtitle), "Deauth (%s)", diface);
    panel_title_passive(y0, x, w, dtitle, DASH_PANEL_DEAUTH);
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
    panel_title(y0, x, w, "Summary", DASH_PANEL_SUMMARY);
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

static void draw_dns_log_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "DNS log", DASH_PANEL_DNS);
    /* DNS log shares the DNS category grey with DNS rows in the packets band. */
    int cat = (int)PKT_CAT_DNS;
    tui_pkt_bg_cat(cat);
    clipline(y0 + 1, x, w, "  %-3s %-5s %-22s %s",
             "Q/R", "type", "qname", "answer");
    int rows = h - 2;
    int n = s->dns_log_count < rows ? s->dns_log_count : rows;
    /* fixed prefix width = 2 + 3 + 1 + 5 + 1 + qname_w + 1 = 13 + qname_w
       Variable: qname grows, answer fills the remainder. */
    int qname_w  = (w - 13) / 2;
    if (qname_w < 16) qname_w = 16;
    int answer_w = w - (13 + qname_w);
    if (answer_w < 8) answer_w = 8;
    for (int i = 0; i < n; i++) {
        const dns_log_entry_t *e = &s->dns_log[i];
        /* Paint grey bg first, then overprint. */
        tui_pkt_bg_cat(cat);
        clipline(y0 + 2 + i, x, w, "");
        /* status prefix: Q/R */
        int xc = x;
        move(y0 + 2 + i, xc);
        tui_pkt_bg_cat(cat);
        printw("  %-3s %-5.5s ",
               e->is_resp ? "R" : "Q", e->qtype);
        xc += 12;
        /* qname column — brand-coloured (Google rainbow, Firefox orange, …) */
        move(y0 + 2 + i, xc);
        tui_pkt_bg_cat(cat);
        {
            char qbuf[64];
            snprintf(qbuf, sizeof(qbuf), "%-*.*s", qname_w, qname_w, e->qname);
            tui_brand_addstr(qbuf, cat);
        }
        tui_pkt_bg_cat(cat);
        addch(' ');
        xc += qname_w + 1;
        /* answer column — IP if it looks like one */
        move(y0 + 2 + i, xc);
        if (strchr(e->answer, '.') && e->answer[0] >= '0' &&
            e->answer[0] <= '9') {
            tui_ip_addstr(e->answer, cat);
        } else {
            int is_nx = (strcmp(e->answer, "NXDOMAIN") == 0);
            if (is_nx)           tui_pkt_bg_cat(cat), attrset(COLOR_PAIR(CP_HEAT_HI));
            else if (e->is_resp) tui_pkt_bg_cat(cat), attrset(COLOR_PAIR(CP_BRIGHT));
            else                 tui_pkt_bg_cat(cat);
            printw("%.*s", answer_w, e->answer[0] ? e->answer : "-");
        }
    }
    for (int i = n; i < rows; i++) {
        tui_pkt_bg_cat(cat);
        clipline(y0 + 2 + i, x, w, "");
    }
}

static void draw_icmp_log_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "ICMP log", DASH_PANEL_ICMP);
    int cat = (int)PKT_CAT_ICMP;
    tui_pkt_bg_cat(cat);
    clipline(y0 + 1, x, w, "  %-3s %-15s %s",
             "v",  "src", "type");
    int rows = h - 2;
    int n = s->icmp_log_count < rows ? s->icmp_log_count : rows;
    /* fixed prefix: 2 + 3 + 1 + 15 + 1 = 22 chars  */
    int desc_w = w - 22;
    if (desc_w < 8) desc_w = 8;
    for (int i = 0; i < n; i++) {
        const icmp_log_entry_t *e = &s->icmp_log[i];

        /* full-row grey bg */
        tui_pkt_bg_cat(cat);
        clipline(y0 + 2 + i, x, w, "");

        int xc = x;
        move(y0 + 2 + i, xc);
        tui_pkt_bg_cat(cat);
        printw("  %-3s ", e->is_v6 ? "v6" : "v4");
        xc += 6;
        /* src IP coloured */
        move(y0 + 2 + i, xc);
        tui_ip_addstr(e->src, cat);
        /* pad to 15 chars + trailing space */
        tui_pkt_bg_cat(cat);
        int srclen = (int)strlen(e->src);
        for (int j = srclen; j < 15; j++) addch(' ');
        addch(' ');
        xc += 16;
        /* desc column, colour-coded by class */
        int is_err = e->is_v6
            ? (e->type >= 1 && e->type <= 4)
            : (e->type == 3 || e->type == 11 || e->type == 12);
        int is_req = e->is_v6 ? (e->type == 128) : (e->type == 8);
        if (is_err)      attrset(COLOR_PAIR(CP_HEAT_HI));
        else if (is_req) attrset(COLOR_PAIR(CP_BRIGHT));
        else             tui_pkt_bg_cat(cat);
        move(y0 + 2 + i, xc);
        printw("%.*s", desc_w, e->desc);
    }
    for (int i = n; i < rows; i++) {
        tui_pkt_bg_cat(cat);
        clipline(y0 + 2 + i, x, w, "");
    }
}

static void draw_ssdp_panel(const sloth_state_t *s, int y0, int h, int x, int w) {
    panel_title(y0, x, w, "SSDP / UPnP", DASH_PANEL_SSDP);
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
    draw_conn_band      (s, conn_y, conn_h, x0,          conn_w);
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
        s->active_view = panel_to_view(s->dash_focus);
        break;
    default:
        break;
    }
}
