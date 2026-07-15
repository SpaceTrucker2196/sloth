#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "history.h"
#include "util.h"
#include "oui.h"
#include "views/iface.h"
#include "capture/probe.h"

/* 4-char mode label — MON/WIFI/ETH highlight what a WiFi-SIGINT
 * operator cares about at a glance. UNKNOWN renders as "?". */
static const char *mode_label(iface_mode_t m) {
    switch (m) {
    case IFACE_MODE_MONITOR: return "MON ";
    case IFACE_MODE_WIFI:    return "WIFI";
    case IFACE_MODE_ETHER:   return "ETH ";
    default:                 return "?   ";
    }
}

/* Compact vendor from OUI table. Returns "-" if MAC is unknown /
 * all-zero, or if the OUI isn't in our embedded table. */
static const char *iface_vendor(const iface_stat_t *f) {
    static const uint8_t zero[6] = {0};
    if (memcmp(f->mac, zero, 6) == 0) return "-";
    const char *v = oui_lookup(f->mac);
    return (v && v[0]) ? v : "-";
}

/* ── sparkline ───────────────────────────────────────────── */

/* Unicode vertical block chars: levels 0 (empty) through 8 (full). */
static const char *SPARK_GLYPH[] = {
    " ",
    "\xe2\x96\x81",  /* ▁ */
    "\xe2\x96\x82",  /* ▂ */
    "\xe2\x96\x83",  /* ▃ */
    "\xe2\x96\x84",  /* ▄ */
    "\xe2\x96\x85",  /* ▅ */
    "\xe2\x96\x86",  /* ▆ */
    "\xe2\x96\x87",  /* ▇ */
    "\xe2\x96\x88",  /* █ */
};
#define SPARK_LEVELS 9

/* Build a UTF-8 sparkline string into out (must hold width*3+1 bytes). */
static void make_sparkline(const iface_hist_t *h, int use_rx,
                            char *out, int width) {
    double max_val = 1.0;
    for (int i = 0; i < h->count; i++) {
        int idx = ((h->head - h->count + i) % HIST_LEN + HIST_LEN) % HIST_LEN;
        double v = use_rx ? h->rx[idx] : h->tx[idx];
        if (v > max_val) max_val = v;
    }
    int pad = width - h->count;
    if (pad < 0) pad = 0;
    int pos = 0;
    for (int i = 0; i < pad && i < width; i++)
        out[pos++] = ' ';
    for (int i = 0; i < h->count && (pad + i) < width; i++) {
        int idx = ((h->head - h->count + i) % HIST_LEN + HIST_LEN) % HIST_LEN;
        double v = use_rx ? h->rx[idx] : h->tx[idx];
        int lv = (int)((v / max_val) * (SPARK_LEVELS - 1 - 0.001));
        if (lv < 0) lv = 0;
        if (lv >= SPARK_LEVELS) lv = SPARK_LEVELS - 1;
        const char *g = SPARK_GLYPH[lv];
        while (*g) out[pos++] = *g++;
    }
    out[pos] = '\0';
}

/* Print sparkline char-by-char with heat-gradient colour (grey→red). */
static void print_sparkline_heat(const iface_hist_t *h, int use_rx, int width) {
    double max_val = 1.0;
    for (int i = 0; i < h->count; i++) {
        int idx = ((h->head - h->count + i) % HIST_LEN + HIST_LEN) % HIST_LEN;
        double v = use_rx ? h->rx[idx] : h->tx[idx];
        if (v > max_val) max_val = v;
    }
    int pad = width - h->count;
    if (pad < 0) pad = 0;
    tui_dim();
    for (int i = 0; i < pad && i < width; i++)
        TPRINT(" ");
    for (int i = 0; i < h->count && (pad + i) < width; i++) {
        int idx = ((h->head - h->count + i) % HIST_LEN + HIST_LEN) % HIST_LEN;
        double v = use_rx ? h->rx[idx] : h->tx[idx];
        double frac = v / max_val;
        int lv = (int)(frac * (SPARK_LEVELS - 1 - 0.001));
        if (lv < 0) lv = 0;
        if (lv >= SPARK_LEVELS) lv = SPARK_LEVELS - 1;
        tui_heat(frac);
        TPRINT("%s", SPARK_GLYPH[lv]);
    }
}

/* ── read-only history lookup ────────────────────────────── */

static const iface_hist_t *find_hist_ro(const sloth_state_t *s, const char *name) {
    for (int i = 0; i < MAX_IFACES; i++) {
        if (s->iface_hist[i].count > 0 &&
            strncmp(s->iface_hist[i].name, name, 16) == 0)
            return &s->iface_hist[i];
    }
    return NULL;
}

/* ── 2-D bar graph ───────────────────────────────────────── */

#define GRAPH_H 8

static void draw_series(const iface_hist_t *hist, int is_rx) {
    double vals[HIST_LEN];
    memset(vals, 0, sizeof(vals));
    int count = 0;

    if (hist) {
        count = (hist->count < HIST_LEN) ? hist->count : HIST_LEN;
        int start = (hist->count < HIST_LEN) ? 0 : hist->head;
        for (int i = 0; i < count; i++) {
            int slot = (start + i) % HIST_LEN;
            int col  = HIST_LEN - count + i;  /* right-align: newest at HIST_LEN-1 */
            vals[col] = is_rx ? hist->rx[slot] : hist->tx[slot];
        }
    }

    double max_val = 1.0;
    for (int c = 0; c < HIST_LEN; c++)
        if (vals[c] > max_val) max_val = vals[c];

    char max_str[12], mid_str[12];
    fmt_rate(max_val, max_str, (int)sizeof(max_str));
    fmt_rate(max_val / 2.0, mid_str, (int)sizeof(mid_str));

    tui_bright();
    TPRINT("  %s  (peak: %s)\n", is_rx ? "RX" : "TX", max_str);

    for (int draw_r = GRAPH_H - 1; draw_r >= 0; draw_r--) {
        double threshold = max_val * draw_r / GRAPH_H;

        /* Y-axis: " %8.8s ┤" or "          │" (11 display chars each) */
        if (draw_r == GRAPH_H - 1) {
            tui_dim(); TPRINT(" %8.8s \xe2\x94\xa4", max_str);
        } else if (draw_r == GRAPH_H / 2) {
            tui_dim(); TPRINT(" %8.8s \xe2\x94\xa4", mid_str);
        } else if (draw_r == 0) {
            tui_dim(); TPRINT(" %8s \xe2\x94\xa4", "0");
        } else {
            tui_dim(); TPRINT("          \xe2\x94\x82");
        }

        /* Data columns */
        for (int c = 0; c < HIST_LEN; c++) {
            int filled = (vals[c] > threshold);
            if (draw_r == 0 && !filled) {
                tui_dim(); TPRINT("\xe2\x94\x80");      /* ─ baseline */
            } else if (filled) {
                if (is_rx) tui_bright(); else tui_dim();
                TPRINT("\xe2\x96\x88");                 /* █ */
            } else {
                tui_dim(); TPRINT(" ");
            }
        }
        TPRINT("\n");
    }

    /* X-axis label */
    tui_dim();
    TPRINT("           %-*snow\n", HIST_LEN - 3, "older");
    tui_normal();
}

static void draw_iface_detail_stats(const iface_stat_t *iface) {
    char rx_b[16], tx_b[16], rxp_b[16], txp_b[16];

    /* line 1: speed / MTU */
    tui_dim(); TPRINT("  Speed: ");
    if (iface->speed_mbps > 0) {
        tui_bright();
        if (iface->speed_mbps >= 1000)
            TPRINT("%d Gbps", iface->speed_mbps / 1000);
        else
            TPRINT("%d Mbps", iface->speed_mbps);
    } else {
        tui_dim(); TPRINT("--");
    }
    tui_dim(); TPRINT("   MTU: ");
    if (iface->mtu > 0) { tui_bright(); TPRINT("%u", iface->mtu); }
    else                 { tui_dim();    TPRINT("--"); }
    TPRINT("\n");

    /* line 2: cumulative bytes / packets */
    fmt_bytes(iface->rx_bytes, rx_b, (int)sizeof(rx_b));
    fmt_bytes(iface->tx_bytes, tx_b, (int)sizeof(tx_b));
    fmt_bytes(iface->rx_packets, rxp_b, (int)sizeof(rxp_b));
    fmt_bytes(iface->tx_packets, txp_b, (int)sizeof(txp_b));

    tui_dim();   TPRINT("  Total RX: ");
    tui_bright(); TPRINT("%-10s", rx_b);
    tui_dim();   TPRINT("  TX: ");
    tui_bright(); TPRINT("%-10s", tx_b);
    tui_dim();   TPRINT("  pkts rx/tx: ");
    tui_bright(); TPRINT("%s / %s", rxp_b, txp_b);
    TPRINT("\n");

    /* line 3: errors / drops — only shown when non-zero */
    int have_err = (iface->rx_errors || iface->rx_drops ||
                    iface->tx_errors || iface->tx_drops);
    if (have_err) {
        tui_bright(); TPRINT("  Errors ");
        tui_dim();    TPRINT("rx: ");
        if (iface->rx_errors) { tui_bright(); TPRINT("%llu ", (unsigned long long)iface->rx_errors); }
        else                  { tui_dim();    TPRINT("-- "); }
        tui_dim(); TPRINT("drop: ");
        if (iface->rx_drops)  { tui_bright(); TPRINT("%llu  ", (unsigned long long)iface->rx_drops); }
        else                  { tui_dim();    TPRINT("--  "); }
        tui_dim(); TPRINT("tx: ");
        if (iface->tx_errors) { tui_bright(); TPRINT("%llu ", (unsigned long long)iface->tx_errors); }
        else                  { tui_dim();    TPRINT("-- "); }
        tui_dim(); TPRINT("drop: ");
        if (iface->tx_drops)  { tui_bright(); TPRINT("%llu", (unsigned long long)iface->tx_drops); }
        else                  { tui_dim();    TPRINT("--"); }
        TPRINT("\n");
    } else {
        tui_dim(); TPRINT("  Errors: --\n");
    }
    TPRINT("\n");
    tui_normal();
}

static void draw_iface_graph(const sloth_state_t *s) {
    if (s->iface_count == 0) {
        tui_dim(); TPRINT("  (no interfaces)\n"); tui_normal(); return;
    }

    const iface_stat_t *iface = &s->ifaces[s->iface_sel];
    const iface_hist_t *hist  = find_hist_ro(s, iface->name);

    tui_bright();
    TPRINT(" \xe2\x94\x80\xe2\x94\x80 %s  [Esc] back \xe2\x94\x80\xe2\x94\x80\n\n", iface->name);

    draw_iface_detail_stats(iface);

    draw_series(hist, 1);
    TPRINT("\n");
    draw_series(hist, 0);

    tui_normal();
}

/* ── hidden helper ───────────────────────────────────────── */

/* Declared in sloth.h — shared with the dashboard iface band so the
 * election is honoured in both places. */
int iface_is_hidden(const sloth_state_t *s, const char *name) {
    for (int i = 0; i < s->iface_hidden_count; i++) {
        if (strncmp(s->iface_hidden[i], name, 16) == 0)
            return 1;
    }
    return 0;
}

/* #25: hide every interface except the monitor capture radio (and the IP
 * capture iface, if any) so a monitor-mode launch foregrounds the RF world.
 * Display-only; the operator can un-hide from the interface view. */
void iface_hide_non_monitor(sloth_state_t *s) {
    for (int i = 0; i < s->iface_count; i++) {
        const char *nm = s->ifaces[i].name;
        if (!nm[0]) continue;
        if (s->probe_iface[0] && strcmp(nm, s->probe_iface) == 0) continue;
        if (s->pkt_iface[0]   && strcmp(nm, s->pkt_iface)   == 0) continue;
        if (iface_is_hidden(s, nm)) continue;
        if (s->iface_hidden_count < MAX_IFACES)
            snprintf(s->iface_hidden[s->iface_hidden_count++],
                     sizeof(s->iface_hidden[0]), "%s", nm);
    }
}

/* Declared in sloth.h — shared with the capture callback (on_packet)
 * so a deselected iface's packets are dropped before any decode runs.
 * Kept independent of iface_is_hidden: hide is display-only, deselect
 * is data-stream. See issue #17. */
int iface_is_deselected(const sloth_state_t *s, const char *name) {
    for (int i = 0; i < s->iface_deselected_count; i++) {
        if (strncmp(s->iface_deselected[i], name, 16) == 0)
            return 1;
    }
    return 0;
}

/* Launch-time allow-list (#35) — the headless complement to the [y]
 * deselect above. Kept independent of the deselect election: the
 * capture callback drops when either one rejects. An empty list means
 * unrestricted, so a bare launch (or a failed --monitor-only resolve)
 * changes nothing. */
int iface_is_allowed(const sloth_state_t *s, const char *name) {
    if (s->iface_allowed_count == 0) return 1;
    for (int i = 0; i < s->iface_allowed_count; i++) {
        if (strncmp(s->iface_allowed[i], name, 16) == 0)
            return 1;
    }
    return 0;
}

int iface_allow_add(sloth_state_t *s, const char *name) {
    if (!name || !name[0]) return 0;
    for (int i = 0; i < s->iface_allowed_count; i++) {
        if (strncmp(s->iface_allowed[i], name, 16) == 0)
            return 1;   /* dedupe: already present */
    }
    if (s->iface_allowed_count >= MAX_IFACES) return 0;
    snprintf(s->iface_allowed[s->iface_allowed_count++],
             sizeof(s->iface_allowed[0]), "%s", name);
    return 1;
}

/* Display-side complement of iface_is_allowed (#37): true only when a
 * non-empty allow-list is dropping this iface's frames. Split out so
 * the view marks exactly what the capture callback rejects — an empty
 * list excludes nothing, keeping the bare-launch render unchanged. */
int iface_is_excluded(const sloth_state_t *s, const char *name) {
    return s->iface_allowed_count > 0 && !iface_is_allowed(s, name);
}

/* Row-prefix election, the one source of truth for both render paths:
 * hidden > deselected > excluded > scanning > default. Deselect wins
 * over excluded so an iface rejected by both elections reads as the
 * one the operator can still toggle. */
char iface_row_prefix(const sloth_state_t *s, const char *name, int is_scan) {
    if (iface_is_hidden(s, name))     return 'h';
    if (iface_is_deselected(s, name)) return 'd';
    if (iface_is_excluded(s, name))   return 'x';
    return is_scan ? 's' : ' ';
}

/* ── draw ────────────────────────────────────────────────── */

/* Format the monitor radio's scan state into `buf`: the channel list with
 * the currently-scanned channel bracketed, e.g. " ch: 1  6 [11] 36 44".
 * Falls back to "  [scanning]" when there's no live hop list (radio parked
 * on one channel). Structural (brackets, not colour) so it reads the same
 * on selected/inverted rows and in the ANSI build. */
static void fmt_scan_bar(const sloth_state_t *s, char *buf, int sz) {
    if (s->scan_chan_count <= 0) {
        snprintf(buf, sz, "  [scanning]");
        return;
    }
    int off = snprintf(buf, sz, "  ch:");
    for (int i = 0; i < s->scan_chan_count && off < sz - 8; i++)
        off += snprintf(buf + off, sz - off,
                        i == s->scan_cur_idx ? "[%d]" : " %d ",
                        s->scan_chans[i]);
}

void view_iface_draw(const sloth_state_t *s) {
    if (s->iface_graph) { draw_iface_graph(s); return; }

    char spark[HIST_LEN * 3 + 1];  /* 3 UTF-8 bytes per block glyph */
    char rx_r[16], tx_r[16], rx_b[16], tx_b[16];

#ifdef WITH_NCURSES
    int sel  = s->iface_sel;
    int rows = getmaxy(stdscr) - 4;

    static int vp = 0;
    if (sel < vp) vp = sel;
    if (sel >= vp + rows) vp = sel - rows + 1;
    if (vp < 0) vp = 0;

    tui_dim();
    printw("  %-10s %-4s %-12s %-10s %-10s %-*s %-9s %-9s\n",
           "Interface", "Mode", "Vendor", "RX", "TX",
           HIST_LEN + 2, "RX history", "Total RX", "Total TX");
    tui_normal();

    for (int i = vp; i < s->iface_count && (i - vp) < rows; i++) {
        const iface_stat_t *f = &s->ifaces[i];
        int hidden     = iface_is_hidden(s, f->name);
        int deselected = iface_is_deselected(s, f->name);
        int excluded   = iface_is_excluded(s, f->name);
        int is_scan = (s->probe_iface[0] && strncmp(s->probe_iface, f->name, 16) == 0);
        char scanbuf[128];
        if (is_scan) fmt_scan_bar(s, scanbuf, sizeof(scanbuf));
        char pfx    = iface_row_prefix(s, f->name, is_scan);
        const char *mode   = mode_label(f->mode);
        const char *vendor = iface_vendor(f);

        const iface_hist_t *h = NULL;
        for (int j = 0; j < MAX_IFACES; j++) {
            if (strncmp(s->iface_hist[j].name, f->name, 16) == 0) {
                h = &s->iface_hist[j]; break;
            }
        }

        if (i == sel) {
            if (h && !hidden) make_sparkline(h, 1, spark, HIST_LEN);
            else memset(spark, ' ', HIST_LEN), spark[HIST_LEN] = '\0';
            tui_sel();
            printw("  %c%-9s %-4s %-12.12s %-10s %-10s [%s] %-9s %-9s%s\n",
                   pfx, f->name, mode, vendor,
                   hidden ? "   hidden" : fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)),
                   hidden ? ""          : fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)),
                   spark,
                   fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
                   fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)),
                   is_scan     ? scanbuf
                   : hidden    ? "  (hidden)"
                   : deselected? "  (deselected)"
                   : excluded  ? "  (excluded)"
                   : (f->mode == IFACE_MODE_MONITOR ? "  [monitor]" : ""));
            tui_reset();
        } else if (hidden) {
            tui_dim();
            printw("  h%-9s %-4s %-12.12s  (hidden)\n", f->name, mode, vendor);
            tui_reset();
        } else {
            if (is_scan || f->mode == IFACE_MODE_MONITOR) tui_bright();
            else tui_normal();
            printw("  %c%-9s %-4s %-12.12s",
                   pfx, f->name, mode, vendor);
            /* RX rate */
            if (f->rx_rate > 0) tui_bright(); else tui_dim();
            printw(" %-10s", fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)));
            /* TX rate */
            if (f->tx_rate > 0) tui_bright(); else tui_dim();
            printw(" %-10s [", fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)));
            /* sparkline: per-char intensity */
            if (h) print_sparkline_heat(h, 1, HIST_LEN);
            else { tui_dim(); printw("%*s", HIST_LEN, ""); }
            /* totals */
            tui_dim();
            printw("] %-9s %-9s",
                   fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
                   fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)));
            if (is_scan) { tui_bright(); printw("%s", scanbuf); }
            else if (deselected) { tui_dim(); printw("  (deselected)"); }
            else if (excluded)   { tui_dim(); printw("  (excluded)"); }
            else if (f->mode == IFACE_MODE_MONITOR) { tui_bright(); printw("  [monitor]"); }
            printw("\n");
            tui_normal();
        }
    }

    if (s->iface_count == 0) {
        tui_dim(); printw("  (no interfaces found)\n"); tui_normal();
    }

    tui_dim();
    mvprintw(getmaxy(stdscr) - 1, 0,
             " ↑↓ navigate  t hide  y deselect data  m scan  Enter detail  %d iface%s",
             s->iface_count, s->iface_count == 1 ? "" : "s");
    tui_normal();

#else
    /* ── ANSI fallback ── */
    tui_dim();
    printf("  %-10s %-4s %-12s %-10s %-10s %-*s %-9s %-9s\n",
           "Interface", "Mode", "Vendor", "RX", "TX",
           HIST_LEN + 2, "RX history", "Total RX", "Total TX");
    printf("  %s\n",
           "--------------------------------------------------------------------"
           "-----------------------");
    tui_normal();

    for (int i = 0; i < s->iface_count; i++) {
        const iface_stat_t *f = &s->ifaces[i];
        int hidden     = iface_is_hidden(s, f->name);
        int deselected = iface_is_deselected(s, f->name);
        int excluded   = iface_is_excluded(s, f->name);
        int is_scan = (s->probe_iface[0] && strncmp(s->probe_iface, f->name, 16) == 0);
        char scanbuf[128];
        if (is_scan) fmt_scan_bar(s, scanbuf, sizeof(scanbuf));
        int sel     = (i == s->iface_sel);
        char pfx    = iface_row_prefix(s, f->name, is_scan);
        const char *mode   = mode_label(f->mode);
        const char *vendor = iface_vendor(f);

        const iface_hist_t *h = NULL;
        for (int j = 0; j < MAX_IFACES; j++) {
            if (strncmp(s->iface_hist[j].name, f->name, 16) == 0) {
                h = &s->iface_hist[j]; break;
            }
        }

        if (sel) {
            if (h && !hidden) make_sparkline(h, 1, spark, HIST_LEN);
            else memset(spark, ' ', HIST_LEN), spark[HIST_LEN] = '\0';
            tui_sel();
            printf(" >%c%-9s %-4s %-12.12s %-10s %-10s [%s] %-9s %-9s%s",
                   pfx, f->name, mode, vendor,
                   hidden ? "   hidden" : fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)),
                   hidden ? ""          : fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)),
                   spark,
                   fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
                   fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)),
                   is_scan     ? scanbuf
                   : hidden    ? "  (hidden)"
                   : deselected? "  (deselected)"
                   : excluded  ? "  (excluded)"
                   : (f->mode == IFACE_MODE_MONITOR ? "  [monitor]" : ""));
            tui_reset(); printf("\n");
        } else if (hidden) {
            tui_dim();
            printf("   h%-9s %-4s %-12.12s  (hidden)\n", f->name, mode, vendor);
            tui_normal();
        } else {
            if (is_scan || f->mode == IFACE_MODE_MONITOR) tui_bright();
            else tui_normal();
            printf("  %c%-9s %-4s %-12.12s",
                   pfx, f->name, mode, vendor);
            if (f->rx_rate > 0) tui_bright(); else tui_dim();
            printf(" %-10s", fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)));
            if (f->tx_rate > 0) tui_bright(); else tui_dim();
            printf(" %-10s [", fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)));
            if (h) print_sparkline_heat(h, 1, HIST_LEN);
            else { tui_dim(); printf("%*s", HIST_LEN, ""); }
            tui_dim();
            printf("] %-9s %-9s",
                   fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
                   fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)));
            if (is_scan) { tui_bright(); printf("%s", scanbuf); }
            else if (deselected) { tui_dim(); printf("  (deselected)"); }
            else if (excluded)   { tui_dim(); printf("  (excluded)"); }
            else if (f->mode == IFACE_MODE_MONITOR) { tui_bright(); printf("  [monitor]"); }
            printf("\n");
            tui_normal();
        }
    }

    if (s->iface_count == 0) {
        tui_dim(); printf("  (no interfaces found)\n"); tui_normal();
    }

    tui_dim();
    printf("\n  ↑↓ navigate  t hide  y deselect data  m scan  Enter detail  %d iface%s\n",
           s->iface_count, s->iface_count == 1 ? "" : "s");
    tui_normal();
#endif
}

/* ── key handler ─────────────────────────────────────────── */

void view_iface_key(sloth_state_t *s, int key) {
    if (s->iface_graph) {
        if (key == '\033') s->iface_graph = 0;
        return;
    }

    switch (key) {
    case '\r': case '\n':
        if (s->iface_count > 0) s->iface_graph = 1;
        break;

    case 'm': case 'M':
        if (s->iface_count > 0)
            probe_set_iface(s, s->ifaces[s->iface_sel].name);
        break;

    case SLOTH_KEY_UP:
        if (s->iface_sel > 0) s->iface_sel--;
        break;

    case SLOTH_KEY_DOWN:
        if (s->iface_count > 0 && s->iface_sel < s->iface_count - 1)
            s->iface_sel++;
        break;

    case 't': case 'T': {
        if (s->iface_count == 0) break;
        const char *name = s->ifaces[s->iface_sel].name;

        int found = -1;
        for (int i = 0; i < s->iface_hidden_count; i++) {
            if (strncmp(s->iface_hidden[i], name, 16) == 0) {
                found = i; break;
            }
        }
        if (found >= 0) {
            memmove(&s->iface_hidden[found],
                    &s->iface_hidden[found + 1],
                    (size_t)(s->iface_hidden_count - found - 1) * 16);
            s->iface_hidden_count--;
        } else if (s->iface_hidden_count < MAX_IFACES) {
            memcpy(s->iface_hidden[s->iface_hidden_count], name, 16);
            s->iface_hidden_count++;
        }
        break;
    }

    case 'y': case 'Y': {
        /* Toggle data-stream selection for the selected iface. Distinct
         * from hide ('t'): 'y' also drops the iface's packets from the
         * capture pipeline (issue #17). SLL2 detection lives in the
         * capture callback — on non-SLL2 datalinks this is a no-op for
         * the pipeline but the marker still renders. */
        if (s->iface_count == 0) break;
        const char *name = s->ifaces[s->iface_sel].name;

        int found = -1;
        for (int i = 0; i < s->iface_deselected_count; i++) {
            if (strncmp(s->iface_deselected[i], name, 16) == 0) {
                found = i; break;
            }
        }
        if (found >= 0) {
            memmove(&s->iface_deselected[found],
                    &s->iface_deselected[found + 1],
                    (size_t)(s->iface_deselected_count - found - 1) * 16);
            s->iface_deselected_count--;
        } else if (s->iface_deselected_count < MAX_IFACES) {
            memcpy(s->iface_deselected[s->iface_deselected_count], name, 16);
            s->iface_deselected_count++;
        }
        break;
    }

    default: break;
    }
}
