#include <stdio.h>
#include <string.h>
#include "ntop.h"
#include "tui.h"
#include "history.h"
#include "util.h"
#include "views/iface.h"

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

static const iface_hist_t *find_hist_ro(const ntop_state_t *s, const char *name) {
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

static void draw_iface_graph(const ntop_state_t *s) {
    if (s->iface_count == 0) {
        tui_dim(); TPRINT("  (no interfaces)\n"); tui_normal(); return;
    }

    const iface_stat_t *iface = &s->ifaces[s->iface_sel];
    const iface_hist_t *hist  = find_hist_ro(s, iface->name);

    tui_bright();
    TPRINT(" \xe2\x94\x80\xe2\x94\x80 %s  [Esc] back \xe2\x94\x80\xe2\x94\x80\n\n", iface->name);

    draw_series(hist, 1);
    TPRINT("\n");
    draw_series(hist, 0);

    tui_normal();
}

/* ── hidden helper ───────────────────────────────────────── */

static int is_hidden(const ntop_state_t *s, const char *name) {
    for (int i = 0; i < s->iface_hidden_count; i++) {
        if (strncmp(s->iface_hidden[i], name, 16) == 0)
            return 1;
    }
    return 0;
}

/* ── draw ────────────────────────────────────────────────── */

void view_iface_draw(const ntop_state_t *s) {
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
    printw("  %-13s  %-11s  %-11s  %-*s  %-10s  %-10s\n",
           "Interface", "RX", "TX", HIST_LEN + 2, "RX history", "Total RX", "Total TX");
    tui_normal();

    for (int i = vp; i < s->iface_count && (i - vp) < rows; i++) {
        const iface_stat_t *f = &s->ifaces[i];
        int hidden = is_hidden(s, f->name);

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
            printw("  %c%-12s  %-11s  %-11s  [%s]  %-10s  %-10s%s\n",
                   hidden ? 'h' : ' ', f->name,
                   hidden ? "   hidden" : fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)),
                   hidden ? ""          : fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)),
                   spark,
                   fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
                   fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)),
                   hidden ? "  (hidden)" : "");
            tui_reset();
        } else if (hidden) {
            tui_dim();
            printw("  h%-12s  (hidden)\n", f->name);
            tui_reset();
        } else {
            /* interface name: bright */
            tui_bright(); printw("  %-13s", f->name);
            /* RX rate */
            if (f->rx_rate > 0) tui_bright(); else tui_dim();
            printw("  %-11s", fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)));
            /* TX rate */
            if (f->tx_rate > 0) tui_bright(); else tui_dim();
            printw("  %-11s  [", fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)));
            /* sparkline: per-char intensity */
            if (h) print_sparkline_heat(h, 1, HIST_LEN);
            else { tui_dim(); printw("%*s", HIST_LEN, ""); }
            /* totals */
            tui_dim();
            printw("]  %-10s  %-10s\n",
                   fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
                   fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)));
            tui_normal();
        }
    }

    if (s->iface_count == 0) {
        tui_dim(); printw("  (no interfaces found)\n"); tui_normal();
    }

    tui_dim();
    mvprintw(getmaxy(stdscr) - 1, 0,
             " ↑↓ navigate   t toggle hidden   Enter graph   %d interface%s",
             s->iface_count, s->iface_count == 1 ? "" : "s");
    tui_normal();

#else
    /* ── ANSI fallback ── */
    tui_dim();
    printf("  %-13s  %-11s  %-11s  %-*s  %-10s  %-10s\n",
           "Interface", "RX", "TX", HIST_LEN + 2, "RX history", "Total RX", "Total TX");
    printf("  %s\n",
           "--------------------------------------------------------------------"
           "-----------------------");
    tui_normal();

    for (int i = 0; i < s->iface_count; i++) {
        const iface_stat_t *f = &s->ifaces[i];
        int hidden = is_hidden(s, f->name);
        int sel    = (i == s->iface_sel);

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
            printf(" >%c%-12s  %-11s  %-11s  [%s]  %-10s  %-10s%s",
                   hidden ? 'h' : ' ', f->name,
                   hidden ? "   hidden" : fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)),
                   hidden ? ""          : fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)),
                   spark,
                   fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
                   fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)),
                   hidden ? "  (hidden)" : "");
            tui_reset(); printf("\n");
        } else if (hidden) {
            tui_dim();
            printf("   h%-12s  (hidden)\n", f->name);
            tui_normal();
        } else {
            tui_bright(); printf("   %-13s", f->name);
            if (f->rx_rate > 0) tui_bright(); else tui_dim();
            printf("  %-11s", fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)));
            if (f->tx_rate > 0) tui_bright(); else tui_dim();
            printf("  %-11s  [", fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)));
            if (h) print_sparkline_heat(h, 1, HIST_LEN);
            else { tui_dim(); printf("%*s", HIST_LEN, ""); }
            tui_dim();
            printf("]  %-10s  %-10s\n",
                   fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
                   fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)));
            tui_normal();
        }
    }

    if (s->iface_count == 0) {
        tui_dim(); printf("  (no interfaces found)\n"); tui_normal();
    }

    tui_dim();
    printf("\n  ↑↓ navigate   t toggle hidden   Enter graph   %d interface%s\n",
           s->iface_count, s->iface_count == 1 ? "" : "s");
    tui_normal();
#endif
}

/* ── key handler ─────────────────────────────────────────── */

void view_iface_key(ntop_state_t *s, int key) {
    if (s->iface_graph) {
        if (key == '\033') s->iface_graph = 0;
        return;
    }

    switch (key) {
    case '\r': case '\n':
        if (s->iface_count > 0) s->iface_graph = 1;
        break;

    case NTOP_KEY_UP:
        if (s->iface_sel > 0) s->iface_sel--;
        break;

    case NTOP_KEY_DOWN:
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

    default: break;
    }
}
