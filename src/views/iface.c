#include <stdio.h>
#include <string.h>
#include "ntop.h"
#include "tui.h"
#include "history.h"
#include "util.h"
#include "views/iface.h"

/* ── sparkline ───────────────────────────────────────────── */

static const char SPARK[] = " ._-=+|#";

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
    for (int i = 0; i < pad && i < width; i++)
        out[i] = ' ';
    for (int i = 0; i < h->count && (pad + i) < width; i++) {
        int idx = ((h->head - h->count + i) % HIST_LEN + HIST_LEN) % HIST_LEN;
        double v = use_rx ? h->rx[idx] : h->tx[idx];
        int lv = (int)((v / max_val) * 7.999);
        if (lv > 7) lv = 7;
        out[pad + i] = SPARK[lv];
    }
    out[width] = '\0';
}

/* Print the sparkline char-by-char varying phosphor intensity by amplitude. */
static void print_sparkline_phosphor(const iface_hist_t *h, int use_rx, int width) {
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
        int lv = (int)((v / max_val) * 7.999);
        if (lv > 7) lv = 7;
        if      (lv <= 2) tui_dim();
        else if (lv <= 4) tui_normal();
        else              tui_bright();
        TPRINT("%c", SPARK[lv]);
    }
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
    char spark[HIST_LEN + 1];
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
            if (h) print_sparkline_phosphor(h, 1, HIST_LEN);
            else { tui_dim(); printw("%*s", HIST_LEN, ""); }
            /* totals: dim (background info) */
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
             " ↑↓ navigate   t toggle hidden   %d interface%s",
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
            if (h) print_sparkline_phosphor(h, 1, HIST_LEN);
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
    printf("\n  ↑↓ navigate   t toggle hidden   %d interface%s\n",
           s->iface_count, s->iface_count == 1 ? "" : "s");
    tui_normal();
#endif
}

/* ── key handler ─────────────────────────────────────────── */

void view_iface_key(ntop_state_t *s, int key) {
    switch (key) {
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
