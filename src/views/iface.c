#include <stdio.h>
#include <string.h>
#include "ntop.h"
#include "tui.h"
#include "history.h"
#include "util.h"
#include "views/iface.h"

/* ── sparkline ───────────────────────────────────────────── */

/* 8-level ASCII ramp: space → dense */
static const char SPARK[] = " ._-=+|#";

static void make_sparkline(const iface_hist_t *h, int use_rx,
                            char *out, int width) {
    /* find window max for scaling */
    double max_val = 1.0;
    for (int i = 0; i < h->count; i++) {
        int idx = ((h->head - h->count + i) % HIST_LEN + HIST_LEN) % HIST_LEN;
        double v = use_rx ? h->rx[idx] : h->tx[idx];
        if (v > max_val) max_val = v;
    }

    /* left-pad with spaces if history is shorter than width */
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
    /* ── ncurses ── */
    int sel = s->iface_sel;
    int rows = getmaxy(stdscr) - 4;   /* available rows for iface list */

    /* viewport: keep selected row visible */
    static int vp = 0;
    if (sel < vp) vp = sel;
    if (sel >= vp + rows) vp = sel - rows + 1;
    if (vp < 0) vp = 0;

    attron(A_BOLD);
    printw("  %-13s  %-11s  %-11s  %-*s  %-10s  %-10s\n",
           "Interface", "RX", "TX", HIST_LEN, "RX history", "Total RX", "Total TX");
    attroff(A_BOLD);

    for (int i = vp; i < s->iface_count && (i - vp) < rows; i++) {
        const iface_stat_t *f = &s->ifaces[i];
        int hidden = is_hidden(s, f->name);

        /* sparkline — use empty bar if hidden or no history */
        const iface_hist_t *h = NULL;
        for (int j = 0; j < MAX_IFACES; j++) {
            if (strncmp(s->iface_hist[j].name, f->name, 16) == 0) {
                h = &s->iface_hist[j]; break;
            }
        }
        if (h && !hidden)
            make_sparkline(h, 1, spark, HIST_LEN);
        else
            memset(spark, ' ', HIST_LEN), spark[HIST_LEN] = '\0';

        if (i == sel) attron(A_REVERSE);
        printw("  %c%-12s  %-11s  %-11s  [%s]  %-10s  %-10s%s\n",
               hidden ? 'h' : ' ',
               f->name,
               hidden ? "   hidden" : fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)),
               hidden ? ""          : fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)),
               spark,
               fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
               fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)),
               hidden ? "  (hidden)" : "");
        if (i == sel) attroff(A_REVERSE);
    }

    if (s->iface_count == 0)
        printw("  (no interfaces found)\n");

    /* footer */
    mvprintw(getmaxy(stdscr) - 1, 0,
             " ↑↓ navigate   t toggle hidden   %d interface%s",
             s->iface_count, s->iface_count == 1 ? "" : "s");

#else
    /* ── ANSI fallback ── */
    printf("  %-13s  %-11s  %-11s  %-*s  %-10s  %-10s\n",
           "Interface", "RX", "TX", HIST_LEN, "RX history", "Total RX", "Total TX");
    printf("  %s\n",
           "--------------------------------------------------------------------"
           "-----------------------");

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
        if (h && !hidden)
            make_sparkline(h, 1, spark, HIST_LEN);
        else
            memset(spark, ' ', HIST_LEN), spark[HIST_LEN] = '\0';

        printf(" %c%c%-12s  %-11s  %-11s  [%s]  %-10s  %-10s%s\n",
               sel    ? '>' : ' ',
               hidden ? 'h' : ' ',
               f->name,
               hidden ? "   hidden" : fmt_rate(f->rx_rate, rx_r, (int)sizeof(rx_r)),
               hidden ? ""          : fmt_rate(f->tx_rate, tx_r, (int)sizeof(tx_r)),
               spark,
               fmt_bytes(f->rx_bytes, rx_b, (int)sizeof(rx_b)),
               fmt_bytes(f->tx_bytes, tx_b, (int)sizeof(tx_b)),
               hidden ? "  (hidden)" : "");
    }

    if (s->iface_count == 0)
        printf("  (no interfaces found)\n");

    printf("\n  ↑↓ navigate   t toggle hidden   %d interface%s\n",
           s->iface_count, s->iface_count == 1 ? "" : "s");
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

        /* find in hidden list */
        int found = -1;
        for (int i = 0; i < s->iface_hidden_count; i++) {
            if (strncmp(s->iface_hidden[i], name, 16) == 0) {
                found = i; break;
            }
        }
        if (found >= 0) {
            /* unhide — remove entry by shifting */
            memmove(&s->iface_hidden[found],
                    &s->iface_hidden[found + 1],
                    (size_t)(s->iface_hidden_count - found - 1) * 16);
            s->iface_hidden_count--;
        } else if (s->iface_hidden_count < MAX_IFACES) {
            /* hide — append */
            memcpy(s->iface_hidden[s->iface_hidden_count], name, 16);
            s->iface_hidden_count++;
        }
        break;
    }

    default: break;
    }
}
