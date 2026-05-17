#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/ntp.h"
#include "ntp_log.h"

#define NTP_PAGE 30

void view_ntp_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = NTP_PAGE;
#endif

    tui_normal(); TPRINT(" NTP packets: ");
    tui_bright();  TPRINT("%d", s->ntp_log_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear  (newest first)");
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-8s  %-15s  %-15s  %-8s  %-3s  %-3s  %s\n",
           "Time", "Src", "Dst", "Mode", "V", "St", "Ref");
    TPRINT(" %-8s  %-15s  %-15s  %-8s  %-3s  %-3s  %s\n",
           "--------", "---------------", "---------------",
           "--------", "---", "---", "----------------");
    tui_normal();

    if (s->ntp_log_count == 0) {
        tui_dim();
        TPRINT("  (no NTP packets seen -- waiting for UDP/123 traffic)\n");
        tui_normal();
        return;
    }

    int page_top = s->ntp_log_sel - page / 2;
    if (page_top + page > s->ntp_log_count) page_top = s->ntp_log_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->ntp_log_count) page_end = s->ntp_log_count;

    for (int row = page_top; row < page_end; row++) {
        const ntp_log_entry_t *e = &s->ntp_log[row];

        char ts_buf[10];
        struct tm *tm = localtime(&e->ts);
        if (tm) strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        else    snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

        int is_server = (strcmp(e->mode, "server") == 0);
        int is_client = (strcmp(e->mode, "client") == 0);
        int unsync    = (e->stratum == 0 || e->stratum >= 16);

        if (row == s->ntp_log_sel) {
            tui_sel();
            TPRINT(" %-8s  %-15.15s  %-15.15s  %-8.8s  %-3u  %-3u  %-16.16s\n",
                   ts_buf, e->src, e->dst, e->mode,
                   e->version, e->stratum, e->ref);
            tui_reset();
        } else {
            tui_dim();   TPRINT(" %-8s", ts_buf);
            tui_dim();   TPRINT("  %-15.15s", e->src);
            tui_dim();   TPRINT("  %-15.15s", e->dst);

            /* mode color: server=bright, client=normal, others=dim */
            if      (is_server) tui_bright();
            else if (is_client) tui_normal();
            else                tui_dim();
            TPRINT("  %-8.8s", e->mode);

            tui_dim();   TPRINT("  %-3u", e->version);

            /* stratum: 1=bright (primary), 0/16+=heat, rest=normal */
            if      (e->stratum == 1) tui_bright();
            else if (unsync)          tui_heat(0.7);
            else                      tui_normal();
            TPRINT("  %-3u", e->stratum);

            tui_normal(); TPRINT("  %-16.16s\n", e->ref);
            tui_normal();
        }
    }
    tui_normal();
}

void view_ntp_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->ntp_log_sel > 0) s->ntp_log_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->ntp_log_count > 0 && s->ntp_log_sel < s->ntp_log_count - 1)
            s->ntp_log_sel++;
        break;
    case 'c': case 'C':
        ntp_log_clear();
        s->ntp_log_count = 0;
        s->ntp_log_sel   = 0;
        break;
    default:
        break;
    }
}
