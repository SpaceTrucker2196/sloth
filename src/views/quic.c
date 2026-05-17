#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/quic.h"
#include "quic_log.h"
#include "filter.h"

#define QUIC_PAGE 30

void view_quic_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = QUIC_PAGE;
#endif

    tui_normal(); TPRINT(" QUIC sessions: ");
    tui_bright();  TPRINT("%d", s->quic_log_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear  (newest first)");
    tui_filter_status(s);
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-8s  %-15s  %-15s  %-26s  %s\n",
           "Time", "Src", "Dst", "Host", "Ver");
    TPRINT(" %-8s  %-15s  %-15s  %-26s  %s\n",
           "--------", "---------------", "---------------",
           "--------------------------", "-------");
    tui_normal();

    if (s->quic_log_count == 0) {
        tui_dim();
        TPRINT("  (no QUIC Initial packets seen -- waiting for UDP/443 traffic)\n");
        tui_normal();
        return;
    }

    int page_top = s->quic_log_sel - page / 2;
    if (page_top + page > s->quic_log_count) page_top = s->quic_log_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->quic_log_count) page_end = s->quic_log_count;

    for (int row = page_top; row < page_end; row++) {
        const quic_log_entry_t *e = &s->quic_log[row];
        if (s->filter[0] &&
            !filter_match_any(s->filter, e->src, e->dst,
                              e->host, e->ver, NULL))
            continue;

        char ts_buf[10];
        struct tm *tm = localtime(&e->ts);
        if (tm) strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        else    snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

        const char *host   = e->host[0] ? e->host : "(unknown)";
        int         is_v2  = (strcmp(e->ver, "v2")    == 0);
        int         is_old = (strcmp(e->ver, "draft")  == 0);

        if (row == s->quic_log_sel) {
            tui_sel();
            TPRINT(" %-8s  %-15.15s  %-15.15s  %-26.26s  %s\n",
                   ts_buf, e->src, e->dst, host, e->ver);
            tui_reset();
        } else {
            tui_dim();  TPRINT(" %-8s", ts_buf);
            tui_dim();  TPRINT("  %-15.15s", e->src);
            tui_dim();  TPRINT("  %-15.15s", e->dst);

            if (!e->host[0]) tui_dim(); else tui_normal();
            TPRINT("  %-26.26s", host);

            /* version: v2=bright, draft=dim, v1=normal */
            if      (is_v2)  tui_bright();
            else if (is_old) tui_dim();
            else             tui_normal();
            TPRINT("  %s\n", e->ver);
            tui_normal();
        }
    }
    tui_normal();
}

void view_quic_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->quic_log_sel > 0) s->quic_log_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->quic_log_count > 0 && s->quic_log_sel < s->quic_log_count - 1)
            s->quic_log_sel++;
        break;
    case 'c': case 'C':
        quic_log_clear();
        s->quic_log_count = 0;
        s->quic_log_sel   = 0;
        break;
    default:
        break;
    }
}
