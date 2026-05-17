#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/icmp.h"
#include "icmp_log.h"

#define ICMP_PAGE 30

void view_icmp_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = ICMP_PAGE;
#endif

    tui_normal(); TPRINT(" ICMP messages: ");
    tui_bright();  TPRINT("%d", s->icmp_log_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear  (newest first)");
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-8s  %-15s  %-15s  %-3s  %-15s  %s\n",
           "Time", "Src", "Dst", "V", "Type", "Seq/Code");
    TPRINT(" %-8s  %-15s  %-15s  %-3s  %-15s  %s\n",
           "--------", "---------------", "---------------",
           "---", "---------------", "--------");
    tui_normal();

    if (s->icmp_log_count == 0) {
        tui_dim();
        TPRINT("  (no ICMP messages seen)\n");
        tui_normal();
        return;
    }

    int page_top = s->icmp_log_sel - page / 2;
    if (page_top + page > s->icmp_log_count) page_top = s->icmp_log_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->icmp_log_count) page_end = s->icmp_log_count;

    for (int row = page_top; row < page_end; row++) {
        const icmp_log_entry_t *e = &s->icmp_log[row];

        char ts_buf[10];
        struct tm *tm = localtime(&e->ts);
        if (tm) strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        else    snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

        int is_echo_req   = e->is_v6 ? (e->type == 128) : (e->type == 8);
        int is_echo_reply = e->is_v6 ? (e->type == 129) : (e->type == 0);
        int is_err        = e->is_v6
            ? (e->type >= 1 && e->type <= 4)
            : (e->type == 3 || e->type == 11 || e->type == 12);
        int is_echo = is_echo_req || is_echo_reply;

        char extra[16];
        if (is_echo) snprintf(extra, sizeof(extra), "seq=%u", e->seq);
        else         snprintf(extra, sizeof(extra), "code=%u", e->code);

        if (row == s->icmp_log_sel) {
            tui_sel();
            TPRINT(" %-8s  %-15.15s  %-15.15s  %-3s  %-15.15s  %s\n",
                   ts_buf, e->src, e->dst,
                   e->is_v6 ? "v6" : "v4",
                   e->desc, extra);
            tui_reset();
        } else {
            tui_dim();   TPRINT(" %-8s", ts_buf);
            tui_dim();   TPRINT("  %-15.15s", e->src);
            tui_dim();   TPRINT("  %-15.15s", e->dst);
            tui_dim();   TPRINT("  %-3s", e->is_v6 ? "v6" : "v4");

            /* color by type: echo req=bright, reply=normal, errors=heat, other=dim */
            if      (is_echo_req)   tui_bright();
            else if (is_echo_reply) tui_normal();
            else if (is_err)        tui_heat(0.7);
            else                    tui_dim();
            TPRINT("  %-15.15s", e->desc);

            tui_dim();   TPRINT("  %s\n", extra);
            tui_normal();
        }
    }
    tui_normal();
}

void view_icmp_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->icmp_log_sel > 0) s->icmp_log_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->icmp_log_count > 0 && s->icmp_log_sel < s->icmp_log_count - 1)
            s->icmp_log_sel++;
        break;
    case 'c': case 'C':
        icmp_log_clear();
        s->icmp_log_count = 0;
        s->icmp_log_sel   = 0;
        break;
    default:
        break;
    }
}
