#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/dns_log.h"
#include "../dns_log.h"
#include "filter.h"

#define DNS_PAGE 30

void view_dns_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = DNS_PAGE;
#endif

    tui_normal(); TPRINT(" DNS log: ");
    tui_bright();  TPRINT("%d", s->dns_log_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear  (newest first)");
    tui_filter_status(s);
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-8s  %-15s  %s  %-5s  %-28s  %s\n",
           "Time", "Src", "Q", "Type", "Name", "Answer");
    TPRINT(" %-8s  %-15s  %s  %-5s  %-28s  %s\n",
           "--------", "---------------", "-",
           "-----", "----------------------------", "------");
    tui_normal();

    if (s->dns_log_count == 0) {
        tui_dim();
        TPRINT("  (no DNS packets seen -- waiting for UDP/53 traffic)\n");
        tui_normal();
        return;
    }

    int page_top = s->dns_log_sel - page / 2;
    if (page_top + page > s->dns_log_count) page_top = s->dns_log_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->dns_log_count) page_end = s->dns_log_count;

    for (int row = page_top; row < page_end; row++) {
        const dns_log_entry_t *e = &s->dns_log[row];
        if (s->filter[0] &&
            !filter_match_any(s->filter, e->src, e->qname,
                              e->answer, e->qtype, NULL))
            continue;

        char ts_buf[10];
        struct tm *tm = localtime(&e->ts);
        if (tm) strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        else    snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

        int is_nxdomain = (strcmp(e->answer, "NXDOMAIN") == 0);
        int has_answer  = (e->is_resp && e->answer[0] && !is_nxdomain);
        int is_aaaa     = (strcmp(e->qtype, "AAAA") == 0);

        if (row == s->dns_log_sel) {
            tui_sel();
            TPRINT(" %-8s  %-15.15s  %c  %-5.5s  %-28.28s  %s\n",
                   ts_buf, e->src,
                   e->is_resp ? 'R' : 'Q',
                   e->qtype, e->qname,
                   e->answer[0] ? e->answer : "-");
            tui_reset();
        } else {
            tui_dim();  TPRINT(" %-8s", ts_buf);
            tui_dim();  TPRINT("  %-15.15s", e->src);

            /* Q/R indicator */
            if (e->is_resp) tui_normal(); else tui_dim();
            TPRINT("  %c", e->is_resp ? 'R' : 'Q');

            /* type */
            tui_dim(); TPRINT("  %-5.5s", e->qtype);

            /* name: bright for responses with answers, dim for queries */
            if (has_answer)       tui_bright();
            else if (is_nxdomain) tui_heat(0.7);
            else                  tui_dim();
            TPRINT("  %-28.28s", e->qname);

            /* answer */
            if (is_nxdomain) {
                tui_heat(0.7); TPRINT("  %s", e->answer);
            } else if (has_answer) {
                if (is_aaaa) tui_normal(); else tui_bright();
                TPRINT("  %-15.15s", e->answer);
            } else {
                tui_dim(); TPRINT("  -");
            }
            TPRINT("\n");
            tui_normal();
        }
    }
    tui_normal();
}

void view_dns_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->dns_log_sel > 0) s->dns_log_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->dns_log_count > 0 && s->dns_log_sel < s->dns_log_count - 1)
            s->dns_log_sel++;
        break;
    case 'c': case 'C':
        dns_log_clear();
        s->dns_log_count = 0;
        s->dns_log_sel   = 0;
        break;
    default:
        break;
    }
}
