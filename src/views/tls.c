#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/tls.h"
#include "tls_log.h"

#define TLS_PAGE 30

void view_tls_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = TLS_PAGE;
#endif

    tui_normal(); TPRINT(" TLS connections: ");
    tui_bright();  TPRINT("%d", s->tls_log_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear  (newest first)");
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-8s  %-15s  %-26s  %-7s  %-12s  %s\n",
           "Time", "Src", "Host (SNI)", "Ver", "JA3", "Dst");
    TPRINT(" %-8s  %-15s  %-26s  %-7s  %-12s  %s\n",
           "--------", "---------------",
           "--------------------------", "-------",
           "------------", "---------------");
    tui_normal();

    if (s->tls_log_count == 0) {
        tui_dim();
        TPRINT("  (no TLS ClientHello frames seen -- waiting for TCP/443 traffic)\n");
        tui_normal();
        return;
    }

    int page_top = s->tls_log_sel - page / 2;
    if (page_top + page > s->tls_log_count) page_top = s->tls_log_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->tls_log_count) page_end = s->tls_log_count;

    for (int row = page_top; row < page_end; row++) {
        const tls_log_entry_t *e = &s->tls_log[row];

        char ts_buf[10];
        struct tm *tm = localtime(&e->ts);
        if (tm) strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        else    snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

        const char *host = e->host[0] ? e->host : "(no SNI)";

        int is13 = (strcmp(e->tls_ver, "TLS 1.3") == 0);
        int old  = (strcmp(e->tls_ver, "TLS 1.1") == 0 ||
                    strcmp(e->tls_ver, "TLS 1.0") == 0 ||
                    strcmp(e->tls_ver, "TLS")     == 0);

        /* short JA3: first 12 hex chars is enough to recognise common
           clients (Chrome, Firefox, curl) at a glance. */
        char ja3_short[13];
        snprintf(ja3_short, sizeof(ja3_short), "%.12s",
                 e->ja3[0] ? e->ja3 : "-");

        if (row == s->tls_log_sel) {
            tui_sel();
            TPRINT(" %-8s  %-15.15s  %-26.26s  %-7s  %-12s  %s\n",
                   ts_buf, e->src, host, e->tls_ver, ja3_short, e->dst);
            tui_reset();
        } else {
            tui_dim();  TPRINT(" %-8s", ts_buf);
            tui_dim();  TPRINT("  %-15.15s", e->src);

            /* host: no-SNI entries dimmed */
            if (!e->host[0]) tui_dim(); else tui_normal();
            TPRINT("  %-26.26s", host);

            /* version color: TLS 1.3 bright, old versions heat */
            if (is13)     tui_bright();
            else if (old) tui_heat(0.6);
            else          tui_normal();
            TPRINT("  %-7s", e->tls_ver);

            /* JA3 in dim phosphor */
            tui_dim(); TPRINT("  %-12s", ja3_short);

            tui_dim(); TPRINT("  %s\n", e->dst);
            tui_normal();
        }
    }
    tui_normal();
}

void view_tls_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->tls_log_sel > 0) s->tls_log_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->tls_log_count > 0 && s->tls_log_sel < s->tls_log_count - 1)
            s->tls_log_sel++;
        break;
    case 'c': case 'C':
        tls_log_clear();
        s->tls_log_count = 0;
        s->tls_log_sel   = 0;
        break;
    default:
        break;
    }
}
