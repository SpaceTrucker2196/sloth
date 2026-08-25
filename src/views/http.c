#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/http.h"
#include "captive_portal.h"
#include "http_log.h"
#include "filter.h"

#define HTTP_PAGE 30

static const char *method_color_class(const char *m) {
    /* return "bright" for safe methods, "normal" for modifying ones */
    return (strcmp(m,"GET")==0 || strcmp(m,"HEAD")==0) ? "bright" : "normal";
}

void view_http_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = HTTP_PAGE;
#endif

    tui_normal(); TPRINT(" HTTP requests: ");
    tui_bright();  TPRINT("%d", s->http_log_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear  (newest first)");
    tui_filter_status(s);
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-8s  %-15s  %-7s  %-24s  %s\n",
           "Time", "Src", "Method", "Host", "Path");
    TPRINT(" %-8s  %-15s  %-7s  %-24s  %s\n",
           "--------", "---------------", "-------",
           "------------------------", "----");
    tui_normal();

    if (s->http_log_count == 0) {
        tui_dim();
        TPRINT("  (no HTTP requests seen -- waiting for TCP/80,8080,8000 traffic)\n");
        tui_normal();
        return;
    }

    int page_top = s->http_log_sel - page / 2;
    if (page_top + page > s->http_log_count) page_top = s->http_log_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->http_log_count) page_end = s->http_log_count;

    for (int row = page_top; row < page_end; row++) {
        const http_log_entry_t *e = &s->http_log[row];
        if (s->filter[0] &&
            !filter_match_any(s->filter, e->src, e->host,
                              e->method, e->path, NULL))
            continue;

        char ts_buf[10];
        struct tm *tm = localtime(&e->ts);
        if (tm)
            strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        else
            snprintf(ts_buf, sizeof(ts_buf), "??:??:??");

        const char *host = e->host[0] ? e->host : "?";
        const char *path = e->path[0] ? e->path : "/";

        /* Connectivity-check rows carry an inline verdict (#69). A
         * sentinel URL has exactly one correct answer, so the row can
         * say whether it got it — and `?` is a third state, not a
         * hedge: sloth does not reassemble TCP, so a response it did
         * not see whole is one it cannot judge. */
        char status_buf[8];
        snprintf(status_buf, sizeof(status_buf), "%u", e->status);

        const char *cp_tag = "";
        if (cp_is_sentinel_host(e->host)) {
            if (!e->is_response)          cp_tag = " [check]";
            else if (!e->body_complete)   cp_tag = " [?]";
            else if (cp_check_response(e)) cp_tag = " [HIJACK]";
            else                          cp_tag = " [ok]";
        }

        if (row == s->http_log_sel) {
            tui_sel();
            TPRINT(" %-8s  %-15.15s  %-7.7s  %-24.24s  %.40s%s\n",
                   ts_buf, e->src,
                   e->is_response ? status_buf : e->method,
                   host, path, cp_tag);
            tui_reset();
        } else {
            tui_dim(); TPRINT(" %-8s", ts_buf);
            tui_dim(); TPRINT("  %-15.15s", e->src);

            /* method color: GET/HEAD bright, others normal */
            if (strcmp(method_color_class(e->method), "bright") == 0)
                tui_bright();
            else
                tui_normal();
            TPRINT("  %-7.7s", e->is_response ? status_buf : e->method);

            tui_normal();
            TPRINT("  %-24.24s", host);

            tui_dim();
            TPRINT("  %.40s", path);
            if (cp_tag[0]) {
                if (strcmp(cp_tag, " [HIJACK]") == 0) tui_heat(1.0);
                else if (strcmp(cp_tag, " [ok]") == 0) tui_normal();
                else tui_dim();
                TPRINT("%s", cp_tag);
            }
            TPRINT("\n");
            tui_normal();
        }
    }
    tui_normal();
}

void view_http_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->http_log_sel > 0) s->http_log_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->http_log_count > 0 && s->http_log_sel < s->http_log_count - 1)
            s->http_log_sel++;
        break;
    case 'c': case 'C':
        http_log_clear();
        s->http_log_count = 0;
        s->http_log_sel   = 0;
        break;
    default:
        break;
    }
}
