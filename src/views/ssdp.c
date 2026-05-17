#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/ssdp.h"
#include "ssdp_snoop.h"

#define SSDP_PAGE 30

/* Return the most readable part of a UPnP type string. */
static const char *short_type(const char *nt) {
    const char *last = strrchr(nt, ':');
    if (!last) return nt;
    if (last == nt) return nt + 1;
    const char *prev = last - 1;
    while (prev > nt && *prev != ':') prev--;
    if (*prev == ':') return prev + 1;
    return nt;
}

void view_ssdp_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = SSDP_PAGE;
#endif

    tui_normal(); TPRINT(" UPnP/SSDP devices: ");
    tui_bright();  TPRINT("%d", s->ssdp_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear");
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-15s  %-7s  %-24s  %s\n",
           "IP", "Status", "Type", "Location");
    TPRINT(" %-15s  %-7s  %-24s  %s\n",
           "---------------", "-------",
           "------------------------", "--------");
    tui_normal();

    if (s->ssdp_count == 0) {
        tui_dim();
        TPRINT("  (no SSDP devices seen -- waiting for UDP/1900 traffic)\n");
        tui_normal();
        return;
    }

    int page_top = s->ssdp_sel - page / 2;
    if (page_top + page > s->ssdp_count) page_top = s->ssdp_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->ssdp_count) page_end = s->ssdp_count;

    time_t now = time(NULL);
    for (int row = page_top; row < page_end; row++) {
        const ssdp_device_t *e = &s->ssdp_devices[row];

        int age = (int)(now - e->last_seen);
        char age_buf[16];
        if (age < 60)        snprintf(age_buf, sizeof(age_buf), "%ds", age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%dm", age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%dh", age / 3600);

        const char *ts  = short_type(e->type);
        const char *loc = e->location[0] ? e->location : "--";

        if (row == s->ssdp_sel) {
            tui_sel();
            TPRINT(" %-15.15s  %-7.7s  %-24.24s  %.34s\n",
                   e->ip, e->nts, ts, loc);
            tui_reset();
        } else {
            /* dim the byebye entries */
            if (strcmp(e->nts, "byebye") == 0) tui_dim();
            else                                tui_normal();
            TPRINT(" %-15.15s", e->ip);
            if (strcmp(e->nts, "alive") == 0)        tui_bright();
            else if (strcmp(e->nts, "byebye") == 0)  tui_dim();
            else                                      tui_normal();
            TPRINT("  %-7.7s", e->nts);
            tui_normal();
            TPRINT("  %-24.24s", ts);
            tui_dim();
            TPRINT("  %.34s\n", loc);
            tui_normal();
        }
    }
    tui_normal();
}

void view_ssdp_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->ssdp_sel > 0) s->ssdp_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->ssdp_count > 0 && s->ssdp_sel < s->ssdp_count - 1)
            s->ssdp_sel++;
        break;
    case 'c': case 'C':
        ssdp_clear();
        s->ssdp_count = 0;
        s->ssdp_sel   = 0;
        break;
    default:
        break;
    }
}
