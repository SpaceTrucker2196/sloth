#include <stdio.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/nbns.h"
#include "nbns_snoop.h"

#define NBNS_PAGE 30

static const char *suffix_label(uint8_t s) {
    switch (s) {
    case 0x00: return "Workstation";
    case 0x03: return "Messenger";
    case 0x1B: return "Domain Master";
    case 0x1C: return "Domain Group";
    case 0x1D: return "Master Browser";
    case 0x1E: return "Browser";
    case 0x20: return "File Server";
    default:   return "";
    }
}

void view_nbns_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = NBNS_PAGE;
#endif

    tui_normal(); TPRINT(" NetBIOS names: ");
    tui_bright();  TPRINT("%d", s->nbns_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear");
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-15s  %-15s  %-14s  %s\n",
           "Name", "IP", "Type", "Age");
    TPRINT(" %-15s  %-15s  %-14s  %s\n",
           "---------------", "---------------",
           "--------------", "---");
    tui_normal();

    if (s->nbns_count == 0) {
        tui_dim();
        TPRINT("  (no NetBIOS names seen -- waiting for UDP/137 traffic)\n");
        tui_normal();
        return;
    }

    int page_top = s->nbns_sel - page / 2;
    if (page_top + page > s->nbns_count) page_top = s->nbns_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->nbns_count) page_end = s->nbns_count;

    time_t now = time(NULL);
    for (int row = page_top; row < page_end; row++) {
        const nbns_name_t *e = &s->nbns_names[row];

        int age = (int)(now - e->last_seen);
        char age_buf[16];
        if (age < 60)        snprintf(age_buf, sizeof(age_buf), "%ds", age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%dm", age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%dh", age / 3600);

        if (row == s->nbns_sel) {
            tui_sel();
            TPRINT(" %-15.15s  %-15.15s  %-14.14s  %s\n",
                   e->name[0] ? e->name : "?",
                   e->ip[0]   ? e->ip   : "--",
                   suffix_label(e->suffix),
                   age_buf);
            tui_reset();
        } else {
            tui_bright(); TPRINT(" %-15.15s", e->name[0] ? e->name : "?");
            tui_normal(); TPRINT("  %-15.15s", e->ip[0] ? e->ip : "--");
            tui_dim();    TPRINT("  %-14.14s  %s\n",
                                 suffix_label(e->suffix), age_buf);
            tui_normal();
        }
    }
    tui_normal();
}

void view_nbns_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->nbns_sel > 0) s->nbns_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->nbns_count > 0 && s->nbns_sel < s->nbns_count - 1)
            s->nbns_sel++;
        break;
    case 'c': case 'C':
        nbns_clear();
        s->nbns_count = 0;
        s->nbns_sel   = 0;
        break;
    default:
        break;
    }
}
