#include <stdio.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/dhcp_snoop.h"
#include "../dhcp_snoop.h"

#define DHCP_PAGE 30

static const char *msg_label(uint8_t t) {
    switch (t) {
    case 1: return "DISCOVER";
    case 2: return "OFFER";
    case 3: return "REQUEST";
    case 4: return "DECLINE";
    case 5: return "ACK";
    case 6: return "NAK";
    case 7: return "RELEASE";
    case 8: return "INFORM";
    default: return "?";
    }
}

void view_dhcp_snoop_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = DHCP_PAGE;
#endif

    tui_normal(); TPRINT(" Live DHCP events: ");
    tui_bright();  TPRINT("%d", s->dhcp_event_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear");
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-18s  %-15s  %-20s  %-8s  %s\n",
           "MAC", "IP", "Hostname", "Type", "Age");
    TPRINT(" %-18s  %-15s  %-20s  %-8s  %s\n",
           "------------------", "---------------",
           "--------------------", "--------", "---");
    tui_normal();

    if (s->dhcp_event_count == 0) {
        tui_dim();
        TPRINT("  (no DHCP events seen -- waiting for UDP/67-68 traffic)\n");
        tui_normal();
        return;
    }

    int page_top = s->dhcp_event_sel - page / 2;
    if (page_top + page > s->dhcp_event_count)
        page_top = s->dhcp_event_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->dhcp_event_count) page_end = s->dhcp_event_count;

    time_t now = time(NULL);
    for (int row = page_top; row < page_end; row++) {
        const dhcp_event_t *e = &s->dhcp_events[row];

        int age = (int)(now - e->last_seen);
        char age_buf[16];
        if (age < 60)        snprintf(age_buf, sizeof(age_buf), "%ds", age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%dm", age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%dh", age / 3600);

        const char *ipstr   = e->ip[0]       ? e->ip       : "--";
        const char *hosstr  = e->hostname[0]  ? e->hostname : "--";

        if (row == s->dhcp_event_sel) {
            tui_sel();
            TPRINT(" %-18.18s  %-15.15s  %-20.20s  %-8.8s  %s\n",
                   e->mac, ipstr, hosstr, msg_label(e->msg_type), age_buf);
            tui_reset();
        } else {
            tui_dim();    TPRINT(" %-18.18s", e->mac);
            tui_normal(); TPRINT("  %-15.15s", ipstr);
            tui_bright(); TPRINT("  %-20.20s", hosstr);
            tui_dim();    TPRINT("  %-8.8s  %s\n",
                                 msg_label(e->msg_type), age_buf);
            tui_normal();
        }
    }
    tui_normal();
}

void view_dhcp_snoop_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->dhcp_event_sel > 0) s->dhcp_event_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->dhcp_event_count > 0 &&
            s->dhcp_event_sel < s->dhcp_event_count - 1)
            s->dhcp_event_sel++;
        break;
    case 'c': case 'C':
        dhcp_snoop_clear();
        s->dhcp_event_count = 0;
        s->dhcp_event_sel   = 0;
        break;
    default:
        break;
    }
}
