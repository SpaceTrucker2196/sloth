#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/deauth.h"
#include "deauth_snoop.h"

#define DEAUTH_PAGE 30

static char g_mac_buf[18];

static const char *mac_str(const uint8_t *m) {
    snprintf(g_mac_buf, sizeof(g_mac_buf),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return g_mac_buf;
}

static const char *reason_str(uint16_t code) {
    switch (code) {
    case 0:  return "Reserved";
    case 1:  return "Unspecified";
    case 2:  return "Auth-expired";
    case 3:  return "Leaving";
    case 4:  return "Inactivity";
    case 5:  return "AP-full";
    case 6:  return "Class2-frame";
    case 7:  return "Class3-frame";
    case 8:  return "Leaving-BSS";
    case 15: return "4WHS-timeout";
    default: return NULL;
    }
}

static int is_broadcast(const uint8_t *m) {
    return m[0]==0xff && m[1]==0xff && m[2]==0xff &&
           m[3]==0xff && m[4]==0xff && m[5]==0xff;
}

void view_deauth_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 6;
    if (page < 1) page = 1;
#else
    int page = DEAUTH_PAGE;
#endif

    tui_normal(); TPRINT(" Deauth/Disassoc events: ");
    tui_bright();  TPRINT("%d", s->deauth_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear");
    if (s->probe_iface[0])
        TPRINT("  iface: %s", s->probe_iface);
    TPRINT("\n");

    /* flood alert banner */
    if (s->deauth_flood_active) {
        tui_heat(1.0);
        TPRINT(" !! DEAUTH FLOOD DETECTED");
        for (int i = 0; i < s->deauth_count; i++) {
            const deauth_event_t *e = &s->deauth_events[i];
            if (!e->flood) continue;
            char flood_buf[80];
            if (is_broadcast(e->dst))
                snprintf(flood_buf, sizeof(flood_buf),
                         " -- %s → BROADCAST (%d frames)",
                         mac_str(e->src), e->count);
            else
                snprintf(flood_buf, sizeof(flood_buf),
                         " -- %s → %s (%d frames)",
                         mac_str(e->src), mac_str(e->dst), e->count);
            TPRINT("%s", flood_buf);
            break;  /* show first flooder only */
        }
        TPRINT("\n");
        tui_normal();
    }

    tui_dim();
    TPRINT(" %-17s  %-17s  %-17s  %-8s  %-13s  %5s  %s\n",
           "Src", "Dst", "BSSID", "Type", "Reason", "Count", "Last");
    TPRINT(" %-17s  %-17s  %-17s  %-8s  %-13s  %5s  %s\n",
           "-----------------", "-----------------", "-----------------",
           "--------", "-------------", "-----", "----");
    tui_normal();

    if (s->deauth_count == 0) {
        tui_dim();
        TPRINT("  (no deauth/disassoc frames seen on monitor iface)\n");
        tui_normal();
        return;
    }

    int page_top = s->deauth_sel - page / 2;
    if (page_top + page > s->deauth_count) page_top = s->deauth_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->deauth_count) page_end = s->deauth_count;

    time_t now = time(NULL);
    for (int row = page_top; row < page_end; row++) {
        const deauth_event_t *e = &s->deauth_events[row];

        const char *type_str = (e->subtype == 12) ? "DEAUTH" : "DISASSOC";

        char rsn_buf[16];
        const char *rs = reason_str(e->reason);
        if (rs)
            snprintf(rsn_buf, sizeof(rsn_buf), "%s", rs);
        else
            snprintf(rsn_buf, sizeof(rsn_buf), "code-%u", e->reason);

        int age = (int)(now - e->last_seen);
        char age_buf[16];
        if      (age < 60)   snprintf(age_buf, sizeof(age_buf), "%ds",  age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%dm",  age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%dh",  age / 3600);

        /* format dst — abbreviate broadcast */
        char dst_buf[18];
        if (is_broadcast(e->dst))
            snprintf(dst_buf, sizeof(dst_buf), "ff:ff:ff:ff:ff:ff");
        else
            snprintf(dst_buf, sizeof(dst_buf), "%s", mac_str(e->dst));

        if (row == s->deauth_sel) {
            tui_sel();
            TPRINT(" %-17.17s  %-17.17s  %-17.17s  %-8.8s  %-13.13s  %5d  %s\n",
                   mac_str(e->src), dst_buf, mac_str(e->bssid),
                   type_str, rsn_buf, e->count, age_buf);
            tui_reset();
        } else {
            if (e->flood) tui_heat(1.0); else tui_normal();
            TPRINT(" %-17.17s", mac_str(e->src));

            /* broadcast dst in heat color */
            if (is_broadcast(e->dst)) tui_heat(0.8); else tui_dim();
            TPRINT("  %-17.17s", dst_buf);

            tui_dim();
            TPRINT("  %-17.17s", mac_str(e->bssid));

            if (e->subtype == 12) tui_bright(); else tui_normal();
            TPRINT("  %-8.8s", type_str);

            tui_dim();
            TPRINT("  %-13.13s", rsn_buf);

            if (e->flood) tui_heat(1.0); else tui_normal();
            TPRINT("  %5d", e->count);

            tui_dim();
            TPRINT("  %s", age_buf);
            if (e->flood) { tui_heat(1.0); TPRINT(" [FLOOD]"); }
            TPRINT("\n");
            tui_normal();
        }
    }
    tui_normal();
}

void view_deauth_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->deauth_sel > 0) s->deauth_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->deauth_count > 0 && s->deauth_sel < s->deauth_count - 1)
            s->deauth_sel++;
        break;
    case 'c': case 'C':
        deauth_clear();
        s->deauth_count       = 0;
        s->deauth_sel         = 0;
        s->deauth_flood_active = 0;
        break;
    default:
        break;
    }
}
