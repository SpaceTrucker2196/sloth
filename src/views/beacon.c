#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/beacon.h"
#include "beacon_snoop.h"

#define BEACON_PAGE 30

static char fmt_bssid[18];

static const char *bssid_str(const uint8_t *b) {
    snprintf(fmt_bssid, sizeof(fmt_bssid),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
    return fmt_bssid;
}

void view_beacon_draw(const sloth_state_t *s) {
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = BEACON_PAGE;
#endif

    tui_normal(); TPRINT(" Passive beacons: ");
    tui_bright();  TPRINT("%d", s->beacon_count);
    tui_dim();     TPRINT("  [up/dn] navigate  [c] clear");
    if (s->probe_iface[0])
        TPRINT("  iface: %s", s->probe_iface);
    TPRINT("\n");

    tui_dim();
    TPRINT(" %-32s  %-17s  %4s  %3s  %-6s  %5s  %s\n",
           "SSID", "BSSID", "Sig", "Ch", "Enc", "Intv", "Last");
    TPRINT(" %-32s  %-17s  %4s  %3s  %-6s  %5s  %s\n",
           "--------------------------------", "-----------------",
           "----", "---", "------", "-----", "----");
    tui_normal();

    if (s->beacon_count == 0) {
        tui_dim();
        TPRINT("  (no beacons seen -- waiting for 802.11 beacon frames on monitor iface)\n");
        tui_normal();
        return;
    }

    int page_top = s->beacon_sel - page / 2;
    if (page_top + page > s->beacon_count) page_top = s->beacon_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->beacon_count) page_end = s->beacon_count;

    time_t now = time(NULL);
    for (int row = page_top; row < page_end; row++) {
        const beacon_ap_t *ap = &s->beacon_aps[row];

        const char *ssid = ap->ssid[0] ? ap->ssid : "(hidden)";

        char sig_buf[8];
        snprintf(sig_buf, sizeof(sig_buf), "%d", ap->signal_dbm);

        char intv_buf[8];
        snprintf(intv_buf, sizeof(intv_buf), "%ums", ap->beacon_ms);

        int age = (int)(now - ap->last_seen);
        char age_buf[16];
        if      (age < 60)   snprintf(age_buf, sizeof(age_buf), "%ds",  age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%dm",  age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%dh",  age / 3600);

        if (row == s->beacon_sel) {
            tui_sel();
            TPRINT(" %-32.32s  %-17.17s  %4s  %3d  %-6.6s  %5s  %s\n",
                   ssid, bssid_str(ap->bssid), sig_buf, ap->channel,
                   ap->enc, intv_buf, age_buf);
            tui_reset();
        } else {
            /* dim hidden SSIDs */
            if (!ap->ssid[0]) tui_dim(); else tui_normal();
            TPRINT(" %-32.32s", ssid);

            tui_dim();
            TPRINT("  %-17.17s", bssid_str(ap->bssid));

            /* signal heat */
            double frac = (ap->signal_dbm + 90.0) / 60.0;  /* -90=0.0, -30=1.0 */
            tui_heat(frac);
            TPRINT("  %4s", sig_buf);

            tui_normal();
            TPRINT("  %3d", ap->channel);

            /* enc color: OPEN/WEP dim, WPA/WPA2/WPA3 normal/bright */
            if (strcmp(ap->enc, "OPEN") == 0 || strcmp(ap->enc, "WEP") == 0)
                tui_dim();
            else if (strcmp(ap->enc, "WPA3") == 0)
                tui_bright();
            else
                tui_normal();
            TPRINT("  %-6.6s", ap->enc);

            tui_dim();
            TPRINT("  %5s  %s\n", intv_buf, age_buf);
            tui_normal();
        }
    }
    tui_normal();
}

void view_beacon_key(sloth_state_t *s, int key) {
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->beacon_sel > 0) s->beacon_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->beacon_count > 0 && s->beacon_sel < s->beacon_count - 1)
            s->beacon_sel++;
        break;
    case 'c': case 'C':
        beacon_clear();
        s->beacon_count = 0;
        s->beacon_sel   = 0;
        break;
    default:
        break;
    }
}
