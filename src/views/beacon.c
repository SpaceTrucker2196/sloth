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
    TPRINT(" %-24s  %-17s  %4s  %3s  %-5s  %-9s  %-3s  %-10s  %-3s  %-10s  %4s\n",
           "SSID", "BSSID", "Sig", "Ch", "Enc",
           "Pairwise", "MFP", "AKM", "WPS", "Vendor", "Last");
    TPRINT(" %-24s  %-17s  %4s  %3s  %-5s  %-9s  %-3s  %-10s  %-3s  %-10s  %4s\n",
           "------------------------", "-----------------",
           "----", "---", "-----", "---------", "---",
           "----------", "---", "----------", "----");
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

        char ssid_display[40];
        if (ap->ssid[0]) {
            if (ap->revealed)
                snprintf(ssid_display, sizeof(ssid_display), "%s *", ap->ssid);
            else
                snprintf(ssid_display, sizeof(ssid_display), "%s", ap->ssid);
        } else {
            snprintf(ssid_display, sizeof(ssid_display), "(hidden)");
        }
        const char *ssid = ssid_display;

        char sig_buf[8];
        snprintf(sig_buf, sizeof(sig_buf), "%d", ap->signal_dbm);

        int age = (int)(now - ap->last_seen);
        char age_buf[16];
        if      (age < 60)   snprintf(age_buf, sizeof(age_buf), "%ds",  age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%dm",  age / 60);
        else                 snprintf(age_buf, sizeof(age_buf), "%dh",  age / 3600);

        const char *mfp_s = (ap->mfp == 2) ? "REQ"
                          : (ap->mfp == 1) ? "cap" : "-";
        const char *pw    = ap->pairwise[0] ? ap->pairwise : "-";
        const char *akm   = ap->akm[0]      ? ap->akm      : "-";
        const char *wps_s = ap->has_wps ? "ON" : "-";
        const char *vend  = ap->vendor[0] ? ap->vendor : "-";

        if (row == s->beacon_sel) {
            tui_sel();
            TPRINT(" %-24.24s  %-17.17s  %4s  %3d  %-5.5s  %-9.9s  %-3s  %-10.10s  %-3s  %-10.10s  %s\n",
                   ssid, bssid_str(ap->bssid), sig_buf, ap->channel,
                   ap->enc, pw, mfp_s, akm, wps_s, vend, age_buf);
            tui_reset();
        } else {
            /* dim hidden SSIDs */
            if (!ap->ssid[0]) tui_dim(); else tui_normal();
            TPRINT(" %-24.24s", ssid);

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
            TPRINT("  %-5.5s", ap->enc);

            /* pairwise cipher — TKIP is a smell on a WPA2 net */
            if (strcmp(pw, "TKIP") == 0) tui_heat(0.7);
            else                          tui_normal();
            TPRINT("  %-9.9s", pw);

            /* MFP — REQ bright, cap normal, off (-) dim */
            if (ap->mfp == 2)       tui_bright();
            else if (ap->mfp == 1)  tui_normal();
            else                    tui_dim();
            TPRINT("  %-3s", mfp_s);

            tui_normal();
            TPRINT("  %-10.10s", akm);

            /* WPS — on = heat-coloured smell (PixieDust / PIN-attack
             * vector). off = dim. */
            if (ap->has_wps) tui_heat(0.7);
            else             tui_dim();
            TPRINT("  %-3s", wps_s);

            /* Vendor — bright for known, dim "-" for unknown. */
            if (ap->vendor[0]) tui_bright();
            else                tui_dim();
            TPRINT("  %-10.10s", vend);

            tui_dim();
            TPRINT("  %s\n", age_buf);
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
