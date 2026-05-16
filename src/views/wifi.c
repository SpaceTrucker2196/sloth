#include <stdio.h>
#include <string.h>
#include "ntop.h"
#include "tui.h"
#include "oui.h"
#include "views/wifi.h"

#define WIFI_PAGE 20

/* Phosphor intensity based on signal strength. */
static void phos_signal(int dbm) {
    if      (dbm > -50) tui_bright();
    else if (dbm > -70) tui_normal();
    else                tui_dim();
}

/* Print a signal bar with left→right phosphor gradient.
   Filled portion grades dim→normal→bright; empty dots are dim. */
static void print_signal_bar_phosphor(int dbm, int width) {
    double pct    = (dbm < -90) ? 0.0 : (dbm > -30) ? 1.0 : (dbm + 90.0) / 60.0;
    int    filled = (int)(pct * width);
    for (int i = 0; i < width; i++) {
        if (i < filled) {
            double pos = (double)i / width;
            if      (pos < 0.33) tui_dim();
            else if (pos < 0.66) tui_normal();
            else                 tui_bright();
            TPRINT("#");
        } else {
            tui_dim(); TPRINT(".");
        }
    }
}

/* ── Draw ───────────────────────────────────────────────── */

void view_wifi_draw(const ntop_state_t *s) {
#ifndef WITH_WIFI
    (void)s;
    tui_dim(); TPRINT("  WiFi scanning disabled (build with WITH_WIFI=1)\n");
    tui_normal();
    return;
#else
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = WIFI_PAGE;
#endif

    /* status bar */
    tui_normal(); TPRINT(" WiFi: ");
    tui_bright();  TPRINT("%d AP%s", s->ap_count, s->ap_count == 1 ? "" : "s");
#ifndef WITH_NCURSES
    if (s->ap_count > 0) { tui_dim(); TPRINT("  [up/dn] navigate"); }
#endif
    TPRINT("\n");

    /* column headers */
    tui_dim();
    TPRINT(" %-32s  %-17s  %-12s  %3s  %-14s  %s\n",
           "SSID", "BSSID", "Vendor", "Ch", "Signal", "Enc");
    TPRINT(" %-32s  %-17s  %-12s  %3s  %-14s  %s\n",
           "--------------------------------", "-----------------",
           "------------", "---", "--------------", "---");
    tui_normal();

    if (s->ap_count == 0) {
        tui_dim(); TPRINT("  (scanning... may require root or CAP_NET_ADMIN)\n");
        tui_normal(); return;
    }

    int top = s->wifi_sel - page / 2;
    if (top + page > s->ap_count) top = s->ap_count - page;
    if (top < 0) top = 0;
    int end = top + page;
    if (end > s->ap_count) end = s->ap_count;

    for (int row = top; row < end; row++) {
        const wifi_ap_t *ap = &s->aps[row];

        const char *vendor = oui_lookup_str(ap->bssid);
        const char *vstr   = vendor ? vendor : "";

        if (row == s->wifi_sel) {
            /* selected: uniform bright reverse */
            char bar[12];
            double pct    = (ap->signal_dbm < -90) ? 0.0
                          : (ap->signal_dbm > -30) ? 1.0
                          : (ap->signal_dbm + 90.0) / 60.0;
            int    filled = (int)(pct * 10);
            for (int i = 0; i < 10; i++) bar[i] = (i < filled) ? '#' : '.';
            bar[10] = '\0';
            tui_sel();
            TPRINT(" %-32.32s  %-17s  %-12.12s  %3d  [%-10s]%4d  %-4s\n",
                   ap->ssid, ap->bssid, vstr, ap->channel,
                   bar, ap->signal_dbm, ap->enc);
            tui_reset();
        } else {
            /* SSID: bright — the primary field */
            tui_bright(); TPRINT(" %-32.32s", ap->ssid);
            /* BSSID: dim — secondary identifier */
            tui_dim();    TPRINT("  %-17s", ap->bssid);
            /* Vendor: dim */
            tui_dim();    TPRINT("  %-12.12s", vstr);
            /* Channel: normal */
            tui_normal(); TPRINT("  %3d  [", ap->channel);
            /* Signal bar: gradient */
            print_signal_bar_phosphor(ap->signal_dbm, 10);
            /* dBm value: intensity matches signal strength */
            phos_signal(ap->signal_dbm);
            TPRINT("]%4d", ap->signal_dbm);
            /* Encryption */
            if (strncmp(ap->enc, "Open", 4) == 0) tui_dim();
            else tui_bright();
            TPRINT("  %-4s\n", ap->enc);
            tui_normal();
        }
    }
#endif /* WITH_WIFI */
}

/* ── Key handler ────────────────────────────────────────── */

void view_wifi_key(ntop_state_t *s, int key) {
    switch (key) {
    case NTOP_KEY_UP:
        if (s->wifi_sel > 0) s->wifi_sel--;
        break;
    case NTOP_KEY_DOWN:
        if (s->ap_count > 0 && s->wifi_sel < s->ap_count - 1)
            s->wifi_sel++;
        break;
    default:
        break;
    }
}
