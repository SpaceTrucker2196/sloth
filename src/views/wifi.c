#include <stdio.h>
#include <string.h>
#include "ntop.h"
#include "tui.h"
#include "views/wifi.h"

#define WIFI_PAGE 20

/* -90 dBm (weak) → 0%, -30 dBm (strong) → 100% */
static void signal_bar(int dbm, char *out, int width) {
    double pct = (dbm < -90) ? 0.0 : (dbm > -30) ? 1.0 : (dbm + 90.0) / 60.0;
    int filled = (int)(pct * width);
    for (int i = 0; i < width; i++)
        out[i] = (i < filled) ? '#' : '.';
    out[width] = '\0';
}

/* ── Draw ───────────────────────────────────────────────── */

void view_wifi_draw(const ntop_state_t *s) {
#ifndef WITH_WIFI
    (void)s;
    TPRINT("  WiFi scanning disabled (build with WITH_WIFI=1)\n");
    return;
#else
#ifdef WITH_NCURSES
    int page = LINES - 5;
    if (page < 1) page = 1;
#else
    int page = WIFI_PAGE;
#endif

    /* status bar */
    TPRINT(" WiFi: %d AP%s", s->ap_count, s->ap_count == 1 ? "" : "s");
#ifndef WITH_NCURSES
    if (s->ap_count > 0)
        TPRINT("  [up/dn] navigate");
#endif
    TPRINT("\n");

    /* column headers */
    TPRINT(" %-32s  %-17s  %3s  %-14s  %s\n",
           "SSID", "BSSID", "Ch", "Signal", "Enc");
    TPRINT(" %-32s  %-17s  %3s  %-14s  %s\n",
           "--------------------------------", "-----------------",
           "---", "--------------", "---");

    if (s->ap_count == 0) {
        TPRINT("  (scanning... may require root or CAP_NET_ADMIN)\n");
        return;
    }

    /* viewport: keep wifi_sel roughly centred */
    int top = s->wifi_sel - page / 2;
    if (top + page > s->ap_count) top = s->ap_count - page;
    if (top < 0) top = 0;

    int end = top + page;
    if (end > s->ap_count) end = s->ap_count;

    char bar[12];
    for (int row = top; row < end; row++) {
        const wifi_ap_t *ap = &s->aps[row];
        signal_bar(ap->signal_dbm, bar, 10);

#ifdef WITH_NCURSES
        if (row == s->wifi_sel) attron(A_REVERSE);
        TPRINT(" %-32.32s  %-17s  %3d  [%-10s]%4d  %-4s\n",
               ap->ssid, ap->bssid, ap->channel,
               bar, ap->signal_dbm, ap->enc);
        if (row == s->wifi_sel) attroff(A_REVERSE);
#else
        TPRINT("%c%-32.32s  %-17s  %3d  [%-10s]%4d  %-4s\n",
               (row == s->wifi_sel) ? '>' : ' ',
               ap->ssid, ap->bssid, ap->channel,
               bar, ap->signal_dbm, ap->enc);
#endif
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
