#include <stdio.h>
#include "ntop.h"
#include "tui.h"
#include "views/wifi.h"

static void signal_bar(int dbm, char *out, int width) {
    /* typical range: -90 dBm (weak) to -30 dBm (strong) */
    double pct = (dbm < -90) ? 0.0 : (dbm > -30) ? 1.0 : (dbm + 90.0) / 60.0;
    int filled = (int)(pct * width);
    for (int i = 0; i < width; i++)
        out[i] = (i < filled) ? '#' : '.';
    out[width] = '\0';
}

void view_wifi_draw(const ntop_state_t *s) {
#ifndef WITH_WIFI
    (void)s;
    TPRINT("  WiFi scanning disabled (build with WITH_WIFI=1)\n");
    return;
#else
    char bar[12];

    TPRINT("  %-32s  %-17s  %-4s  %-14s  %s\n",
           "SSID", "BSSID", "Ch", "Signal", "Enc");
    TPRINT("  %-32s  %-17s  %-4s  %-14s  %s\n",
           "--------------------------------", "-----------------",
           "----", "--------------", "---");

    for (int i = 0; i < s->ap_count; i++) {
        const wifi_ap_t *ap = &s->aps[i];
        signal_bar(ap->signal_dbm, bar, 10);
        TPRINT("  %-32s  %-17s  %-4d  [%-10s]%4ddBm  %s\n",
               ap->ssid, ap->bssid, ap->channel,
               bar, ap->signal_dbm, ap->enc);
    }

    if (s->ap_count == 0)
        TPRINT("  (scanning... may require root or CAP_NET_RAW)\n");
#endif /* WITH_WIFI */
}
