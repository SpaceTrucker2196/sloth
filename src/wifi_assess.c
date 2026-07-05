#include "wifi_assess.h"
#include <string.h>
#include <stdio.h>

static void add(wifi_finding_t *out, int *n, int max, const char *sev,
                const char *title, const char *ssid, const char *bss,
                const char *note) {
    if (*n >= max) return;
    wifi_finding_t *f = &out[(*n)++];
    snprintf(f->severity, sizeof(f->severity), "%s", sev);
    snprintf(f->title,    sizeof(f->title),    "%s", title);
    snprintf(f->evidence, sizeof(f->evidence), "SSID %s / %s : %s",
             ssid[0] ? ssid : "<hidden>", bss, note);
}

int wifi_assess(const sloth_state_t *s, wifi_finding_t *out, int max) {
    if (!s || !out || max <= 0) return 0;
    int n = 0;

    for (int i = 0; i < s->beacon_count && n < max; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        char bss[20];
        snprintf(bss, sizeof(bss), "%02x:%02x:%02x:%02x:%02x:%02x",
                 a->bssid[0], a->bssid[1], a->bssid[2],
                 a->bssid[3], a->bssid[4], a->bssid[5]);
        const char *ssid = a->ssid;

        /* Encryption posture — one finding per AP, worst first. */
        if (strcmp(a->enc, "OPEN") == 0)
            add(out, &n, max, "HIGH", "Unencrypted network", ssid, bss,
                "OPEN — traffic and credentials in the clear");
        else if (strcmp(a->enc, "WEP") == 0)
            add(out, &n, max, "HIGH", "Deprecated WEP encryption", ssid, bss,
                "WEP — trivially crackable");
        else if (strcmp(a->enc, "WPA") == 0 || strcmp(a->pairwise, "TKIP") == 0)
            add(out, &n, max, "MED", "Legacy WPA / TKIP cipher", ssid, bss,
                "WPA1/TKIP — deprecated, KRACK-adjacent");

        /* Management-frame protection. RSN present but MFP not required. */
        if (strcmp(a->enc, "WPA2") == 0 || strcmp(a->enc, "WPA3") == 0) {
            if (a->mfp == 0)
                add(out, &n, max, "MED", "Management frames unprotected", ssid,
                    bss, "RSN MFP off — deauth/disassoc spoofing possible");
            else if (a->mfp == 1 && strstr(a->akm, "SAE"))
                add(out, &n, max, "LOW", "WPA3 transition mode", ssid, bss,
                    "SAE present but MFP optional, not required");
        }

        /* WPS attack surface. */
        if (a->has_wps)
            add(out, &n, max, "MED", "WPS enabled", ssid, bss,
                a->wps_locked == 2 ? "WPS present (locked)"
                                   : "WPS PIN brute-force surface");
    }
    return n;
}
