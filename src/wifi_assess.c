#include "wifi_assess.h"
#include "beacon_snoop.h"
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

uint8_t wifi_downgrade_flags(const beacon_ap_t *a) {
    if (!a) return 0;
    uint8_t f = 0;

    /* 1. Transition mode — PSK and SAE both on offer. The exact test is
     * only possible against the bitmaps: "SAE" substring-matches inside
     * "FT-SAE", and the display string caps at three AKMs, which is
     * where a crowded transition config hides (#60 slice 1). */
    if ((a->akm_bits & RSN_AKM_PSK_FAMILY) &&
        (a->akm_bits & RSN_AKM_SAE_FAMILY))
        f |= WPA_DG_TRANSITION_SAE_PSK;

    /* 3. MFP capable but not required on a BSS offering SAE. WPA3
     * mandates MFP; optional-not-required is the Dragonblood downgrade
     * primitive, because a client that would have insisted is allowed
     * not to. mfp==0 is not this finding — that is an AP with no MFP at
     * all, which wifi_assess already reports as its own MED. */
    if ((a->akm_bits & RSN_AKM_SAE_FAMILY) && a->mfp == 1)
        f |= WPA_DG_MFP_OPTIONAL;

    /* 4. Legacy WPA1 IE alongside RSN: TKIP still on offer, deprecated
     * since 2019. WPA1 *without* RSN is a different and older finding
     * that wifi_assess already reports, so the RSN half is required —
     * akm_bits is non-zero exactly when an RSN IE was parsed. */
    if (a->has_wpa1 && a->akm_bits)
        f |= WPA_DG_WPA1_ALONGSIDE;

    return f;
}

const char *wifi_downgrade_label(uint8_t kind) {
    switch (kind) {
    case WPA_DG_TRANSITION_SAE_PSK: return "WPA2+WPA3 transition";
    case WPA_DG_OWE_TRANSITION:     return "OWE transition";
    case WPA_DG_MFP_OPTIONAL:       return "MFP optional";
    case WPA_DG_WPA1_ALONGSIDE:     return "WPA1 alongside RSN";
    default:                        return "";
    }
}

void wifi_downgrade_update(sloth_state_t *s) {
    if (!s) return;
    for (int i = 0; i < s->beacon_count; i++) {
        beacon_ap_t *a = &s->beacon_aps[i];
        uint8_t f = wifi_downgrade_flags(a);

        /* OWE transition needs the pair: the element names an open
         * companion BSS, and without one there is nothing to downgrade
         * to. Matched by SSID rather than by the BSSID in the element,
         * because we may not have heard that BSSID yet and a same-SSID
         * open BSS beside an OWE one is the observable either way. */
        if (a->owe_trans) {
            for (int j = 0; j < s->beacon_count; j++) {
                if (j == i) continue;
                const beacon_ap_t *o = &s->beacon_aps[j];
                if (strcmp(o->enc, "OPEN") != 0) continue;
                if (o->ssid[0] && a->ssid[0] &&
                    strcmp(o->ssid, a->ssid) != 0) continue;
                f |= WPA_DG_OWE_TRANSITION;
                break;
            }
        }
        a->downgrade_flags = f;
    }
}

/* Worst-first: an AP still offering TKIP is a bigger problem than one
 * whose MFP is merely optional, and a column has room for one. */
const char *wifi_downgrade_column(uint8_t flags) {
    if (flags & WPA_DG_WPA1_ALONGSIDE)     return "WPA1+RSN";
    if (flags & WPA_DG_TRANSITION_SAE_PSK) return "WPA2+3";
    if (flags & WPA_DG_OWE_TRANSITION)     return "OWE-tr";
    if (flags & WPA_DG_MFP_OPTIONAL)       return "MFP-opt";
    return NULL;
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
