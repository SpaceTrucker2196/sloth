#include "wifi_baseline.h"
#include <string.h>
#include <stdio.h>

/* Baseline snapshot — only the fields we diff on. */
typedef struct {
    uint8_t bssid[6];
    char    ssid[33];
    char    enc[10];
    int     channel;
    int     mfp;
} base_ap_t;

static base_ap_t g_base[MAX_BEACON_APS];
static int       g_base_n;
static int       g_base_ready;

void wifi_baseline_capture(const sloth_state_t *s) {
    g_base_n = 0;
    if (!s) return;
    for (int i = 0; i < s->beacon_count && g_base_n < MAX_BEACON_APS; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        base_ap_t *b = &g_base[g_base_n++];
        memcpy(b->bssid, a->bssid, 6);
        snprintf(b->ssid, sizeof(b->ssid), "%s", a->ssid);
        snprintf(b->enc,  sizeof(b->enc),  "%s", a->enc);
        b->channel = a->channel;
        b->mfp     = a->mfp;
    }
    g_base_ready = 1;
}

int wifi_baseline_ready(void) { return g_base_ready; }

void wifi_baseline_clear(void) { g_base_n = 0; g_base_ready = 0; }

static void bstr(const uint8_t *b, char *out, int sz) {
    snprintf(out, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             b[0], b[1], b[2], b[3], b[4], b[5]);
}

int wifi_baseline_drift(const sloth_state_t *s, drift_finding_t *out, int max) {
    if (!g_base_ready || !s || !out) return 0;
    int n = 0;
    char matched[MAX_BEACON_APS];
    memset(matched, 0, sizeof(matched));

    for (int i = 0; i < s->beacon_count && n < max; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        int j = -1;
        for (int k = 0; k < g_base_n; k++)
            if (memcmp(g_base[k].bssid, a->bssid, 6) == 0) { j = k; break; }

        char bss[20];
        bstr(a->bssid, bss, sizeof(bss));
        if (j < 0) {
            drift_finding_t *f = &out[n++];
            snprintf(f->kind, sizeof(f->kind), "NEW");
            snprintf(f->detail, sizeof(f->detail), "%s  %s  %s ch%d",
                     bss, a->ssid[0] ? a->ssid : "<hidden>", a->enc, a->channel);
            continue;
        }
        matched[j] = 1;
        if (strcmp(g_base[j].enc, a->enc) != 0 ||
            g_base[j].channel != a->channel ||
            g_base[j].mfp != a->mfp) {
            drift_finding_t *f = &out[n++];
            snprintf(f->kind, sizeof(f->kind), "CHG");
            snprintf(f->detail, sizeof(f->detail),
                     "%s  %s: %s ch%d mfp%d -> %s ch%d mfp%d",
                     bss, a->ssid[0] ? a->ssid : "<hidden>",
                     g_base[j].enc, g_base[j].channel, g_base[j].mfp,
                     a->enc, a->channel, a->mfp);
        }
    }
    for (int k = 0; k < g_base_n && n < max; k++) {
        if (matched[k]) continue;
        char bss[20];
        bstr(g_base[k].bssid, bss, sizeof(bss));
        drift_finding_t *f = &out[n++];
        snprintf(f->kind, sizeof(f->kind), "GONE");
        snprintf(f->detail, sizeof(f->detail), "%s  %s  %s ch%d",
                 bss, g_base[k].ssid[0] ? g_base[k].ssid : "<hidden>",
                 g_base[k].enc, g_base[k].channel);
    }
    return n;
}
