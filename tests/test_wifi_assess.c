#include "runner.h"
#include "sloth.h"
#include "wifi_assess.h"
#include <string.h>

static int has_title(const wifi_finding_t *f, int n, const char *t) {
    for (int i = 0; i < n; i++) if (strstr(f[i].title, t)) return 1;
    return 0;
}

static void set_ap(sloth_state_t *s, int i, const char *ssid, const char *enc,
                   const char *akm, int mfp, int has_wps) {
    beacon_ap_t *a = &s->beacon_aps[i];
    a->bssid[0] = (uint8_t)(0xa0 + i);
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    snprintf(a->enc,  sizeof(a->enc),  "%s", enc);
    snprintf(a->akm,  sizeof(a->akm),  "%s", akm);
    a->mfp     = mfp;
    a->has_wps = has_wps;
}

static void test_open_and_wep_flagged_high(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    set_ap(&s, 0, "FreeWiFi", "OPEN", "", 0, 0);
    set_ap(&s, 1, "OldAP",    "WEP",  "", 0, 0);
    s.beacon_count = 2;
    wifi_finding_t f[16];
    int n = wifi_assess(&s, f, 16);
    ASSERT(has_title(f, n, "Unencrypted"));
    ASSERT(has_title(f, n, "WEP"));
    for (int i = 0; i < n; i++) ASSERT_STR(f[i].severity, "HIGH");
}

static void test_mfp_off_and_transition(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    set_ap(&s, 0, "Corp",  "WPA2", "PSK", 0, 0);   /* MFP off */
    set_ap(&s, 1, "Corp3", "WPA3", "SAE", 1, 0);   /* transition (MFP optional) */
    s.beacon_count = 2;
    wifi_finding_t f[16];
    int n = wifi_assess(&s, f, 16);
    ASSERT(has_title(f, n, "Management frames unprotected"));
    ASSERT(has_title(f, n, "transition"));
}

static void test_wps_flagged_clean_mfp(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    set_ap(&s, 0, "Home", "WPA2", "PSK", 2, 1);    /* MFP required, WPS on */
    s.beacon_count = 1;
    wifi_finding_t f[16];
    int n = wifi_assess(&s, f, 16);
    ASSERT(has_title(f, n, "WPS enabled"));
    ASSERT(!has_title(f, n, "Management frames unprotected"));
}

static void test_clean_ap_no_findings(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    set_ap(&s, 0, "Secure", "WPA3", "SAE", 2, 0);  /* WPA3, MFP required, no WPS */
    s.beacon_count = 1;
    wifi_finding_t f[16];
    ASSERT_EQ(wifi_assess(&s, f, 16), 0);
}

void run_wifi_assess_tests(void) {
    TEST_SUITE("wifi assessment findings");
    RUN_TEST(test_open_and_wep_flagged_high);
    RUN_TEST(test_mfp_off_and_transition);
    RUN_TEST(test_wps_flagged_clean_mfp);
    RUN_TEST(test_clean_ap_no_findings);
}
