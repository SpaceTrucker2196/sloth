#include "runner.h"
#include "sloth.h"
#include "wifi_baseline.h"
#include <string.h>

static void set_ap(sloth_state_t *s, int i, uint8_t last, const char *ssid,
                   const char *enc, int ch, int mfp) {
    beacon_ap_t *a = &s->beacon_aps[i];
    a->bssid[0] = 0xaa; a->bssid[5] = last;
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    snprintf(a->enc,  sizeof(a->enc),  "%s", enc);
    a->channel = ch;
    a->mfp     = mfp;
}

static void test_no_drift_when_identical(void) {
    wifi_baseline_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    set_ap(&s, 0, 1, "Home",  "WPA2", 6,  2);
    set_ap(&s, 1, 2, "Guest", "WPA3", 36, 2);
    s.beacon_count = 2;
    wifi_baseline_capture(&s);
    ASSERT(wifi_baseline_ready());
    drift_finding_t d[16];
    ASSERT_EQ(wifi_baseline_drift(&s, d, 16), 0);
}

static void test_detects_new_gone_changed(void) {
    wifi_baseline_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    set_ap(&s, 0, 1, "Home",  "WPA2", 6,  2);
    set_ap(&s, 1, 2, "Guest", "WPA3", 36, 2);
    s.beacon_count = 2;
    wifi_baseline_capture(&s);

    snprintf(s.beacon_aps[0].enc, sizeof(s.beacon_aps[0].enc), "OPEN"); /* CHG */
    set_ap(&s, 1, 3, "New", "WPA2", 11, 2);   /* Guest(2) GONE, New(3) NEW */

    drift_finding_t d[16];
    int n = wifi_baseline_drift(&s, d, 16);
    ASSERT_EQ(n, 3);
    int chg = 0, gone = 0, nw = 0;
    for (int i = 0; i < n; i++) {
        if (!strcmp(d[i].kind, "CHG"))  chg  = 1;
        if (!strcmp(d[i].kind, "GONE")) gone = 1;
        if (!strcmp(d[i].kind, "NEW"))  nw   = 1;
    }
    ASSERT(chg && gone && nw);
}

static void test_no_baseline_no_drift(void) {
    wifi_baseline_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    set_ap(&s, 0, 1, "Home", "WPA2", 6, 2);
    s.beacon_count = 1;
    drift_finding_t d[16];
    ASSERT_EQ(wifi_baseline_ready(), 0);
    ASSERT_EQ(wifi_baseline_drift(&s, d, 16), 0);
}

void run_wifi_baseline_tests(void) {
    TEST_SUITE("wifi baseline drift");
    RUN_TEST(test_no_drift_when_identical);
    RUN_TEST(test_detects_new_gone_changed);
    RUN_TEST(test_no_baseline_no_drift);
}
