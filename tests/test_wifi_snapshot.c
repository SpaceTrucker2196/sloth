#include "runner.h"
#include "sloth.h"
#include "wifi_snapshot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char tmp[] = "/tmp/sloth_snap_XXXXXX";

static void mktmp(void) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); }

static void seed_ap(sloth_state_t *s, int i, const uint8_t *bssid,
                    const char *ssid, const char *enc, int ch, int mfp) {
    beacon_ap_t *a = &s->beacon_aps[i];
    memcpy(a->bssid, bssid, 6);
    snprintf(a->ssid, sizeof(a->ssid), "%s", ssid);
    snprintf(a->enc,  sizeof(a->enc),  "%s", enc);
    a->channel = ch;
    a->mfp     = mfp;
}

/* Writing then diffing the same state must report zero drift. */
static void test_roundtrip_no_diff(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b0[6] = { 0xaa, 0, 0, 0, 0, 1 }, b1[6] = { 0xaa, 0, 0, 0, 0, 2 };
    seed_ap(&s, 0, b0, "Home",  "WPA2", 6,  2);
    seed_ap(&s, 1, b1, "Guest", "WPA3", 36, 2);
    s.beacon_count = 2;
    mktmp();
    ASSERT_EQ(wifi_snapshot_write(&s, tmp, "site-a", 1000), 0);
    FILE *nul = fopen("/dev/null", "w");
    ASSERT_EQ(wifi_snapshot_diff(&s, tmp, nul), 0);
    fclose(nul);
}

/* A changed cipher, a disappeared AP, and a new AP = three differences. */
static void test_diff_detects_changes(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    uint8_t b0[6] = { 0xaa, 0, 0, 0, 0, 1 }, b1[6] = { 0xaa, 0, 0, 0, 0, 2 };
    seed_ap(&s, 0, b0, "Home",  "WPA2", 6,  2);
    seed_ap(&s, 1, b1, "Guest", "WPA3", 36, 2);
    s.beacon_count = 2;
    mktmp();
    wifi_snapshot_write(&s, tmp, NULL, 1000);

    uint8_t b2[6] = { 0xaa, 0, 0, 0, 0, 3 };
    snprintf(s.beacon_aps[0].enc, sizeof(s.beacon_aps[0].enc), "OPEN"); /* CHANGED */
    seed_ap(&s, 1, b2, "New", "WPA2", 11, 2);   /* b1 GONE + b2 NEW */

    FILE *nul = fopen("/dev/null", "w");
    int d = wifi_snapshot_diff(&s, tmp, nul);
    fclose(nul);
    ASSERT_EQ(d, 3);
}

static void test_missing_baseline(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    FILE *nul = fopen("/dev/null", "w");
    ASSERT_EQ(wifi_snapshot_diff(&s, "/no/such/baseline/file", nul), -1);
    fclose(nul);
}

void run_wifi_snapshot_tests(void) {
    TEST_SUITE("wifi site snapshot");
    RUN_TEST(test_roundtrip_no_diff);
    RUN_TEST(test_diff_detects_changes);
    RUN_TEST(test_missing_baseline);
}
