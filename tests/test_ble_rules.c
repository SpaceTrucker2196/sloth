#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "ble_hci.h"
#include "ble_snoop.h"
#include "ble_flood.h"
#include "ble_detect.h"
#include "ble_watchlist.h"
#include "jsonl.h"
#include "sensor_health.h"
#include "sensors.h"
#include "sloth_clock.h"
#include "tui.h"
#include "tune.h"
#include "views/ble.h"

/*
 * The BLE detector lanes, the [*] BLE view and the ble_device /
 * ble_alert records — #144 slice 4.
 *
 * Every advertisement is built by hand from the AD-structure layout of
 * Core Specification Supplement Part A (length, type, value; Vol 3
 * Part C §11), never captured (agents/AGENTS.md, "No pcap fixtures"):
 *
 *   0x01 Flags                      §1.3
 *   0x02/0x03 16-bit Service UUIDs  §1.1   (list, LSO first)
 *   0x16 Service Data - 16-bit UUID §1.11  (UUID LSO first, then data)
 *   0x19 Appearance                 §1.12  (Assigned Numbers category 0x00F = HID)
 *   0xFF Manufacturer Specific Data §1.4   (company ID LSO first, then data)
 *
 * Payload keys are the ones the BLE Spam tool's source writes
 * (research/bluetooth/ble-spam-flood.md): Microsoft 0x0006 beacon 0x03
 * (Swift Pair), Apple 0x004C Continuity 0x07, Google Fast Pair Service
 * Data 0xFE2C. The watchlist rows are an in-test table — test fixtures,
 * not the shipped (empty) table and not a claim the shapes are verified.
 *
 * Both clocks are pinned: flood windows run on the monotonic clock, the
 * rules and the device rows on the wall/frame clock.
 */

TEST_STATE(g_s);

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }

static void pin_clocks(void) {
    g_mono = 1000000;
    g_wall = 1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
}

/* One advertising report as the HCI decoder would hand it on: header
 * fields from the arguments, AD fields from ble_ad_parse() over `ad`.
 * `addr` is display order; the report carries LSO first. */
static void make_report(ble_adv_report_t *r, uint8_t evt, uint8_t atype,
                        const uint8_t addr[6], const uint8_t *ad,
                        size_t len, int rssi) {
    memset(r, 0, sizeof(*r));
    r->event_type = evt;
    r->addr_type  = atype;
    for (int i = 0; i < 6; i++) r->addr[i] = addr[5 - i];
    if (rssi != 127) { r->has_rssi = true; r->rssi = (int8_t)rssi; }
    ble_ad_parse(ad, len, r);
}

static void observe(const ble_adv_report_t *r, time_t ts) {
    ble_obs_t o = { r, SENSOR_BLE, BT_MONITOR_DEVICE, 0, -1, 0, ts };
    ble_dev_observe(&o);
}

/* A random-looking address: 0xC0 in the top bits marks a static random
 * address (Vol 6 Part B §1.3.2.1); the low octets are the index. */
static void addr_n(uint8_t a[6], unsigned n) {
    a[0] = 0xC2; a[1] = 0x00; a[2] = 0x00;
    a[3] = (uint8_t)(n >> 16); a[4] = (uint8_t)(n >> 8); a[5] = (uint8_t)n;
}

/* Swift Pair, as swiftpair.c writes it: 0xFF, 06 00, beacon 03,
 * sub-scenario 00, reserved RSSI 80, then a name. */
static const uint8_t AD_SWIFT[] = { 0x08, 0xFF, 0x06, 0x00, 0x03, 0x00, 0x80, 'k', 'b' };

/* Apple Continuity with a chosen message type. */
static size_t ad_apple(uint8_t *b, uint8_t type) {
    b[0] = 0x05; b[1] = 0xFF; b[2] = 0x4C; b[3] = 0x00; b[4] = type; b[5] = 0x00;
    return 6;
}

/* Fast Pair, as fastpair.c writes it: UUID list 0xFE2C, then Service
 * Data 0xFE2C with a 24-bit model. */
static const uint8_t AD_FASTPAIR[] = {
    0x03, 0x03, 0x2C, 0xFE,
    0x06, 0x16, 0x2C, 0xFE, 0x12, 0x34, 0x56,
};

static int count_type(const sloth_state_t *s, alert_type_t t) {
    int n = 0;
    for (int i = 0; i < s->alert_count; i++) if (s->alerts[i].type == t) n++;
    return n;
}

static int find_type(const sloth_state_t *s, alert_type_t t) {
    for (int i = 0; i < s->alert_count; i++) if (s->alerts[i].type == t) return i;
    return -1;
}

static void evaluate(void) {
    ble_snapshot(&g_s);
    alerts_update(&g_s);
}

/* ── AD decoding added by this slice ─────────────────────────────── */

static void test_service_data16_is_decoded(void) {
    ble_adv_report_t r;
    const uint8_t a[6] = { 0xC0, 1, 2, 3, 4, 5 };
    make_report(&r, 0x00, 1, a, AD_FASTPAIR, sizeof(AD_FASTPAIR), -60);
    ASSERT(r.has_svc_data16);
    ASSERT_EQ(r.svc_data_uuid16, 0xFE2C);
    ASSERT_EQ(r.svc_data_len, 3);
    ASSERT_EQ(r.svc_data[0], 0x12);
    ASSERT_EQ(r.svc_data[2], 0x56);
    ASSERT(!r.truncated);
}

static void test_service_data_shorter_than_its_uuid_is_ignored(void) {
    /* Length 2 = type + one octet: half a UUID. Seen to fail: with the
     * val_len >= 2 guard removed, has_svc_data16 is set from one octet
     * and the next byte of the buffer. */
    const uint8_t ad[] = { 0x02, 0x16, 0x2C, 0x02, 0x01, 0x06 };
    ble_adv_report_t r;
    const uint8_t a[6] = { 0xC0, 1, 2, 3, 4, 5 };
    make_report(&r, 0x00, 1, a, ad, sizeof(ad), -60);
    ASSERT(!r.has_svc_data16);
    ASSERT(r.has_flags);              /* the walk went on past it */
}

static void test_every_listed_uuid16_is_kept(void) {
    /* Battery first, HID second: the HID rule must not need 0x1812 to
     * be the first UUID a device lists. A trailing odd octet is not
     * half a UUID. */
    const uint8_t ad[] = { 0x06, 0x03, 0x0F, 0x18, 0x12, 0x18, 0xAA };
    ble_adv_report_t r;
    const uint8_t a[6] = { 0xC0, 1, 2, 3, 4, 5 };
    make_report(&r, 0x00, 1, a, ad, sizeof(ad), -60);
    ASSERT(r.has_service_uuid16);
    ASSERT_EQ(r.service_uuid16, 0x180F);
    ASSERT_EQ(r.uuid16_count, 2);
    ASSERT_EQ(r.uuid16_list[1], 0x1812);
}

static void test_hid_appearance_range(void) {
    ASSERT(ble_appearance_is_hid(0x03C0));
    ASSERT(ble_appearance_is_hid(0x03C1));    /* keyboard */
    ASSERT(ble_appearance_is_hid(0x03CA));    /* presentation remote */
    ASSERT(!ble_appearance_is_hid(0x03CB));
    ASSERT(!ble_appearance_is_hid(0x03BF));
    ASSERT(!ble_appearance_is_hid(0x0040));   /* generic phone */
}

/* ── BLE_ADV_FLOOD ────────────────────────────────────────────────── */

/* One advertisement on the key from a resident address, then the clock
 * moved to the next window boundary: the window after has a baseline
 * (gate 1 judges freshness only against a window that held something),
 * as it would have on a key genuine devices already use. */
static void prime_key(const uint8_t *ad, size_t len, uint8_t evt) {
    const uint8_t home[6] = { 0xC2, 0xFF, 0xFF, 0x00, 0x00, 0x01 };
    ble_adv_report_t r;
    make_report(&r, evt, 1, home, ad, len, -70);
    observe(&r, g_wall);
}

/* 1000 advertisements from 500 addresses over 2 s, every 2 ms. */
static void flood_now(const uint8_t *ad, size_t len, uint8_t evt,
                      unsigned addr_base) {
    for (unsigned i = 0; i < 1000; i++) {
        uint8_t a[6];
        addr_n(a, addr_base + (i % 500));
        ble_adv_report_t r;
        make_report(&r, evt, 1, a, ad, len, -40 - (int)(i % 20));
        observe(&r, g_wall);
        g_mono += 2;
    }
}

/* The key primed, one window boundary crossed, then the flood: the
 * flood sits at the start of the key's second window. */
static void play_flood(const uint8_t *ad, size_t len, uint8_t evt,
                       unsigned addr_base) {
    prime_key(ad, len, evt);
    g_mono += BLE_FLOOD_WINDOW_S * 1000;
    flood_now(ad, len, evt, addr_base);
}

static void test_swift_pair_flood_fires_once_per_key(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    play_flood(AD_SWIFT, sizeof(AD_SWIFT), 0x03, 0);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 1);
    int i = find_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT_STR(g_s.alerts[i].key, "bleflood:bluetooth-monitor:3:mfr:6:3");
        ASSERT(strstr(g_s.alerts[i].detail, " new of >=128 addresses") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "1000 adv in 10s") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "(100.0/s)") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "ADV_NONCONN_IND") != NULL);
    }
    /* 500 fresh addresses; the Bloom sets may lose a few, never add. */
    ble_finding_t f[BLE_FINDINGS_MAX];
    int nf = ble_findings_build(&g_s, g_wall, f, BLE_FINDINGS_MAX, NULL);
    ASSERT_EQ(nf, 1);
    if (nf == 1) { ASSERT(f[0].fresh > 450); ASSERT(f[0].fresh <= 500); }
    /* Evaluated again: the same incident, not a second one. */
    g_mono += 100;
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 1);
    ASSERT_STR(alert_technique(ALERT_TYPE_BLE_ADV_FLOOD), "T1499");
    sloth_clock_test_set(NULL, NULL);
}

static void test_two_spam_keys_are_two_incidents(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    uint8_t ad[8];
    size_t n = ad_apple(ad, 0x07);         /* Proximity Pair */
    prime_key(AD_SWIFT, sizeof(AD_SWIFT), 0x03);
    prime_key(ad, n, 0x03);
    prime_key(AD_FASTPAIR, sizeof(AD_FASTPAIR), 0x00);
    g_mono += BLE_FLOOD_WINDOW_S * 1000;
    flood_now(AD_SWIFT, sizeof(AD_SWIFT), 0x03, 0);
    flood_now(ad, n, 0x03, 10000);
    flood_now(AD_FASTPAIR, sizeof(AD_FASTPAIR), 0x00, 20000);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 3);
    int fp = 0;
    for (int i = 0; i < g_s.alert_count; i++)
        if (strcmp(g_s.alerts[i].key,
                   "bleflood:bluetooth-monitor:0:svc_data:65068:none") == 0) fp = 1;
    ASSERT(fp);
    sloth_clock_test_set(NULL, NULL);
}

/* Gate 3. Seen to fail: with `if (!r->spam_known) continue;` removed
 * from flood_findings(), this fires on Apple 0x10 (Nearby Info). */
static void test_same_volume_on_an_unlisted_subtype_does_not_fire(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    uint8_t ad[8];
    size_t n = ad_apple(ad, 0x10);
    play_flood(ad, n, 0x03, 0);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 0);
    ASSERT(g_s.ble_flood_count >= 1);       /* counted, just not listed */
    sloth_clock_test_set(NULL, NULL);
}

/* The issue's negative: the same 1000 / 500 spread over every subtype,
 * so even the listed ones (0x07, 0x0F) get four advertisements from four
 * addresses each. Seen to fail: with win_passes() returning 1 (both
 * numeric gates gone), the listed subtypes' buckets fire. Either gate
 * alone keeps this quiet; the next two tests isolate each. */
static void test_spread_across_subtypes_does_not_fire(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    uint8_t pad[8];
    size_t pn = ad_apple(pad, 0x07);
    prime_key(pad, pn, 0x03);
    pn = ad_apple(pad, 0x0F);
    prime_key(pad, pn, 0x03);
    g_mono += BLE_FLOOD_WINDOW_S * 1000;
    for (unsigned i = 0; i < 1000; i++) {
        uint8_t a[6], ad[8];
        addr_n(a, i % 500);
        size_t n = ad_apple(ad, (uint8_t)(i % 256));
        ble_adv_report_t r;
        make_report(&r, 0x03, 1, a, ad, n, -50);
        observe(&r, g_wall);
        g_mono += 2;
    }
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 0);
    sloth_clock_test_set(NULL, NULL);
}

/* Gate 1. Five addresses at 50 adv/s, in a window with a baseline.
 * Seen to fail: with the fresh-address comparison removed from
 * win_passes(), it fires. */
static void test_few_addresses_at_high_rate_does_not_fire(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    prime_key(AD_SWIFT, sizeof(AD_SWIFT), 0x03);
    g_mono += BLE_FLOOD_WINDOW_S * 1000;
    for (unsigned i = 0; i < 500; i++) {
        uint8_t a[6];
        addr_n(a, i % 5);
        ble_adv_report_t r;
        make_report(&r, 0x03, 1, a, AD_SWIFT, sizeof(AD_SWIFT), -50);
        observe(&r, g_wall);
        g_mono += 20;
    }
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 0);
    sloth_clock_test_set(NULL, NULL);
}

/* Gate 2. Thirty fresh addresses, one advertisement each, in a window
 * with a baseline: 3/s against the 10/s gate. Seen to fail: with the total comparison
 * removed from win_passes(), it fires. */
static void test_many_addresses_at_low_rate_does_not_fire(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    prime_key(AD_SWIFT, sizeof(AD_SWIFT), 0x03);
    g_mono += BLE_FLOOD_WINDOW_S * 1000;
    for (unsigned i = 0; i < 30; i++) {
        uint8_t a[6];
        addr_n(a, i);
        ble_adv_report_t r;
        make_report(&r, 0x03, 1, a, AD_SWIFT, sizeof(AD_SWIFT), -50);
        observe(&r, g_wall);
        g_mono += 300;
    }
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 0);
    sloth_clock_test_set(NULL, NULL);
}

/* ── Gate 1 is FRESH addresses (review of slice 4) ── */

/* A crowd of genuine devices: 25 stable addresses re-advertising every
 * 250 ms for 30 s - 100 adv/s from 25 addresses on a listed key, which
 * passed the old distinct-address gate (the reviewer's probe: alerts=1).
 * Seen to fail: with win_passes() comparing w->distinct instead of
 * w->fresh, both crowds fire from their second window on. */
static int play_crowd(const uint8_t *ad, size_t len, unsigned base) {
    int fired = 0;
    for (unsigned t = 0; t < 120; t++) {            /* 120 x 250 ms */
        for (unsigned k = 0; k < 25; k++) {
            uint8_t a[6];
            addr_n(a, base + k);
            ble_adv_report_t r;
            make_report(&r, 0x00, 1, a, ad, len, -60 - (int)k);
            observe(&r, g_wall);
        }
        g_mono += 250;
        if (t % 4 == 3) {                           /* once a second */
            evaluate();
            fired += count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD);
        }
    }
    return fired;
}

static void test_crowd_of_stable_fast_pair_advertisers_does_not_fire(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    ASSERT_EQ(play_crowd(AD_FASTPAIR, sizeof(AD_FASTPAIR), 0x100), 0);
    /* Counted, on a listed key, at the rate: only freshness failed. */
    ASSERT(g_s.ble_flood_count >= 1);
    if (g_s.ble_flood_count >= 1) {
        ASSERT(g_s.ble_flood[0].spam_known);
        ASSERT(g_s.ble_flood[0].prev.distinct >= 20);
        ASSERT(g_s.ble_flood[0].prev.total >= 100);
        ASSERT(g_s.ble_flood[0].prev.baseline);
        ASSERT_EQ((int)g_s.ble_flood[0].prev.fresh, 0);
    }
    sloth_clock_test_set(NULL, NULL);
}

static void test_crowd_of_stable_proximity_pair_advertisers_does_not_fire(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    uint8_t ad[8];
    size_t n = ad_apple(ad, 0x07);
    ASSERT_EQ(play_crowd(ad, n, 0x200), 0);
    /* The same crowd, then the tool's shape on top of it: fresh
     * addresses on the same key. The crowd does not mask it. */
    flood_now(ad, n, 0x00, 0x4000);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 1);
    sloth_clock_test_set(NULL, NULL);
}

/* A key's first window has nothing to be fresh against. Seen to fail:
 * with `w->baseline &&` removed from win_passes(), the unprimed flood
 * fires in its first window. The same flood carried on into the next
 * window fires there. */
static void test_flood_on_a_new_key_waits_one_window(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    flood_now(AD_SWIFT, sizeof(AD_SWIFT), 0x03, 0);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 0);
    g_mono += 8000;                          /* the next window */
    flood_now(AD_SWIFT, sizeof(AD_SWIFT), 0x03, 0x1000);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 1);
    sloth_clock_test_set(NULL, NULL);
}

/* Addresses missed for one window are still not fresh: the baseline is
 * the two windows before. Window 1: 25 addresses at rate. Window 2: one
 * resident only (so window 3 has a baseline). Window 3: the 25 again.
 * Seen to fail: with the bloom_prev2 test dropped from ble_flood_note(),
 * window 3 fires. */
static void test_address_heard_two_windows_ago_is_not_fresh(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    for (int w = 0; w < 3; w++) {
        if (w == 1) {
            prime_key(AD_SWIFT, sizeof(AD_SWIFT), 0x03);
        } else {
            for (unsigned i = 0; i < 400; i++) {     /* 4 s at 100/s */
                uint8_t a[6];
                addr_n(a, 0x300 + (i % 25));
                ble_adv_report_t r;
                make_report(&r, 0x03, 1, a, AD_SWIFT, sizeof(AD_SWIFT), -50);
                observe(&r, g_wall);
                g_mono += 10;
            }
        }
        if (w == 0) g_mono += 6000;          /* to 10 s: window 2 */
        if (w == 1) g_mono += 10000;         /* to 20 s: window 3 */
    }
    evaluate();                              /* 24 s, inside window 3 */
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 0);
    ASSERT(g_s.ble_flood_count == 1);
    if (g_s.ble_flood_count == 1) {
        ASSERT(g_s.ble_flood[0].cur.baseline);
        ASSERT_EQ((int)g_s.ble_flood[0].cur.total, 400);
    }
    sloth_clock_test_set(NULL, NULL);
}

/* Bucketed, not latched: the window that flooded is `prev` for one
 * window, then gone — whether the table was looked at in between (one
 * window closes at a time) or not (two close at once). Seen to fail:
 * with roll()'s n > 1 branch keeping the closing window as `prev`
 * instead of clearing it, the second half's finding outlives its
 * window; the first half alone did not catch that, which is why the
 * second exists. */
static void test_flood_decays_after_two_quiet_windows(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    play_flood(AD_SWIFT, sizeof(AD_SWIFT), 0x03, 0);
    ble_finding_t f[BLE_FINDINGS_MAX];

    g_mono += 9000;                 /* 21 s after the prime: prev (10..20 s) holds it */
    ble_snapshot(&g_s);
    int n = ble_findings_build(&g_s, g_wall, f, BLE_FINDINGS_MAX, NULL);
    ASSERT_EQ(n, 1);
    if (n == 1) ASSERT_EQ(f[0].window, 1);

    g_mono += 15000;                /* 36 s: the window after it was empty */
    ble_snapshot(&g_s);
    n = ble_findings_build(&g_s, g_wall, f, BLE_FINDINGS_MAX, NULL);
    ASSERT_EQ(n, 0);

    /* Again, with no snapshot until two windows have closed at once. */
    ble_clear();
    memset(&g_s, 0, sizeof(g_s));
    play_flood(AD_SWIFT, sizeof(AD_SWIFT), 0x03, 0);
    g_mono += 23000;                /* 35 s: two windows close at once */
    ble_snapshot(&g_s);
    n = ble_findings_build(&g_s, g_wall, f, BLE_FINDINGS_MAX, NULL);
    ASSERT_EQ(n, 0);
    sloth_clock_test_set(NULL, NULL);
}

static void test_tuned_gates_reach_the_detector(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    char err[128];
    /* The low-rate case above, with the operator's rate gate at 2/s. */
    ASSERT_EQ(tune_set("ble.flood_rate=2", err, sizeof(err)), 0);
    prime_key(AD_SWIFT, sizeof(AD_SWIFT), 0x03);
    g_mono += BLE_FLOOD_WINDOW_S * 1000;
    for (unsigned i = 0; i < 30; i++) {
        uint8_t a[6];
        addr_n(a, i);
        ble_adv_report_t r;
        make_report(&r, 0x03, 1, a, AD_SWIFT, sizeof(AD_SWIFT), -50);
        observe(&r, g_wall);
        g_mono += 300;
    }
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_ADV_FLOOD), 1);
    ASSERT_EQ(tune_set("ble.flood_distinct_addrs=129", err, sizeof(err)), -1);
    ASSERT_EQ(tune_set("ble.flood_window_s=0", err, sizeof(err)), -1);
    ASSERT_EQ((long long)tune_spec(TUNE_BLE_FLOOD_WINDOW_S)->def, BLE_FLOOD_WINDOW_S);
    ASSERT_STR(tune_spec(TUNE_BLE_HID_ROTATE_WINDOW_S)->name, "ble.hid_rotate_window_s");
    tune_reset();
    sloth_clock_test_set(NULL, NULL);
}

static void test_spam_list_names_its_source(void) {
    const char *src = NULL;
    ASSERT(ble_spam_family_known(BLE_FAM_MFR, 0x0006, 0x03, &src));
    ASSERT(src && strstr(src, "swiftpair.c"));
    ASSERT(ble_spam_family_known(BLE_FAM_MFR, 0x004C, 0x0F, NULL));
    ASSERT(ble_spam_family_known(BLE_FAM_SVC_DATA, 0xFE2C, -1, NULL));
    ASSERT(!ble_spam_family_known(BLE_FAM_MFR, 0x004C, 0x10, &src));
    ASSERT(src == NULL);
    ASSERT(!ble_spam_family_known(BLE_FAM_SVC_DATA, 0xFE2C, 0x00, NULL));
}

static void test_flood_table_evictions_are_tallied(void) {
    pin_clocks();
    uint64_t before = sh_evict_count(SH_EVICT_BLE_FLOOD);
    for (unsigned i = 0; i < MAX_BLE_FLOOD + 4; i++) {
        uint8_t a[6], ad[8];
        addr_n(a, 1);
        size_t n = ad_apple(ad, (uint8_t)i);
        ble_adv_report_t r;
        make_report(&r, 0x03, 1, a, ad, n, -50);
        observe(&r, g_wall + (time_t)i);
    }
    ble_snapshot(&g_s);
    ASSERT_EQ(g_s.ble_flood_count, MAX_BLE_FLOOD);
    ASSERT_EQ((long long)(sh_evict_count(SH_EVICT_BLE_FLOOD) - before), 4);
    ASSERT_STR(sh_evict_name(SH_EVICT_BLE_FLOOD), "ble_flood");
    sloth_clock_test_set(NULL, NULL);
}

/* ── BLE_HID_UNEXPECTED ───────────────────────────────────────────── */

/* Appearance 0x03C1 (keyboard), LSO first. */
static const uint8_t AD_KEYBOARD[] = { 0x03, 0x19, 0xC1, 0x03, 0x02, 0x01, 0x05 };

static void test_hid_from_espressif_public_address_fires(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    const uint8_t esp[6] = { 0x24, 0x0a, 0xc4, 0x11, 0x22, 0x33 };
    ble_adv_report_t r;
    make_report(&r, 0x00, 0, esp, AD_KEYBOARD, sizeof(AD_KEYBOARD), -55);
    observe(&r, g_wall);
    evaluate();
    int i = find_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ((int)g_s.alerts[i].sev, (int)ALERT_SEV_WARN);
        ASSERT_STR(g_s.alerts[i].key,
                   "blehid:oui:bluetooth-monitor:24:0a:c4:11:22:33");
        ASSERT(strstr(g_s.alerts[i].detail, "Espressif") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "no pairing observed") != NULL);
    }
    ASSERT_STR(alert_technique(ALERT_TYPE_BLE_HID_UNEXPECTED), "T1200");
    sloth_clock_test_set(NULL, NULL);
}

static void test_hid_service_second_in_list_from_hak5_fires(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    const uint8_t hak5[6] = { 0x00, 0x13, 0x37, 0xaa, 0xbb, 0xcc };
    const uint8_t ad[] = { 0x05, 0x03, 0x0F, 0x18, 0x12, 0x18 };
    ble_adv_report_t r;
    make_report(&r, 0x00, 0, hak5, ad, sizeof(ad), -55);
    observe(&r, g_wall);
    evaluate();
    int i = find_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT(strstr(g_s.alerts[i].detail, "Hak5") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "0x1812") != NULL);
    }
    sloth_clock_test_set(NULL, NULL);
}

/* Seen to fail: with the OUI-table check in hid_oui_findings() replaced
 * by a constant, the ordinary-OUI keyboard fires. */
static void test_hid_from_an_ordinary_public_address_does_not_fire(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    const uint8_t ok[6] = { 0x00, 0x1b, 0xdc, 0x01, 0x02, 0x03 };
    ble_adv_report_t r;
    make_report(&r, 0x00, 0, ok, AD_KEYBOARD, sizeof(AD_KEYBOARD), -55);
    observe(&r, g_wall);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED), 0);
    ASSERT_EQ(g_s.ble_device_count, 1);
    if (g_s.ble_device_count == 1) ASSERT_EQ(g_s.ble_devices[0].hid, BLE_HID_APPEARANCE);
    sloth_clock_test_set(NULL, NULL);
}

/* A random address has no OUI: its top octet is not a vendor's. Seen to
 * fail: with addr_is_public() returning 1 for every type, the random
 * address whose bytes happen to read 24:0a:c4 fires. */
static void test_hid_from_a_random_address_is_not_an_oui_match(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    const uint8_t esp[6] = { 0x24, 0x0a, 0xc4, 0x11, 0x22, 0x33 };
    ble_adv_report_t r;
    make_report(&r, 0x00, 1, esp, AD_KEYBOARD, sizeof(AD_KEYBOARD), -55);
    observe(&r, g_wall);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED), 0);
    sloth_clock_test_set(NULL, NULL);
}

static void start_session_at(time_t ts) {
    const uint8_t a[6] = { 0xC2, 0, 0, 0, 0, 0x99 };
    const uint8_t ad[] = { 0x02, 0x01, 0x06 };
    ble_adv_report_t r;
    make_report(&r, 0x00, 1, a, ad, sizeof(ad), -70);
    observe(&r, ts);
}

static void hid_on_new_random(unsigned n, time_t ts) {
    uint8_t a[6];
    addr_n(a, 0x500 + n);
    ble_adv_report_t r;
    make_report(&r, 0x00, 1, a, AD_KEYBOARD, sizeof(AD_KEYBOARD), -50);
    observe(&r, ts);
}

static void test_hid_rotating_across_random_addresses_fires(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    start_session_at(g_wall - 2000);
    for (unsigned i = 0; i < 3; i++) hid_on_new_random(i, g_wall - 100 + (time_t)i);
    evaluate();
    int i = find_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED);
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_STR(g_s.alerts[i].key, "blehid:rotate:bluetooth-monitor");
        ASSERT(strstr(g_s.alerts[i].detail, "3 new random addresses") != NULL);
    }
    sloth_clock_test_set(NULL, NULL);
}

/* The first window of a run: every address is new in it. Seen to fail:
 * with the adv_first_ts gate removed from hid_rotate_findings(), three
 * keyboards present at startup fire. */
static void test_hid_rotation_cannot_fire_in_the_first_window(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    for (unsigned i = 0; i < 3; i++) hid_on_new_random(i, g_wall - 10);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED), 0);
    sloth_clock_test_set(NULL, NULL);
}

/* Seen to fail: with `count < need` changed to `count < 1`, two fire. */
static void test_hid_rotation_needs_the_tuned_count(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    start_session_at(g_wall - 2000);
    for (unsigned i = 0; i < 2; i++) hid_on_new_random(i, g_wall - 100);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED), 0);
    sloth_clock_test_set(NULL, NULL);
}

/* ESP32 IoT gear is everywhere and advertises from public Espressif
 * addresses: without a HID field it is not this rule. Seen to fail:
 * with `!d->hid ||` removed from hid_oui_findings(), it fires. */
static void test_espressif_public_address_without_hid_does_not_fire(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    const uint8_t esp[6] = { 0x24, 0x0a, 0xc4, 0x44, 0x55, 0x66 };
    const uint8_t ad[] = { 0x02, 0x01, 0x06, 0x05, 0x09, 'e', 's', 'p', '1' };
    ble_adv_report_t r;
    make_report(&r, 0x00, 0, esp, ad, sizeof(ad), -55);
    observe(&r, g_wall);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED), 0);
    ASSERT_EQ(g_s.ble_device_count, 1);
    if (g_s.ble_device_count == 1) ASSERT_EQ(g_s.ble_devices[0].hid, 0);
    sloth_clock_test_set(NULL, NULL);
}

/* Resident keyboards: three random HID addresses first heard before the
 * window, still advertising inside it. Seen to fail: with
 * `if (d->first_seen <= since) continue;` removed, they fire. */
static void test_hid_rotation_ignores_addresses_heard_before_the_window(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    start_session_at(g_wall - 3000);
    for (unsigned i = 0; i < 3; i++) hid_on_new_random(i, g_wall - 2000);
    for (unsigned i = 0; i < 3; i++) hid_on_new_random(i, g_wall - 10);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED), 0);
    ASSERT_EQ(g_s.ble_device_count, 4);
    sloth_clock_test_set(NULL, NULL);
}

/* The rotation form is about RANDOM addresses; public ones do not
 * rotate. Ordinary-OUI public keyboards, three new in the window. Seen
 * to fail: with `if (!addr_is_random(d->addr_type)) continue;` removed,
 * they fire. */
static void test_hid_rotation_ignores_public_addresses(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    start_session_at(g_wall - 2000);
    for (unsigned i = 0; i < 3; i++) {
        const uint8_t a[6] = { 0x00, 0x1b, 0xdc, 0x0a, 0x0b, (uint8_t)i };
        ble_adv_report_t r;
        make_report(&r, 0x00, 0, a, AD_KEYBOARD, sizeof(AD_KEYBOARD), -50);
        observe(&r, g_wall - 100);
    }
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED), 0);
    sloth_clock_test_set(NULL, NULL);
}

/* The rotation form counts the HID APPEARANCE: a 0x1812-only row is a
 * service list, which every HID host-side profile and many dongles
 * carry. Seen to fail: with `if (!(d->hid & BLE_HID_APPEARANCE))
 * continue;` removed, three such rows fire. */
static void test_hid_rotation_ignores_service_only_rows(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    start_session_at(g_wall - 2000);
    const uint8_t ad[] = { 0x03, 0x03, 0x12, 0x18 };
    for (unsigned i = 0; i < 3; i++) {
        uint8_t a[6];
        addr_n(a, 0x600 + i);
        ble_adv_report_t r;
        make_report(&r, 0x00, 1, a, ad, sizeof(ad), -50);
        observe(&r, g_wall - 100);
    }
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED), 0);
    ASSERT_EQ(g_s.ble_device_count, 4);
    if (g_s.ble_device_count == 4) ASSERT_EQ(g_s.ble_devices[3].hid, BLE_HID_SERVICE);
    sloth_clock_test_set(NULL, NULL);
}

/* A second sensor started late has its own first window. The host
 * controller has listened for 2000 s; an Ubertooth capture starts 100 s
 * ago and hears three HID keyboards, all new to it. Seen to fail: with
 * the per-iface sensor_first_ts() gate replaced by the host-wide
 * adv_first_ts, the capture's first window fires. Once the capture has
 * itself listened longer than the window, three new ones fire. */
static void observe_capture(const ble_adv_report_t *r, time_t ts) {
    ble_obs_t o = { r, SENSOR_BLE, BT_CAPTURE_IFACE, 0, 37, 1, ts };
    ble_dev_observe(&o);
}

static void test_hid_rotation_first_window_is_per_sensor(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    start_session_at(g_wall - 2000);
    for (unsigned i = 0; i < 3; i++) {
        uint8_t a[6];
        addr_n(a, 0x800 + i);
        ble_adv_report_t r;
        make_report(&r, 0x00, 1, a, AD_KEYBOARD, sizeof(AD_KEYBOARD), -50);
        observe_capture(&r, g_wall - 100 + (time_t)i);
    }
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED), 0);

    g_wall += 1000;                          /* the capture is 1100 s old */
    for (unsigned i = 0; i < 3; i++) {
        uint8_t a[6];
        addr_n(a, 0x810 + i);
        ble_adv_report_t r;
        make_report(&r, 0x00, 1, a, AD_KEYBOARD, sizeof(AD_KEYBOARD), -50);
        observe_capture(&r, g_wall - 50);
    }
    evaluate();
    int i = find_type(&g_s, ALERT_TYPE_BLE_HID_UNEXPECTED);
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_STR(g_s.alerts[i].key, "blehid:rotate:ubertooth");
    sloth_clock_test_set(NULL, NULL);
}

/* Past the cap every lane goes on counting what it could not return.
 * Seen to fail: with the lanes' `continue` after a refused slot() put
 * back to `return`, three Espressif keyboards with room for one report
 * 1 dropped, not 2. */
static void test_dropped_counts_every_finding_past_the_cap(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    for (unsigned i = 0; i < 3; i++) {
        const uint8_t esp[6] = { 0x24, 0x0a, 0xc4, 0x11, 0x22, (uint8_t)i };
        ble_adv_report_t r;
        make_report(&r, 0x00, 0, esp, AD_KEYBOARD, sizeof(AD_KEYBOARD), -55);
        observe(&r, g_wall);
    }
    ble_snapshot(&g_s);
    ble_finding_t f[1];
    int dropped = -1;
    ASSERT_EQ(ble_findings_build(&g_s, g_wall, f, 1, &dropped), 1);
    ASSERT_EQ(dropped, 2);
    sloth_clock_test_set(NULL, NULL);
}

/* ── BLE_WATCHLIST ────────────────────────────────────────────────── */

/* Test fixtures, not shipped rows (see the file comment). */
static const ble_wl_row_t k_test_rows[] = {
    { "smarttag", BLE_WL_SVC_DATA, 0xFD5A, -1, -1, -1,
      "fixture: shape per Yu et al. 2024 §3 as the owner's #144 comment cites it" },
    { "tile", BLE_WL_UUID16, 0xFEED, -1, -1, -1,
      "fixture: SIG member_uuids.yaml assigns 0xFEED to Tile, Inc." },
    { "find-my", BLE_WL_MFR, 0x004C, 0x12, 27, 27,
      "fixture: the issue body's offline-finding shape" },
};

static void test_shipped_table_is_empty_and_never_fires(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    ASSERT_EQ(ble_watchlist_count(), 0);
    const uint8_t a[6] = { 0xC2, 1, 2, 3, 4, 5 };
    const uint8_t ad[] = { 0x05, 0x16, 0x5A, 0xFD, 0x01, 0x02 };
    ble_adv_report_t r;
    make_report(&r, 0x00, 1, a, ad, sizeof(ad), -60);
    ASSERT(ble_watchlist_match(&r) == NULL);
    observe(&r, g_wall);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_WATCHLIST), 0);
    ASSERT_STR(alert_technique(ALERT_TYPE_BLE_WATCHLIST), "");
    sloth_clock_test_set(NULL, NULL);
}

static void test_categories_route_from_the_in_test_table(void) {
    ASSERT_EQ(ble_watchlist_set_table(k_test_rows, 3), 0);
    ASSERT_EQ(ble_watchlist_count(), 3);
    const uint8_t a[6] = { 0xC2, 1, 2, 3, 4, 5 };
    ble_adv_report_t r;

    const uint8_t tag[] = { 0x05, 0x16, 0x5A, 0xFD, 0x01, 0x02 };
    make_report(&r, 0x00, 1, a, tag, sizeof(tag), -60);
    ASSERT(ble_watchlist_match(&r) && strcmp(ble_watchlist_match(&r), "smarttag") == 0);

    const uint8_t tile[] = { 0x05, 0x03, 0x0F, 0x18, 0xED, 0xFE };
    make_report(&r, 0x00, 1, a, tile, sizeof(tile), -60);
    ASSERT(ble_watchlist_match(&r) && strcmp(ble_watchlist_match(&r), "tile") == 0);

    uint8_t fm[31];
    fm[0] = 30; fm[1] = 0xFF; fm[2] = 0x4C; fm[3] = 0x00; fm[4] = 0x12; fm[5] = 0x19;
    for (int i = 6; i < 31; i++) fm[i] = (uint8_t)i;
    make_report(&r, 0x03, 1, a, fm, sizeof(fm), -60);
    ASSERT_EQ(r.mfr_data_len, 27);
    ASSERT(ble_watchlist_match(&r) && strcmp(ble_watchlist_match(&r), "find-my") == 0);

    /* The same company and type, one octet short: the length bound is
     * part of the row. Seen to fail with len_ok() returning 1. */
    fm[0] = 29;
    make_report(&r, 0x03, 1, a, fm, 30, -60);
    ASSERT(ble_watchlist_match(&r) == NULL);

    /* Proximity Pair is Apple too, and is not the row. */
    uint8_t pp[8];
    size_t n = ad_apple(pp, 0x07);
    make_report(&r, 0x03, 1, a, pp, n, -60);
    ASSERT(ble_watchlist_match(&r) == NULL);

    ble_watchlist_reset();
    ASSERT_EQ(ble_watchlist_count(), 0);
}

static void test_a_row_without_a_source_is_refused(void) {
    static const ble_wl_row_t no_src[] = {
        { "tile", BLE_WL_UUID16, 0xFEED, -1, -1, -1, "" },
    };
    static const ble_wl_row_t long_cat[] = {
        { "sixteen-chars-xx", BLE_WL_UUID16, 0xFEED, -1, -1, -1, "src" },
    };
    static const ble_wl_row_t bad_kind[] = {
        { "tile", 9, 0xFEED, -1, -1, -1, "src" },
    };
    ASSERT_EQ(ble_watchlist_set_table(no_src, 1), -1);
    ASSERT_EQ(ble_watchlist_set_table(long_cat, 1), -1);
    ASSERT_EQ(ble_watchlist_set_table(bad_kind, 1), -1);
    ASSERT_EQ(ble_watchlist_set_table(NULL, 1), -1);
    ASSERT_EQ(ble_watchlist_count(), 0);
}

static void test_watchlist_fires_per_category_counting_addresses(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    ASSERT_EQ(ble_watchlist_set_table(k_test_rows, 3), 0);
    const uint8_t tag[] = { 0x05, 0x16, 0x5A, 0xFD, 0x01, 0x02 };
    for (unsigned i = 0; i < 2; i++) {
        uint8_t a[6];
        addr_n(a, 0x700 + i);
        ble_adv_report_t r;
        make_report(&r, 0x00, 1, a, tag, sizeof(tag), -60);
        observe(&r, g_wall - 5);
    }
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_WATCHLIST), 1);
    int i = find_type(&g_s, ALERT_TYPE_BLE_WATCHLIST);
    if (i >= 0) {
        ASSERT_STR(g_s.alerts[i].key, "blewl:smarttag:bluetooth-monitor");
        ASSERT(strstr(g_s.alerts[i].detail, "2 addresses") != NULL);
        ASSERT(strstr(g_s.alerts[i].detail, "never an identity") != NULL);
    }
    ASSERT_STR(g_s.ble_devices[0].watch_cat, "smarttag");
    sloth_clock_test_set(NULL, NULL);
}

/* Seen to fail: with the BLE_WATCH_RECENT_SECS check removed from
 * watch_findings(), the row heard 200 s ago still fires. */
static void test_watchlist_match_heard_long_ago_does_not_fire(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    ASSERT_EQ(ble_watchlist_set_table(k_test_rows, 3), 0);
    const uint8_t tag[] = { 0x05, 0x16, 0x5A, 0xFD, 0x01, 0x02 };
    uint8_t a[6];
    addr_n(a, 0x701);
    ble_adv_report_t r;
    make_report(&r, 0x00, 1, a, tag, sizeof(tag), -60);
    observe(&r, g_wall - 200);
    evaluate();
    ASSERT_EQ(count_type(&g_s, ALERT_TYPE_BLE_WATCHLIST), 0);
    sloth_clock_test_set(NULL, NULL);
}

/* ── JSONL ble_device / ble_alert ─────────────────────────────────── */

static char g_tmp[64];

static void jsonl_fresh(void) {
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/sloth_blerules_XXXXXX");
    int fd = mkstemp(g_tmp);
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_tmp);
    ASSERT(jsonl_open(g_tmp));
}

static char *jsonl_read(void) {
    static char buf[32768];
    FILE *fp = fopen(g_tmp, "r");
    size_t n = 0;
    if (fp) { n = fread(buf, 1, sizeof(buf) - 1, fp); fclose(fp); }
    buf[n] = '\0';
    return buf;
}

static int count_str(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p++) n++;
    return n;
}

static void jsonl_done(void) {
    jsonl_close();
    unlink(g_tmp);
}

static void test_ble_device_record_is_change_only(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    jsonl_fresh();
    const uint8_t a[6] = { 0x00, 0x1b, 0xdc, 0x01, 0x02, 0x03 };
    ble_adv_report_t r;
    make_report(&r, 0x00, 0, a, AD_KEYBOARD, sizeof(AD_KEYBOARD), -55);
    observe(&r, g_wall);
    ble_snapshot(&g_s);
    jsonl_emit_ble_devices(&g_s);

    /* Same row, more advertisements, RSSI inside the same 10 dB bucket:
     * suppressed. Seen to fail: with adv_count added to the signature,
     * the second emit writes a line. */
    make_report(&r, 0x00, 0, a, AD_KEYBOARD, sizeof(AD_KEYBOARD), -52);
    observe(&r, g_wall);
    g_wall += 1;
    ble_snapshot(&g_s);
    jsonl_emit_ble_devices(&g_s);
    char *out = jsonl_read();
    ASSERT_EQ(count_str(out, "\"type\":\"ble_device\""), 1);
    ASSERT(strstr(out, "\"addr\":\"00:1b:dc:01:02:03\"") != NULL);
    ASSERT(strstr(out, "\"iface\":\"bluetooth-monitor\"") != NULL);
    ASSERT(strstr(out, "\"appearance\":961") != NULL);
    ASSERT(strstr(out, "\"hid\":1") != NULL);
    ASSERT(strstr(out, "\"mfr_id\":-1") != NULL);
    ASSERT(strstr(out, "\"watch_category\":\"\"") != NULL);

    /* A stronger best RSSI by a full bucket is a change; a weaker
     * reading is not (the signature carries the best, which only
     * ratchets, so a device hovering on a bucket edge stays quiet). */
    make_report(&r, 0x00, 0, a, AD_KEYBOARD, sizeof(AD_KEYBOARD), -75);
    observe(&r, g_wall);
    g_wall += 1;
    ble_snapshot(&g_s);
    jsonl_emit_ble_devices(&g_s);
    out = jsonl_read();
    ASSERT_EQ(count_str(out, "\"type\":\"ble_device\""), 1);
    make_report(&r, 0x00, 0, a, AD_KEYBOARD, sizeof(AD_KEYBOARD), -30);
    observe(&r, g_wall);
    g_wall += 1;
    ble_snapshot(&g_s);
    jsonl_emit_ble_devices(&g_s);
    out = jsonl_read();
    ASSERT_EQ(count_str(out, "\"type\":\"ble_device\""), 2);
    jsonl_done();
    sloth_clock_test_set(NULL, NULL);
}

static void test_ble_alert_record_carries_the_flood_fields(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    jsonl_fresh();
    play_flood(AD_SWIFT, sizeof(AD_SWIFT), 0x03, 0);
    ble_snapshot(&g_s);
    jsonl_emit_ble_alerts(&g_s);
    /* Unchanged counts: suppressed until the heartbeat. */
    g_mono += 50;
    g_wall += 1;
    ble_snapshot(&g_s);
    jsonl_emit_ble_alerts(&g_s);
    char *out = jsonl_read();
    ASSERT_EQ(count_str(out, "\"type\":\"ble_alert\""), 1);
    ASSERT(strstr(out, "\"kind\":\"adv_flood\"") != NULL);
    ASSERT(strstr(out, "\"alert\":\"ALERT_TYPE_BLE_ADV_FLOOD\"") != NULL);
    ASSERT(strstr(out, "\"key\":\"bleflood:bluetooth-monitor:3:mfr:6:3\"") != NULL);
    ASSERT(strstr(out, "\"family\":\"mfr\"") != NULL);
    ASSERT(strstr(out, "\"distinct_addrs\":128") != NULL);
    ASSERT(strstr(out, "\"distinct_capped\":1") != NULL);
    ASSERT(strstr(out, "\"fresh_addrs\":") != NULL);
    ASSERT(strstr(out, "\"total_adv\":1000") != NULL);
    ASSERT(strstr(out, "\"spam_source\":\"ble_spam swiftpair.c") != NULL);
    jsonl_done();
    sloth_clock_test_set(NULL, NULL);
}

/* An ADV_IND and its SCAN_RSP alternate, and an Apple device rotates
 * its Continuity type: neither is a change of the advertiser. The
 * reviewer's probe wrote 10 lines of 10. Seen to fail: with
 * last_event_type back in the signature in place of pdu_mask, the first
 * loop writes one line per snapshot; with mfr_sub kept as last-seen in
 * observe_locked(), the second does. */
/* #144 slice 4 second review: an advertiser whose ADV_IND carries a
 * shortened name, one UUID and TX power, and whose SCAN_RSP carries the
 * complete name, a different UUID and none, alternates every last-value
 * field on its row. Signing those fields wrote a record per snapshot.
 * Seen to fail with the name and uuid16 back in the signature. */
static void test_ble_device_alternating_fields_settle(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    jsonl_fresh();
    /* Shortened name "kb" (0x08), UUID16 0x180F, TX power 4. */
    static const uint8_t adv[] = { 0x03, 0x08, 'k', 'b',
                                   0x03, 0x03, 0x0F, 0x18,
                                   0x02, 0x0A, 0x04 };
    /* Complete name "kbd" (0x09), UUID16 0x180A. */
    static const uint8_t rsp[] = { 0x04, 0x09, 'k', 'b', 'd',
                                   0x03, 0x03, 0x0A, 0x18 };
    const uint8_t a[6] = { 0x00, 0x1b, 0xdc, 0x01, 0x02, 0x05 };
    for (int i = 0; i < 40; i++) {
        ble_adv_report_t r;
        if (i & 1) make_report(&r, 0x04, 0, a, rsp, sizeof(rsp), -58);
        else       make_report(&r, 0x00, 0, a, adv, sizeof(adv), -57);
        observe(&r, g_wall);
        g_wall += 1;
        ble_snapshot(&g_s);
        jsonl_emit_ble_devices(&g_s);
    }
    char *out = jsonl_read();
    /* ADV_IND alone, then the row once SCAN_RSP and the TX-power, UUID
     * and name presence bits are all set: never one per report. */
    ASSERT(count_str(out, "\"addr\":\"00:1b:dc:01:02:05\"") <= 2);
    jsonl_done();
    sloth_clock_test_set(NULL, NULL);
}

static void test_ble_device_alternating_pdus_settles(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    jsonl_fresh();
    const uint8_t a[6] = { 0x00, 0x1b, 0xdc, 0x01, 0x02, 0x04 };
    for (int i = 0; i < 10; i++) {
        ble_adv_report_t r;
        make_report(&r, (i & 1) ? 0x04 : 0x00, 0, a, AD_KEYBOARD,
                    sizeof(AD_KEYBOARD), -55);
        observe(&r, g_wall);
        g_wall += 1;
        ble_snapshot(&g_s);
        jsonl_emit_ble_devices(&g_s);
    }
    char *out = jsonl_read();
    ASSERT_EQ(count_str(out, "\"type\":\"ble_device\""), 2);   /* ADV_IND, then the mask with SCAN_RSP */
    ASSERT(strstr(out, "\"pdu_mask\":17") != NULL);           /* bits 0 and 4 */

    const uint8_t b[6] = { 0xC2, 0x10, 0x20, 0x30, 0x40, 0x50 };
    for (int i = 0; i < 10; i++) {
        uint8_t ad[8];
        size_t n = ad_apple(ad, (i & 1) ? 0x10 : 0x0C);
        ble_adv_report_t r;
        make_report(&r, 0x00, 1, b, ad, n, -60);
        observe(&r, g_wall);
        g_wall += 1;
        ble_snapshot(&g_s);
        jsonl_emit_ble_devices(&g_s);
    }
    out = jsonl_read();
    ASSERT_EQ(count_str(out, "\"addr\":\"c2:10:20:30:40:50\""), 1);
    ASSERT(strstr(out, "\"mfr_subtype\":12") != NULL);        /* first seen, 0x0C */
    jsonl_done();
    sloth_clock_test_set(NULL, NULL);
}

/* A sustained flood is one state. 50 adv/s of Swift Pair from a fresh
 * address each, snapshot and emit once a second for 60 s. The
 * reviewer's probe wrote 18 lines. Seen to fail: with the signature
 * signing the window in progress (log2 of x->total / x->rate_x10 in
 * place of the prev_* fields), it writes one per power-of-two crossing
 * of every window; with the prev_* values signed raw instead of
 * bucketed, the jitter in fresh (Bloom losses) re-emits it too. */
static void test_sustained_flood_is_few_ble_alert_records(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    jsonl_fresh();
    prime_key(AD_SWIFT, sizeof(AD_SWIFT), 0x03);
    g_mono += BLE_FLOOD_WINDOW_S * 1000;
    unsigned addr = 0;
    for (int sec = 0; sec < 60; sec++) {
        for (int k = 0; k < 50; k++) {
            uint8_t a[6];
            addr_n(a, 0x10000 + addr++);
            ble_adv_report_t r;
            make_report(&r, 0x03, 1, a, AD_SWIFT, sizeof(AD_SWIFT), -50);
            observe(&r, g_wall);
            g_mono += 20;
        }
        g_wall += 1;
        ble_snapshot(&g_s);
        jsonl_emit_ble_alerts(&g_s);
    }
    char *out = jsonl_read();
    int lines = count_str(out, "\"type\":\"ble_alert\"");
    ASSERT(lines >= 1);
    ASSERT(lines <= 3);
    jsonl_done();
    sloth_clock_test_set(NULL, NULL);
}

/* ── [*] BLE view ─────────────────────────────────────────────────── */

static void test_view_empty_state(void) {
    memset(&g_s, 0, sizeof(g_s));
    tui_test_erase();
    view_ble_draw(&g_s);
    ASSERT_SCREEN_HAS("BLE advertisers: 0");
    ASSERT_SCREEN_HAS("no advertisements decoded");
}

static void seed_rows(int n) {
    for (int i = 0; i < n; i++) {
        uint8_t a[6];
        addr_n(a, 0x900 + (unsigned)i);
        /* A long name and a manufacturer field, so the summary column
         * has more than it can show and must be cut. */
        uint8_t ad[31];
        size_t k = 0;
        ad[k++] = 21; ad[k++] = 0x09;
        memcpy(ad + k, "a-very-long-name-xx", 20); k += 20;
        ad[k++] = 0x05; ad[k++] = 0xFF; ad[k++] = 0x4C; ad[k++] = 0x00; ad[k++] = 0x10; ad[k++] = 0x00;
        ble_adv_report_t r;
        make_report(&r, 0x00, (uint8_t)(i & 1), a, ad, k, -40 - i);
        observe(&r, g_wall - i);
    }
    ble_snapshot(&g_s);
}

static void test_view_populated_fits_100x33(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    seed_rows(40);
    g_s.ble_sel = 5;
    ASSERT_EQ(tui_init_offscreen(33, 100), 0);
    tui_test_erase();
    view_ble_draw(&g_s);
    char line[4096];
    int over = 0, rows = 0;
    for (int y = 0; y < 33; y++) {
        if (tui_test_line(y, line, sizeof(line)) < 0) break;
        int cells = 0;
        for (const char *p = line; *p; p++)
            if (((unsigned char)*p & 0xC0) != 0x80) cells++;
        if (cells >= 100) over++;
        if (strstr(line, "c2:00:00:00:09:")) rows++;
    }
    if (over) tui_test_dump(stderr);
    ASSERT_EQ(over, 0);
    ASSERT(rows > 10);
    ASSERT(rows < 40);                    /* paged, not all 40 */
    ASSERT_SCREEN_HAS(">c2:00:00:00:09:05");
    ASSERT_SCREEN_HAS("bluetooth-monitor");
    /* 100 columns leave the summary 32: the 33-character one is cut
     * and says so. */
    ASSERT_SCREEN_HAS("\"a-very-long-name-xx\" mfr 004c/~");
    ASSERT_SCREEN_LACKS("mfr 004c/10");
    ASSERT_SCREEN_HAS(" T: P public R random");
    /* At 220 columns the same rows carry the whole name, uncut. */
    ASSERT_EQ(tui_init_offscreen(TEST_SCREEN_ROWS, TEST_SCREEN_COLS), 0);
    tui_test_erase();
    view_ble_draw(&g_s);
    ASSERT_SCREEN_HAS("\"a-very-long-name-xx\" mfr 004c/10");
    sloth_clock_test_set(NULL, NULL);
}

static void test_view_nav_and_enter_detail(void) {
    pin_clocks();
    memset(&g_s, 0, sizeof(g_s));
    seed_rows(3);
    view_ble_key(&g_s, SLOTH_KEY_UP);
    ASSERT_EQ(g_s.ble_sel, 0);              /* clamps at the top */
    view_ble_key(&g_s, SLOTH_KEY_DOWN);
    view_ble_key(&g_s, SLOTH_KEY_DOWN);
    view_ble_key(&g_s, SLOTH_KEY_DOWN);
    ASSERT_EQ(g_s.ble_sel, 2);              /* and at the bottom */
    view_ble_key(&g_s, '\n');
    ASSERT_EQ(g_s.ble_detail, 1);
    tui_test_erase();
    view_ble_draw(&g_s);
    ASSERT_SCREEN_HAS("BLE advertiser");
    ASSERT_SCREEN_HAS("company 0x004c, first octet 0x10");
    ASSERT_SCREEN_HAS("bluetooth-monitor");
    /* Navigation is swallowed while the detail is open; Esc closes. */
    view_ble_key(&g_s, SLOTH_KEY_UP);
    ASSERT_EQ(g_s.ble_sel, 2);
    view_ble_key(&g_s, 27);
    ASSERT_EQ(g_s.ble_detail, 0);
    sloth_clock_test_set(NULL, NULL);
}

void run_ble_rules_tests(void) {
    TEST_SUITE("BLE detectors, view and records (#144 slice 4)");
    RUN_TEST(test_service_data16_is_decoded);
    RUN_TEST(test_service_data_shorter_than_its_uuid_is_ignored);
    RUN_TEST(test_every_listed_uuid16_is_kept);
    RUN_TEST(test_hid_appearance_range);
    RUN_TEST(test_swift_pair_flood_fires_once_per_key);
    RUN_TEST(test_two_spam_keys_are_two_incidents);
    RUN_TEST(test_same_volume_on_an_unlisted_subtype_does_not_fire);
    RUN_TEST(test_spread_across_subtypes_does_not_fire);
    RUN_TEST(test_few_addresses_at_high_rate_does_not_fire);
    RUN_TEST(test_many_addresses_at_low_rate_does_not_fire);
    RUN_TEST(test_crowd_of_stable_fast_pair_advertisers_does_not_fire);
    RUN_TEST(test_crowd_of_stable_proximity_pair_advertisers_does_not_fire);
    RUN_TEST(test_flood_on_a_new_key_waits_one_window);
    RUN_TEST(test_address_heard_two_windows_ago_is_not_fresh);
    RUN_TEST(test_flood_decays_after_two_quiet_windows);
    RUN_TEST(test_tuned_gates_reach_the_detector);
    RUN_TEST(test_spam_list_names_its_source);
    RUN_TEST(test_flood_table_evictions_are_tallied);
    RUN_TEST(test_hid_from_espressif_public_address_fires);
    RUN_TEST(test_hid_service_second_in_list_from_hak5_fires);
    RUN_TEST(test_hid_from_an_ordinary_public_address_does_not_fire);
    RUN_TEST(test_hid_from_a_random_address_is_not_an_oui_match);
    RUN_TEST(test_hid_rotating_across_random_addresses_fires);
    RUN_TEST(test_hid_rotation_cannot_fire_in_the_first_window);
    RUN_TEST(test_hid_rotation_needs_the_tuned_count);
    RUN_TEST(test_espressif_public_address_without_hid_does_not_fire);
    RUN_TEST(test_hid_rotation_ignores_addresses_heard_before_the_window);
    RUN_TEST(test_hid_rotation_ignores_public_addresses);
    RUN_TEST(test_hid_rotation_ignores_service_only_rows);
    RUN_TEST(test_hid_rotation_first_window_is_per_sensor);
    RUN_TEST(test_dropped_counts_every_finding_past_the_cap);
    RUN_TEST(test_shipped_table_is_empty_and_never_fires);
    RUN_TEST(test_categories_route_from_the_in_test_table);
    RUN_TEST(test_a_row_without_a_source_is_refused);
    RUN_TEST(test_watchlist_fires_per_category_counting_addresses);
    RUN_TEST(test_watchlist_match_heard_long_ago_does_not_fire);
    RUN_TEST(test_ble_device_record_is_change_only);
    RUN_TEST(test_ble_alert_record_carries_the_flood_fields);
    RUN_TEST(test_ble_device_alternating_fields_settle);
    RUN_TEST(test_ble_device_alternating_pdus_settles);
    RUN_TEST(test_sustained_flood_is_few_ble_alert_records);
    RUN_TEST(test_view_empty_state);
    RUN_TEST(test_view_populated_fits_100x33);
    RUN_TEST(test_view_nav_and_enter_detail);
}
