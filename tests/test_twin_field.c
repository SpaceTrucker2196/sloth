/* #193 field data (src/alerts/twin_field.h): what is counted, once per
 * episode, and that counting changes no alert.
 *
 * Fixtures are hand-built beacon and deauth rows, as test_alerts.c's
 * chain tests are: the shape is two table entries and a victim row, not
 * a frame sequence. Every state is static: sloth_state_t sits near the
 * test stack's limit. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "alerts/twin_field.h"
#include "flood_window.h"
#include "jsonl.h"
#include "tmp_dir.h"

static const uint8_t ORIG[6]  = {0xa8,0xbb,0xcc,0x01,0x02,0x03};  /* globally administered */
static const uint8_t COPY[6]  = {0x02,0x11,0x22,0x33,0x44,0x55};  /* locally administered */
static const uint8_t OTHER[6] = {0x3c,0x52,0xa1,0x09,0x08,0x07};  /* a second vendor */
static const uint8_t STA[6]   = {0x99,0x99,0x99,0x99,0x99,0x99};

static beacon_ap_t *ap(sloth_state_t *s, const char *ssid, const uint8_t b[6],
                       const char *enc, int channel, time_t first_seen) {
    beacon_ap_t *e = &s->beacon_aps[s->beacon_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->ssid, sizeof(e->ssid), "%s", ssid);
    memcpy(e->bssid, b, 6);
    memcpy(e->fp.oui, b, 3);
    snprintf(e->enc, sizeof(e->enc), "%s", enc);
    e->channel     = channel;
    e->signal_dbm  = -55;
    e->frame_count = 50;
    e->first_seen  = first_seen;
    e->last_seen   = time(NULL);
    return e;
}

/* A flood on `b` whose threshold was met just now: DEAUTH_FLOOD's
 * condition, inside the chain rule's window. */
static deauth_victim_t *flood(sloth_state_t *s, const uint8_t b[6]) {
    time_t now = time(NULL);
    deauth_victim_t *v = &s->deauth_victims[s->deauth_victim_count++];
    memset(v, 0, sizeof(*v));
    memcpy(v->victim, STA, 6);
    memcpy(v->bssid, b, 6);
    v->frames = v->peak_win = 20;
    v->streams = 1;
    v->flood = 1;
    v->first_seen = v->last_seen = v->flood_last = now;
    return v;
}

/* The #193 shape: an original heard 15 minutes ago, a locally
 * administered copy of its SSID and security first heard ten minutes
 * after it, on another channel with nothing else to tell them apart,
 * and a flood against the original. */
static void shape(sloth_state_t *s, const char *ssid) {
    memset(s, 0, sizeof(*s));
    time_t t0 = time(NULL) - 900;
    ap(s, ssid, ORIG, "WPA2", 6, t0);
    ap(s, ssid, COPY, "WPA2", 11, t0 + 600);
    flood(s, ORIG);
}

static int has_type(const sloth_state_t *s, alert_type_t t) {
    for (int k = 0; k < s->alert_count; k++)
        if (s->alerts[k].type == t) return 1;
    return 0;
}

static int chain_row(const sloth_state_t *s) {
    for (int k = 0; k < s->alert_count; k++)
        if (strstr(s->alerts[k].key, "twin-chain:") != NULL) return 1;
    return 0;
}

static twin_field_counts_t counts(void) {
    twin_field_counts_t c;
    twin_field_counts(&c);
    return c;
}

/* The shape is counted once per flood episode, with its denominators,
 * and the chain rule still writes nothing for it. A second episode
 * (the flood decayed, then came back) is a second count; the late copy
 * is one entry and stays one. Seen red 2026-11-12 with twin_field_flood()
 * not called (coincide 0) and with the `coincided` latch removed
 * (coincide 2 after the second pass). */
static void test_shape_is_counted_once_per_episode(void) {
    static sloth_state_t s;
    shape(&s, "Cafe-Net");
    alerts_update(&s);
    ASSERT_EQ(chain_row(&s), 0);
    ASSERT(has_type(&s, ALERT_TYPE_DEAUTH_FLOOD));
    twin_field_counts_t c = counts();
    ASSERT(c.since > 0);
    ASSERT_EQ((int)c.floods, 1);
    ASSERT_EQ((int)c.floods_chain, 1);
    ASSERT_EQ((int)c.named, 0);
    ASSERT_EQ((int)c.late_laa, 1);
    ASSERT_EQ((int)c.coincide, 1);
    ASSERT_EQ((int)c.excl_any, 0);

    alerts_update(&s);
    c = counts();
    ASSERT_EQ((int)c.floods, 1);
    ASSERT_EQ((int)c.coincide, 1);
    ASSERT_EQ((int)c.late_laa, 1);

    s.deauth_victims[0].flood = 0;
    alerts_update(&s);
    s.deauth_victims[0].flood = 1;
    s.deauth_victims[0].flood_last = time(NULL);
    alerts_update(&s);
    c = counts();
    ASSERT_EQ((int)c.floods, 2);
    ASSERT_EQ((int)c.floods_chain, 2);
    ASSERT_EQ((int)c.coincide, 2);
    ASSERT_EQ((int)c.late_laa, 1);
}

/* What is not the shape. A copy heard first (the flooded AP is the late
 * one), a copy inside twin.late_arrival_s, a globally administered copy,
 * a copy under other security, and a flood outside the chain's window:
 * each counts its parts and no coincidence. */
static void test_near_misses_are_not_the_shape(void) {
    static sloth_state_t s;
    time_t t0 = time(NULL) - 900;

    memset(&s, 0, sizeof(s));                    /* the copy came first */
    ap(&s, "Cafe-Net", COPY, "WPA2", 11, t0);
    ap(&s, "Cafe-Net", ORIG, "WPA2", 6,  t0 + 600);
    flood(&s, ORIG);
    alerts_update(&s);
    twin_field_counts_t c = counts();
    ASSERT_EQ((int)c.floods_chain, 1);
    ASSERT_EQ((int)c.late_laa, 0);
    ASSERT_EQ((int)c.coincide, 0);

    twin_field_reset();
    alerts_clear();
    shape(&s, "Cafe-Net");                       /* 60 s apart: not late */
    s.beacon_aps[1].first_seen = s.beacon_aps[0].first_seen + 60;
    alerts_update(&s);
    c = counts();
    ASSERT_EQ((int)c.late_laa, 0);
    ASSERT_EQ((int)c.coincide, 0);

    twin_field_reset();
    alerts_clear();
    shape(&s, "Cafe-Net");                       /* other security */
    snprintf(s.beacon_aps[1].enc, sizeof(s.beacon_aps[1].enc), "WPA3");
    alerts_update(&s);
    c = counts();
    ASSERT_EQ((int)c.late_laa, 1);               /* the background counts it */
    ASSERT_EQ((int)c.coincide, 0);               /* the chain never asks */

    twin_field_reset();
    alerts_clear();
    shape(&s, "Cafe-Net");                       /* stale flood */
    s.deauth_victims[0].flood_last = time(NULL) - 60;
    alerts_update(&s);
    c = counts();
    ASSERT_EQ((int)c.floods, 1);
    ASSERT_EQ((int)c.floods_chain, 0);
    ASSERT_EQ((int)c.coincide, 0);
}

/* A flood the chain rule names is `named`, not a coincidence, even with
 * a late LAA copy beside it: the gap #193 describes did not happen. The
 * named pair is the original and a second vendor whose vendor IEs differ
 * on one band, listed before the copy so the chain stops on it. */
static void test_named_flood_is_not_a_coincidence(void) {
    static sloth_state_t s;
    shape(&s, "Cafe-Net");
    time_t t0 = s.beacon_aps[0].first_seen;
    s.beacon_aps[0].fp.vendor_ies_hash = 0x1111u;
    s.beacon_aps[1] = s.beacon_aps[0];
    ap(&s, "Cafe-Net", COPY, "WPA2", 11, t0 + 600);
    beacon_ap_t *o = &s.beacon_aps[1];
    memcpy(o->bssid, OTHER, 6);
    memcpy(o->fp.oui, OTHER, 3);
    o->fp.vendor_ies_hash = 0x2222u;
    alerts_update(&s);
    ASSERT_EQ(chain_row(&s), 1);
    twin_field_counts_t c = counts();
    ASSERT_EQ((int)c.floods_chain, 1);
    ASSERT_EQ((int)c.named, 1);
    ASSERT_EQ((int)c.late_laa, 1);
    ASSERT_EQ((int)c.coincide, 0);
}

/* The exclusions the dropped option would have met: a carrier SSID, a
 * faint half. Each is counted with the coincidence, not instead of it.
 * The sibling test cannot coincide with a late arrival at any tuning
 * (TWIN_SIBLING_WINDOW_S is 10 s, twin.late_arrival_s at least 30), so
 * excl_sibling is 0 by construction; asserted here so a change to either
 * bound shows up. */
static void test_exclusions_are_counted(void) {
    static sloth_state_t s;
    shape(&s, "xfinitywifi");
    alerts_update(&s);
    twin_field_counts_t c = counts();
    ASSERT_EQ((int)c.coincide, 1);
    ASSERT_EQ((int)c.excl_carrier, 1);
    ASSERT_EQ((int)c.excl_faint, 0);
    ASSERT_EQ((int)c.excl_any, 1);

    twin_field_reset();
    alerts_clear();
    shape(&s, "Cafe-Net");
    s.beacon_aps[1].signal_dbm = -95;            /* below the decode margin */
    alerts_update(&s);
    c = counts();
    ASSERT_EQ((int)c.coincide, 1);
    ASSERT_EQ((int)c.excl_carrier, 0);
    ASSERT_EQ((int)c.excl_faint, 1);
    ASSERT_EQ((int)c.excl_sibling, 0);
    ASSERT_EQ((int)c.excl_any, 1);
    ASSERT(TWIN_SIBLING_WINDOW_S < 30);
}

/* The counter changes no alert. One fixture with the shape, a named
 * pair and a carrier copy, run with the hooks on and then off: the
 * alert table (kind, severity, title, detail, key, evidence) and the
 * taint are the same byte for byte. Seen red 2026-11-12 under a
 * mutation that let the shape fall through to the chain's fire() when
 * the hooks were on (the WARN-only version #193 dropped): an extra
 * twin-chain row and a tainted copy. */
typedef struct {
    int     n;
    alert_t a[64];
    int     taint_copy, taint_other;
} run_t;

static void one_run(run_t *out, int on) {
    static sloth_state_t s;
    alerts_clear();
    evil_twin_taint_clear();
    twin_field_reset();
    twin_field_set_enabled(on);
    shape(&s, "Cafe-Net");
    time_t t0 = s.beacon_aps[0].first_seen;
    ap(&s, "xfinitywifi", ORIG, "WPA2", 1, t0);
    s.beacon_aps[2].bssid[5] = 0x77;
    ap(&s, "xfinitywifi", COPY, "WPA2", 11, t0 + 600);
    s.beacon_aps[3].bssid[5] = 0x78;
    flood(&s, s.beacon_aps[2].bssid);
    ap(&s, "Shop", OTHER, "WPA2", 6, t0);
    s.beacon_aps[4].fp.vendor_ies_hash = 0x1111u;
    uint8_t shop2[6] = {0x5c,0x11,0x22,0x33,0x44,0x55};
    ap(&s, "Shop", shop2, "WPA2", 6, t0 + 1);
    s.beacon_aps[5].fp.vendor_ies_hash = 0x2222u;
    flood(&s, OTHER);
    for (int i = 0; i < 3; i++) alerts_update(&s);

    memset(out, 0, sizeof(*out));
    out->n = s.alert_count < 64 ? s.alert_count : 64;
    for (int k = 0; k < out->n; k++) {
        alert_t *d = &out->a[k];
        const alert_t *a = &s.alerts[k];
        d->type = a->type;
        d->sev  = a->sev;
        memcpy(d->title,  a->title,  sizeof(d->title));
        memcpy(d->detail, a->detail, sizeof(d->detail));
        memcpy(d->key,    a->key,    sizeof(d->key));
        memcpy(d->evidence_ids, a->evidence_ids, sizeof(d->evidence_ids));
        d->evidence_id_count = a->evidence_id_count;
        d->confidence = a->confidence;
        d->count = a->count;
    }
    out->taint_copy  = evil_twin_bssid_is_tainted(COPY);
    out->taint_other = evil_twin_bssid_is_tainted(shop2);
}

static void test_counting_changes_no_alert(void) {
    static run_t on, off;
    one_run(&on, 1);
    twin_field_counts_t c = counts();
    ASSERT_EQ((int)c.coincide, 2);               /* the path really ran */
    ASSERT_EQ((int)c.named, 1);
    one_run(&off, 0);
    c = counts();
    ASSERT_EQ((int)c.floods, 0);                 /* and really did not */
    ASSERT_EQ((int)c.coincide, 0);
    ASSERT(on.n > 0);
    ASSERT_EQ(on.n, off.n);
    ASSERT_EQ(memcmp(on.a, off.a, sizeof(on.a)), 0);
    ASSERT_EQ(on.taint_copy, off.taint_copy);
    ASSERT_EQ(on.taint_copy, 0);
    ASSERT_EQ(on.taint_other, off.taint_other);
    ASSERT_EQ(on.taint_other, 1);
}

/* sensor_health carries the counts, last before jsonl_version. */
static void test_sensor_health_carries_the_counts(void) {
    static sloth_state_t s;
    shape(&s, "Cafe-Net");
    alerts_update(&s);
    twin_field_counts_t c = counts();

    char path[TEST_TMP_MAX];
    int fd = mkstemp(test_tmp_tpl(path, sizeof(path), "sloth_tf_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(path);
    ASSERT(jsonl_open(path));
    jsonl_emit_sensor_health(&s);
    jsonl_close();
    static char body[32768];
    FILE *fp = fopen(path, "r");
    size_t n = fp ? fread(body, 1, sizeof(body) - 1, fp) : 0;
    if (fp) fclose(fp);
    body[n] = '\0';
    unlink(path);

    char want[512];
    snprintf(want, sizeof(want),
             ",\"twin193_since\":%lld,"
             "\"twin193_floods\":1,\"twin193_floods_chain\":1,"
             "\"twin193_named\":0,\"twin193_late_laa\":1,"
             "\"twin193_coincide\":1,\"twin193_excl_carrier\":0,"
             "\"twin193_excl_faint\":0,\"twin193_excl_sibling\":0,"
             "\"twin193_excl_any\":0,\"db_max_mb\":-1,"
             "\"jsonl_version\":\"%s\"}\n",
             (long long)c.since, SLOTH_JSONL_VERSION);
    ASSERT(strstr(body, want) != NULL);
}

void run_twin_field_tests(void) {
    RUN_TEST(test_shape_is_counted_once_per_episode);
    RUN_TEST(test_near_misses_are_not_the_shape);
    RUN_TEST(test_named_flood_is_not_a_coincidence);
    RUN_TEST(test_exclusions_are_counted);
    RUN_TEST(test_counting_changes_no_alert);
    RUN_TEST(test_sensor_health_carries_the_counts);
}
