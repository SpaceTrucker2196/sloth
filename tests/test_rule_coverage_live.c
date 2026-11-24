#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "tmp_dir.h"
#include "fake_platform.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "sys_status.h"
#include "capture_side.h"
#include "rf_side.h"
#include "jsonl.h"
#include "db.h"
#include "ownership.h"
#include "rule_coverage_live.h"
#include "alerts.h"
#include "sensor_health.h"

/*
 * Coverage assessment, the running half (#242 slice 2): the environment
 * built from the source rows and the capture side, the status each
 * daemon keeps for its own kinds, and the records.
 *
 * The sources are the state fields src/sys_status_capture.c derives
 * its rows from (cap_health, mon_health), seeded by hand, as
 * tests/test_sensor_rules.c does. Both clocks are pinned.
 */

TEST_STATE(g_s);

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }

static char g_path[TEST_TMP_MAX];
static char g_buf[1 << 17];

static void begin(void) {
    capture_side_install();
    g_mono = 5000000;
    g_wall = (time_t)1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    ownership_clear();
    memset(&g_s, 0, sizeof(g_s));
}

static void end(void) {
    jsonl_close();
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    ownership_clear();
    capture_side_install();
    sloth_clock_test_set(NULL, NULL);
}

/* The health stage, as the poll runs it. */
static void tick(void) {
    g_mono += 1000;
    g_wall += 1;
    sys_status_poll(&g_s, g_wall, g_mono);
    cov_live_poll(&g_s);
}

static void health_up(capture_health_t *h) {
    h->open = 1;
    h->running = 1;
    h->stale_secs = 0;
}

static void monitor_up(void) {
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "mon0");
    health_up(&g_s.mon_health);
}

static void capture_up(void) {
    snprintf(g_s.pkt_iface, sizeof(g_s.pkt_iface), "eth0");
    g_s.pkt_linktype = 1;
    health_up(&g_s.cap_health);
}

/* The default --hop list, src/wifi_chanhop.c. */
static void hop_default(void) {
    static const int ch[] = { 1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161 };
    g_s.scan_chan_count = (int)(sizeof(ch) / sizeof(*ch));
    for (int i = 0; i < g_s.scan_chan_count; i++) g_s.scan_chans[i] = ch[i];
}

static void sink_open(void) {
    g_path[0] = '\0';
    int fd = mkstemp(test_tmp_tpl(g_path, sizeof(g_path), "sloth_cov_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    db_close();
    unlink(g_path);
    ASSERT(jsonl_open(g_path));
}

static const char *sink_read(void) {
    jsonl_close();
    g_buf[0] = '\0';
    FILE *fp = fopen(g_path, "r");
    if (fp) {
        size_t n = fread(g_buf, 1, sizeof(g_buf) - 1, fp);
        g_buf[n] = '\0';
        fclose(fp);
    }
    unlink(g_path);
    return g_buf;
}

static int count_of(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

static int status_is(alert_type_t t, cov_status_t st, cov_reason_t why) {
    cov_status_t s = COV_OBSERVABLE;
    cov_reason_t w = COV_R_NONE;
    if (!cov_live_get(t, &s, &w)) return 0;
    return s == st && w == why;
}

/* ── the environment from the source rows ─────────────────────────── */

static void test_env_from_sources(void) {
    static sys_snapshot_t sn;
    cov_env_t e;

    /* No sample yet: nothing is claimed, the sampler included. */
    memset(&sn, 0, sizeof(sn));
    cov_env_from_sources(&sn, &e);
    for (int i = 0; i < COV_IN_COUNT; i++) ASSERT_EQ((int)e.input[i], (int)COV_AV_NONE);
    cov_env_from_sources(NULL, &e);
    ASSERT_EQ((int)e.input[COV_IN_SYS], (int)COV_AV_NONE);

    /* A sample with no named row: this daemon reports no source. */
    sn.valid = 1;
    cov_env_from_sources(&sn, &e);
    ASSERT_EQ((int)e.input[COV_IN_SYS], (int)COV_AV_UP);
    ASSERT_EQ((int)e.input[COV_IN_DOT11], (int)COV_AV_NONE);
    ASSERT_EQ((int)e.input[COV_IN_GNSS], (int)COV_AV_NONE);

    /* An Ethernet capture is IP; the same row in monitor mode is
     * 802.11 and gives no IP. */
    sn.src[SYS_SRC_CAPTURE].name = "capture";
    sn.src[SYS_SRC_CAPTURE].state = SYS_ST_OK;
    snprintf(sn.src[SYS_SRC_CAPTURE].kind, sizeof(sn.src[0].kind), "ip-capture");
    cov_env_from_sources(&sn, &e);
    ASSERT_EQ((int)e.input[COV_IN_IP], (int)COV_AV_UP);
    ASSERT_EQ((int)e.input[COV_IN_DOT11], (int)COV_AV_NONE);
    snprintf(sn.src[SYS_SRC_CAPTURE].kind, sizeof(sn.src[0].kind), "wifi-monitor");
    cov_env_from_sources(&sn, &e);
    ASSERT_EQ((int)e.input[COV_IN_IP], (int)COV_AV_NONE);
    ASSERT_EQ((int)e.input[COV_IN_DOT11], (int)COV_AV_UP);

    /* Two sources of one input: the better one counts. A dead monitor
     * radio beside a capture interface in monitor mode is not blind. */
    sn.src[SYS_SRC_MONITOR].name = "monitor";
    sn.src[SYS_SRC_MONITOR].state = SYS_ST_DOWN;
    cov_env_from_sources(&sn, &e);
    ASSERT_EQ((int)e.input[COV_IN_DOT11], (int)COV_AV_UP);
    sn.src[SYS_SRC_CAPTURE].state = SYS_ST_NOT_CONFIGURED;
    cov_env_from_sources(&sn, &e);
    ASSERT_EQ((int)e.input[COV_IN_DOT11], (int)COV_AV_DOWN);

    /* btcap carries advertising and no host command. */
    sn.src[SYS_SRC_BTCAP].name = "btcap";
    sn.src[SYS_SRC_BTCAP].state = SYS_ST_STALE;
    cov_env_from_sources(&sn, &e);
    ASSERT_EQ((int)e.input[COV_IN_BLE_ADV], (int)COV_AV_STALE);
    ASSERT_EQ((int)e.input[COV_IN_BLE_HCI], (int)COV_AV_NONE);
    sn.src[SYS_SRC_BTMON].name = "btmon";
    sn.src[SYS_SRC_BTMON].state = SYS_ST_OK;
    cov_env_from_sources(&sn, &e);
    ASSERT_EQ((int)e.input[COV_IN_BLE_ADV], (int)COV_AV_UP);
    ASSERT_EQ((int)e.input[COV_IN_BLE_HCI], (int)COV_AV_UP);

    /* Trimmed at start (src/rf_trim.h) is not a source. */
    sn.src[SYS_SRC_ADSB].name = "adsb";
    sn.src[SYS_SRC_ADSB].state = SYS_ST_NOT_INSTALLED;
    sn.src[SYS_SRC_GNSS].name = "gnss";
    sn.src[SYS_SRC_GNSS].state = SYS_ST_OK;
    cov_env_from_sources(&sn, &e);
    ASSERT_EQ((int)e.input[COV_IN_ADSB], (int)COV_AV_NONE);
    ASSERT_EQ((int)e.input[COV_IN_GNSS], (int)COV_AV_UP);
}

/* ── the status a running daemon keeps ────────────────────────────── */

static void test_nothing_before_the_first_sample(void) {
    begin();
    ASSERT_EQ(cov_live_valid(), 0);
    ASSERT_EQ(cov_live_get(ALERT_TYPE_EVIL_TWIN, NULL, NULL), 0);
    int ob = 7, pa = 7, bl = 7;
    cov_live_counts(&ob, &pa, &bl);
    ASSERT_EQ(ob + pa + bl, 0);
    sink_open();
    cov_live_emit();
    ASSERT_STR(sink_read(), "");
    end();
}

static void test_no_radio_no_capture(void) {
    /* Acceptance 1 of #242 through the daemon: no monitor radio, and
     * each Wi-Fi rule reads blind with the reason. */
    begin();
    tick();
    ASSERT_EQ(cov_live_valid(), 1);
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_BLIND, COV_R_NO_SOURCE));
    ASSERT(status_is(ALERT_TYPE_HANDSHAKE_HARVEST, COV_BLIND, COV_R_NO_SOURCE));
    ASSERT(status_is(ALERT_TYPE_THREAT_DOMAIN, COV_BLIND, COV_R_NO_SOURCE));
    /* What needs no capture still runs. */
    ASSERT(status_is(ALERT_TYPE_PORT_SCAN, COV_OBSERVABLE, COV_R_NONE));
    ASSERT(status_is(ALERT_TYPE_NO_MONITOR_MODE, COV_OBSERVABLE, COV_R_NONE));
    ASSERT(status_is(ALERT_TYPE_SENSOR_SOURCE_DOWN, COV_OBSERVABLE, COV_R_NONE));
    /* Another daemon's kind has no status here. */
    ASSERT_EQ(cov_live_get(ALERT_TYPE_GNSS_JAMMING, NULL, NULL), 0);
    ASSERT_EQ(cov_live_get(ALERT_TYPE_COUNT, NULL, NULL), 0);

    int ob, pa, bl;
    cov_live_counts(&ob, &pa, &bl);
    ASSERT_EQ(ob + pa + bl, 96);
    ASSERT_EQ(pa, 0);
    /* 5 host kinds and the 3 sampler kinds; 58 + 26 + 4 BLE are blind. */
    ASSERT_EQ(ob, 8);
    ASSERT_EQ(bl, 88);
    end();
}

static void test_radio_down_is_not_radio_absent(void) {
    begin();
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "mon0");
    tick();   /* named, not open */
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_BLIND, COV_R_SOURCE_DOWN));
    end();
}

static void test_fixed_radio(void) {
    begin();
    monitor_up();
    capture_up();
    tick();
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_PARTLY, COV_R_FIXED_CHANNEL));
    ASSERT(status_is(ALERT_TYPE_HANDSHAKE_HARVEST, COV_PARTLY, COV_R_FIXED_CHANNEL));
    /* Band unknown for a radio that is not retuned: no band claim. */
    ASSERT(status_is(ALERT_TYPE_DFS_MASKING, COV_PARTLY, COV_R_FIXED_CHANNEL));
    ASSERT(status_is(ALERT_TYPE_THREAT_DOMAIN, COV_OBSERVABLE, COV_R_NONE));
    const cov_env_t *e = cov_live_env();
    ASSERT_EQ(e->radios, 1);
    ASSERT_EQ(e->channels, 1);
    ASSERT_EQ(e->hopping, 0);
    ASSERT_EQ(e->bands, 0u);
    end();
}

static void test_hopping_radio(void) {
    /* Acceptance 2 of #242 through the daemon, on the default list. */
    begin();
    monitor_up();
    hop_default();
    tick();
    const cov_env_t *e = cov_live_env();
    ASSERT_EQ(e->radios, 1);
    ASSERT_EQ(e->channels, 11);
    ASSERT_EQ(e->hopping, 1);
    ASSERT_EQ(e->bands, COV_B_24 | COV_B_5);
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_OBSERVABLE, COV_R_NONE));
    ASSERT(status_is(ALERT_TYPE_HANDSHAKE_HARVEST, COV_PARTLY, COV_R_HOP));
    ASSERT(status_is(ALERT_TYPE_COUNTRY_ABSENT, COV_OBSERVABLE, COV_R_NONE));
    /* No DFS channel in the list. */
    ASSERT(status_is(ALERT_TYPE_DFS_MASKING, COV_BLIND, COV_R_BAND));
    end();
}

static void test_operator_configuration(void) {
    begin();
    monitor_up();
    hop_default();
    tick();
    ASSERT(status_is(ALERT_TYPE_MY_NETWORK_RECON, COV_BLIND, COV_R_NO_OWN_NET));
    ASSERT(status_is(ALERT_TYPE_SAE_PSK_REGRESSION, COV_BLIND, COV_R_NO_DB));

    ASSERT(ownership_add_ssid("homenet"));
    tick();
    ASSERT(status_is(ALERT_TYPE_MY_NETWORK_RECON, COV_OBSERVABLE, COV_R_NONE));
    ASSERT(status_is(ALERT_TYPE_UNKNOWN_DEVICE, COV_BLIND, COV_R_NO_ROSTER));
    end();
}

static void test_replay_is_not_assessed(void) {
    /* A replay's source rows read `down` and its frames reach the
     * rules all the same: no status is kept for it and none written.
     * Seen red with the is_replay() test removed from
     * cov_capture_fill() (88 kinds blind, 96 records). */
    begin();
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "replay");
    tick();
    ASSERT_EQ(cov_live_valid(), 0);
    ASSERT_EQ(cov_live_get(ALERT_TYPE_EVIL_TWIN, NULL, NULL), 0);
    sink_open();
    cov_live_emit();
    jsonl_emit_sensor_health(&g_s);
    const char *out = sink_read();
    ASSERT(strstr(out, "rule_status") == NULL);
    ASSERT(strstr(out, "\"coverage\"") == NULL);
    ASSERT(strstr(out, "rules_observable") == NULL);
    /* A live run that follows in the same process is assessed again. */
    g_s.probe_iface[0] = '\0';
    tick();
    ASSERT_EQ(cov_live_valid(), 1);
    end();
}

/* ── the records ──────────────────────────────────────────────────── */

static void test_records_baseline_then_change_only(void) {
    begin();
    monitor_up();
    hop_default();
    tick();
    sink_open();
    cov_live_emit();
    const char *out = sink_read();
    /* The baseline: every kind this daemon raises, and the summary. */
    ASSERT_EQ(count_of(out, "{\"type\":\"rule_status\""), 96);
    ASSERT_EQ(count_of(out, "{\"type\":\"coverage\""), 1);
    ASSERT(strstr(out, "\"ty\":18,\"kind\":\"EVIL_TWIN\",\"status\":\"observable\","
                       "\"why\":\"\",\"input\":\"dot11\"") != NULL);
    ASSERT(strstr(out, "\"kind\":\"HANDSHAKE_HARVEST\",\"status\":\"partly\","
                       "\"why\":\"hop\",\"input\":\"dot11\"") != NULL);
    ASSERT(strstr(out, "\"kind\":\"DFS_MASKING\",\"status\":\"blind\","
                       "\"why\":\"band\"") != NULL);
    ASSERT(strstr(out, "\"kind\":\"GNSS_JAMMING\"") == NULL);
    ASSERT(strstr(out, "\"daemon\":\"wifi\",\"rules\":96,") != NULL);
    ASSERT(strstr(out, "\"radios\":1,\"channels\":11,\"hopping\":1,"
                       "\"bands\":\"2.4,5\"") != NULL);

    /* Nothing changed: nothing written. jsonl_open() cleared the cache
     * above, so the baseline is replayed first and then held. */
    sink_open();
    cov_live_emit();
    tick();
    cov_live_emit();
    out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"rule_status\""), 96);
    ASSERT_EQ(count_of(out, "\"type\":\"coverage\""), 1);

    /* The radio goes: the 58 802.11 kinds are rewritten, no other. */
    sink_open();
    cov_live_emit();
    g_s.mon_health.running = 0;
    tick();
    cov_live_emit();
    out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"rule_status\""), 96 + 58);
    ASSERT_EQ(count_of(out, "\"status\":\"blind\",\"why\":\"source_down\""), 58);
    ASSERT_EQ(count_of(out, "\"type\":\"coverage\""), 2);
    end();
}

static void test_sensor_health_counts(void) {
    /* Absent until derived: a count nobody made is not a zero. */
    begin();
    sink_open();
    jsonl_emit_sensor_health(&g_s);
    const char *out = sink_read();
    ASSERT(strstr(out, "\"type\":\"sensor_health\"") != NULL);
    ASSERT(strstr(out, "rules_observable") == NULL);

    monitor_up();
    hop_default();
    tick();
    int ob, pa, bl;
    cov_live_counts(&ob, &pa, &bl);
    char want[96];
    snprintf(want, sizeof(want), "\"rules_observable\":%d,\"rules_partly\":%d,"
                                 "\"rules_blind\":%d,", ob, pa, bl);
    sink_open();
    jsonl_emit_sensor_health(&g_s);
    out = sink_read();
    ASSERT(strstr(out, want) != NULL);
    /* One hopping radio on the default list, no capture, no BLE, no
     * designation: the 8 host and sampler kinds and the 16 beacon-state
     * kinds that need nothing more; the 37 other 802.11 kinds; and the
     * 26 IP, 4 BLE, 4 unconfigured and 1 DFS kinds. */
    ASSERT_EQ(ob, 24);
    ASSERT_EQ(pa, 37);
    ASSERT_EQ(bl, 35);
    end();
}

/* ── SENSOR_SUPPRESSED (#242 item 4) ─────────────────────────────── */

/* The capture filler reads the open incidents: a beacon table evicting
 * past the threshold makes the beacon rules `partly`, `suppressed` on
 * the next tick, and their rule_status rows say so; the rules that read
 * other frames keep their own reason. Seen red with the
 * rules_sensor_suppressed() call left out of cov_capture_fill(). */
static void test_suppressed_reaches_the_statuses(void) {
    begin();
    alerts_clear();
    sh_evict_reset();
    monitor_up();
    hop_default();
    tick();
    alerts_update(&g_s);
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_OBSERVABLE, COV_R_NONE));
    for (int i = 0; i < 700; i++) sh_evict_note(SH_EVICT_BEACON_AP);
    for (int i = 0; i < 61; i++) { tick(); alerts_update(&g_s); }
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_PARTLY, COV_R_SUPPRESSED));
    ASSERT(status_is(ALERT_TYPE_HANDSHAKE_HARVEST, COV_PARTLY, COV_R_HOP));
    ASSERT(status_is(ALERT_TYPE_SENSOR_SUPPRESSED, COV_OBSERVABLE, COV_R_NONE));
    sink_open();
    cov_live_emit();
    const char *out = sink_read();
    ASSERT(strstr(out, "\"kind\":\"EVIL_TWIN\",\"status\":\"partly\","
                       "\"why\":\"suppressed\",\"input\":\"dot11\"") != NULL);
    alerts_clear();
    sh_evict_reset();
    end();
}

/* ── the gap groups (#242 item 3, review of 3c8f7db0) ─────────────── */

/* Every partly and blind kind is in exactly one group, whatever the
 * reasons in play: the report, the JSON `gaps` and the Stats view list
 * the groups under the counts, and a kind in no group would be counted
 * and never named. Checked against the counts, a per-kind sweep and
 * each group's own (status, reason), across the environments the
 * suite can build: no radio, a fixed radio, the hop list, an own
 * network, an open SENSOR_SUPPRESSED, and sloth-rf. Seen red with
 * gap_order[]'s COV_R_HOP entry given COV_BLIND and the fallback loop
 * removed (the hop kinds in no group), and with that entry made a
 * second COV_R_FIXED_CHANNEL (its kinds in two groups); green with the
 * fallback kept under the COV_BLIND mutation. Dropping an entry
 * outright fails the build (gap_order_lists_every_reason). */
static void gaps_cover_every_kind(void) {
    static cov_gap_t gaps[COV_GAP_MAX];
    int ob = 0, pa = 0, bl = 0;
    cov_live_counts(&ob, &pa, &bl);
    int ng = cov_live_gaps(gaps, COV_GAP_MAX);
    int sum = 0;
    int seen[ALERT_TYPE_COUNT];
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < ng; i++) {
        ASSERT(gaps[i].n > 0);
        ASSERT(gaps[i].st != COV_OBSERVABLE);
        sum += gaps[i].n;
        for (int k = 0; k < gaps[i].n; k++) {
            cov_status_t st = COV_OBSERVABLE;
            cov_reason_t why = COV_R_NONE;
            ASSERT_EQ(cov_live_get(gaps[i].kind[k], &st, &why), 1);
            ASSERT_EQ((int)st, (int)gaps[i].st);
            ASSERT_EQ((int)why, (int)gaps[i].why);
            seen[gaps[i].kind[k]]++;
        }
    }
    ASSERT_EQ(sum, pa + bl);
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        cov_status_t st = COV_OBSERVABLE;
        if (!cov_live_get((alert_type_t)t, &st, NULL)) continue;
        ASSERT_EQ(seen[t], st == COV_OBSERVABLE ? 0 : 1);
    }
}

static void test_gaps_hold_every_partly_and_blind_kind(void) {
    begin();
    tick();                         /* nothing configured */
    gaps_cover_every_kind();
    monitor_up();
    capture_up();
    tick();                         /* a fixed radio */
    gaps_cover_every_kind();
    hop_default();
    tick();                         /* the hop list */
    gaps_cover_every_kind();
    ASSERT(ownership_add_ssid("homenet"));
    tick();                         /* an own network, no roster */
    gaps_cover_every_kind();

    alerts_clear();
    sh_evict_reset();
    tick();
    alerts_update(&g_s);
    for (int i = 0; i < 700; i++) sh_evict_note(SH_EVICT_BEACON_AP);
    for (int i = 0; i < 61; i++) { tick(); alerts_update(&g_s); }
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_PARTLY, COV_R_SUPPRESSED));
    gaps_cover_every_kind();        /* suppressed beside hop */
    alerts_clear();
    sh_evict_reset();

    rf_side_install();
    cov_live_reset();
    tick();
    gaps_cover_every_kind();        /* sloth-rf's six */
    end();
}

/* ── sloth-rf ─────────────────────────────────────────────────────── */

static void test_rf_daemon_has_its_own_six(void) {
    begin();
    rf_side_install();
    cov_live_reset();
    tick();
    int ob, pa, bl;
    cov_live_counts(&ob, &pa, &bl);
    ASSERT_EQ(ob + pa + bl, 6);
    /* No --gps, no --adsb: those five are blind, the source rule is
     * not. */
    ASSERT_EQ(bl, 5);
    ASSERT(status_is(ALERT_TYPE_GNSS_JAMMING, COV_BLIND, COV_R_NO_SOURCE));
    ASSERT(status_is(ALERT_TYPE_SENSOR_SOURCE_DOWN, COV_OBSERVABLE, COV_R_NONE));
    ASSERT_EQ(cov_live_get(ALERT_TYPE_EVIL_TWIN, NULL, NULL), 0);
    ASSERT_EQ(cov_live_get(ALERT_TYPE_SENSOR_UNDERVOLT, NULL, NULL), 0);

    sink_open();
    cov_live_emit();
    const char *out = sink_read();
    ASSERT_EQ(count_of(out, "\"type\":\"rule_status\""), 6);
    ASSERT(strstr(out, "\"daemon\":\"rf\",\"rules\":6,") != NULL);
    end();
}

void run_rule_coverage_live_tests(void) {
    TEST_SUITE("coverage assessment, running (#242 slice 2)");
    RUN_TEST(test_env_from_sources);
    RUN_TEST(test_nothing_before_the_first_sample);
    RUN_TEST(test_no_radio_no_capture);
    RUN_TEST(test_radio_down_is_not_radio_absent);
    RUN_TEST(test_fixed_radio);
    RUN_TEST(test_hopping_radio);
    RUN_TEST(test_operator_configuration);
    RUN_TEST(test_replay_is_not_assessed);
    RUN_TEST(test_records_baseline_then_change_only);
    RUN_TEST(test_sensor_health_counts);
    RUN_TEST(test_suppressed_reaches_the_statuses);
    RUN_TEST(test_rf_daemon_has_its_own_six);
    RUN_TEST(test_gaps_hold_every_partly_and_blind_kind);
}
