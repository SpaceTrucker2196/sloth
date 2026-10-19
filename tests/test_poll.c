#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "fake_platform.h"
#include "poll.h"
#include "sloth_clock.h"
#include "jsonl.h"
#include "alerts.h"
#include "reset_all.h"
#include "beacon_snoop.h"
#include "transit.h"

/* poll_tick() and its phase table (#113).
 *
 * poll_data() was static in main.c, which no test binary links, so the
 * order of ~45 calls was never under test and five stale reads sat in it
 * unseen. These run the real table end to end on the fake platform.
 *
 * The stages that read the capture-fed tables are compiled only under
 * WITH_PCAP, exactly as poll_data() gated them, so the beacon / twin /
 * transit cases sit in run_poll_capture_path_tests(). They used to run
 * from a second binary, sloth_test_pcap; since #116 sloth_test is built
 * WITH_PCAP and main_test.c calls both groups. */

/* A fixed wall clock far from any real one: the assertions below compare
 * against it, never against the host's time (CI VMs may be seconds old). */
#define POLL_SENTINEL_WALL ((time_t)2000000000)

static time_t   sentinel_wall(void) { return POLL_SENTINEL_WALL; }
static uint64_t sentinel_mono(void) { return 5000000ULL; }

static int g_chanhop_calls;
static void count_chanhop(sloth_state_t *s) { (void)s; g_chanhop_calls++; }

static char poll_tmp[64];

static void sink_open(void) {
    snprintf(poll_tmp, sizeof(poll_tmp), "/tmp/sloth_poll_XXXXXX");
    int fd = mkstemp(poll_tmp);
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(poll_tmp);   /* jsonl_open recreates it 0600 (#87) */
    ASSERT(jsonl_open(poll_tmp));
}

/* Close the sink and return the file's contents (static buffer). */
static const char *sink_read(void) {
    static char buf[65536];
    jsonl_close();
    buf[0] = '\0';
    FILE *fp = fopen(poll_tmp, "r");
    if (fp) {
        size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[n] = '\0';
        fclose(fp);
    }
    unlink(poll_tmp);
    return buf;
}

static void tick_once(sloth_state_t *s) {
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    poll_tick(s, &ctx);
}

/* ── table invariants ─────────────────────────────────────── */

/* The table is the contract: a stage placed after a later phase's stage
 * would run out of order whatever its phase field says. */
static void test_phases_are_monotonic(void) {
    ASSERT_GT(g_poll_stage_count, 0);
    for (int i = 1; i < g_poll_stage_count; i++) {
        if (g_poll_stages[i].phase < g_poll_stages[i - 1].phase)
            fprintf(stderr, "    stage %s (phase %d) follows %s (phase %d)\n",
                    g_poll_stages[i].name, (int)g_poll_stages[i].phase,
                    g_poll_stages[i - 1].name, (int)g_poll_stages[i - 1].phase);
        ASSERT(g_poll_stages[i].phase >= g_poll_stages[i - 1].phase);
    }
}

/* Every phase is populated, every stage has a body and a unique name —
 * poll_stage_index() would otherwise answer for the wrong one. */
static void test_every_phase_has_a_stage_and_names_are_unique(void) {
    int seen[PH_DURABLE + 1];
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < g_poll_stage_count; i++) {
        ASSERT(g_poll_stages[i].fn != NULL);
        ASSERT(g_poll_stages[i].name != NULL);
        ASSERT_EQ(poll_stage_index(g_poll_stages[i].name), i);
        seen[g_poll_stages[i].phase]++;
    }
    for (int p = PH_PLATFORM; p <= PH_DURABLE; p++) ASSERT_GT(seen[p], 0);
    ASSERT_EQ(poll_stage_index("no_such_stage"), -1);
    ASSERT_EQ(poll_stage_index(NULL), -1);
}

/* #111's ring copy has to precede everything that reads s->packets. */
static void test_capture_ring_is_the_first_snapshot_stage(void) {
    int ring = poll_stage_index("capture_ring");
    ASSERT_GE(ring, 0);
    if (ring < 0) return;
    ASSERT_EQ(g_poll_stages[ring].phase, PH_SNAPSHOT);
    for (int i = 0; i < ring; i++)
        ASSERT(g_poll_stages[i].phase < PH_SNAPSHOT);
}

/* The named orderings this issue fixed, by name, so a reorder that keeps
 * the phases monotonic but moves one of these still goes red. */
static void test_fixed_orderings_hold(void) {
    int alerts = poll_stage_index("alerts");
    int jsonl  = poll_stage_index("jsonl");
    int sens   = poll_stage_index("sensors");
    int twins  = poll_stage_index("twins");
    int ring   = poll_stage_index("capture_ring");
    ASSERT_GE(alerts, 0); ASSERT_GE(jsonl, 0); ASSERT_GE(sens, 0);
    ASSERT_GE(twins, 0);
    ASSERT_LT(ring, twins);
    ASSERT_LT(twins, alerts);
    ASSERT_LT(sens, jsonl);
    ASSERT_LT(alerts, jsonl);
    ASSERT_EQ(poll_stage_index("db"), g_poll_stage_count - 1);
}

/* ── end to end on the fake platform ──────────────────────── */

/* PLATFORM reads through g_platform; ctx hooks fire, and NULL hooks are
 * skipped rather than called. */
static void test_tick_reads_platform_and_runs_hooks(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    fake_net_reset();
    snprintf(g_fake_net.ifaces[0].name, sizeof(g_fake_net.ifaces[0].name), "eth0");
    g_fake_net.ifaces[0].rx_bytes = 4242;
    g_fake_net.iface_count = 1;

    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    g_chanhop_calls = 0;
    ctx.chanhop = count_chanhop;
    poll_tick(&s, &ctx);
    ASSERT_EQ(s.iface_count, 1);
    ASSERT_STR(s.ifaces[0].name, "eth0");
    ASSERT_EQ(s.stats_init, 1);          /* PLATFORM baseline ran */
    ASSERT_EQ(s.stats_base_count, 1);
    ASSERT_EQ(g_chanhop_calls, 1);

    ctx.chanhop = NULL;                  /* must not crash, must not count */
    poll_tick(&s, &ctx);
    ASSERT_EQ(g_chanhop_calls, 1);
    fake_net_reset();
}

/* poll_ctx_init() reads the clock seam, so a test-set clock reaches
 * every stage stamped with ctx->wall (stale read 5: rf_quality and
 * bd_update used to read the real wall clock while alerts_update read
 * the seam). */
static void test_ctx_init_reads_the_clock_seam(void) {
    sloth_clock_test_set(sentinel_mono, sentinel_wall);
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    ASSERT_EQ(ctx.wall, POLL_SENTINEL_WALL);
    ASSERT_EQ(ctx.mono_ms, 5000000ULL);
    ASSERT(ctx.research == NULL);
    ASSERT(ctx.alert_hot == NULL);
    ASSERT(ctx.chanhop == NULL);
    sloth_clock_test_set(NULL, NULL);
}

/* Stale read 3: the sensor and wifi_merged records were emitted ahead
 * of sensor_register(), so the tick a monitor radio first registered
 * wrote no sensor record. Now the first tick carries it, stamped with
 * the tick's own wall clock. */
static void test_sensor_emitted_on_registration_tick(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    fake_net_reset();
    sloth_clock_test_set(sentinel_mono, sentinel_wall);
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan9mon");
    sink_open();
    tick_once(&s);
    const char *out = sink_read();
    ASSERT_EQ(s.sensor_count, 1);
    ASSERT(strstr(out, "\"type\":\"sensor\"") != NULL);
    ASSERT(strstr(out, "\"iface\":\"wlan9mon\"") != NULL);
    ASSERT(strstr(out, "\"first_seen\":2000000000") != NULL);
    sloth_clock_test_set(NULL, NULL);
}

void run_poll_tests(void) {
    TEST_SUITE("poll_tick phase table (#113)");
    RUN_TEST(test_phases_are_monotonic);
    RUN_TEST(test_every_phase_has_a_stage_and_names_are_unique);
    RUN_TEST(test_capture_ring_is_the_first_snapshot_stage);
    RUN_TEST(test_fixed_orderings_hold);
    RUN_TEST(test_tick_reads_platform_and_runs_hooks);
    RUN_TEST(test_ctx_init_reads_the_clock_seam);
    RUN_TEST(test_sensor_emitted_on_registration_tick);
}

#ifdef WITH_PCAP
#include "capture/probe.h"

/* Written when these ran in sloth_test_pcap, which had no default
 * setUp; main_test.c's setUp covers them since #116, and the explicit
 * reset stays because a whole tick touches every module's table. */
static void pcap_case_reset(void) {
    sloth_reset_all();
    probe_clear();
    fake_net_reset();
    sloth_clock_test_set(NULL, NULL);
}

static int has_alert(const sloth_state_t *s, alert_type_t t) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == t) return 1;
    return 0;
}

/* Stale read 4: transit_snapshot() ran after alerts_update(), so
 * rule_recurring_transit evaluated the previous tick's s->transits and
 * a third pass alerted one tick late. Three passes inside the window,
 * one tick: the alert is there. */
static void test_transit_alert_fires_same_tick(void) {
    pcap_case_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    sloth_clock_test_set(sentinel_mono, sentinel_wall);
    const uint8_t mac[6] = {0x02, 0x00, 0x5e, 0x10, 0x20, 0x30};
    /* Gaps past TRANSIT_GAP_SECS so each is its own pass; all three
     * inside TRANSIT_WINDOW_SECS of the sentinel. */
    transit_observe(mac, POLL_SENTINEL_WALL - 3600, -60);
    transit_observe(mac, POLL_SENTINEL_WALL - 2400, -55);
    transit_observe(mac, POLL_SENTINEL_WALL - 1200, -50);

    sink_open();
    tick_once(&s);
    const char *out = sink_read();
    ASSERT_EQ(s.transit_count, 1);
    ASSERT(has_alert(&s, ALERT_TYPE_RECURRING_TRANSIT));
    /* And the record order this changes: alerts are written inside
     * alerts_update(), state records at EMIT, so within a tick the alert
     * now precedes the tick's sensor_health self-report. */
    const char *al = strstr(out, "\"kind\":\"RECURRING_TRANSIT\"");
    if (!al) al = strstr(out, "RECURRING_TRANSIT");
    const char *sh = strstr(out, "\"type\":\"sensor_health\"");
    ASSERT(al != NULL);
    ASSERT(sh != NULL);
    if (al && sh) ASSERT_LT(al, sh);
    pcap_case_reset();
}

/* Stale read 2: twins_snapshot() walked s->beacon_aps before
 * beacon_snapshot() refreshed it, so a twin pair appeared one tick after
 * both halves were in the beacon view. */
static void test_twin_episode_sees_this_ticks_beacons(void) {
    pcap_case_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    const uint8_t a[6] = {0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03};
    const uint8_t b[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    beacon_record(a, "Cafe-Net", -70, 6, "WPA2", 102, NULL);
    beacon_record(b, "Cafe-Net", -50, 6, "WPA2", 102, NULL);

    tick_once(&s);
    ASSERT_EQ(s.beacon_count, 2);
    ASSERT_EQ(s.twin_episode_count, 1);
    if (s.twin_episode_count == 1)
        ASSERT_STR(s.twin_episodes[0].ssid, "Cafe-Net");
    pcap_case_reset();
}

/* Stale read 1: jsonl_emit_state_snapshots() ran ahead of the snapshot
 * block, so a beacon first seen this tick reached the stream a tick
 * late. One beacon, one tick, one beacon record. */
static void test_jsonl_state_emitted_after_snapshot(void) {
    pcap_case_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    const uint8_t a[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    beacon_record(a, "Lab-Seed", -42, 11, "WPA2", 102, NULL);

    sink_open();
    tick_once(&s);
    const char *out = sink_read();
    ASSERT_EQ(s.beacon_count, 1);
    ASSERT(strstr(out, "\"type\":\"beacon\"") != NULL);
    ASSERT(strstr(out, "Lab-Seed") != NULL);
    pcap_case_reset();
}

/* Not a stale read in the issue's five — found while moving them:
 * channel_summary_update() aggregates s->beacon_aps and ran before
 * beacon_snapshot(), so the channel rows trailed the beacon table. */
static void test_channel_summary_sees_this_ticks_beacons(void) {
    pcap_case_reset();
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    const uint8_t a[6] = {0x02, 0x66, 0x77, 0x88, 0x99, 0xaa};
    beacon_record(a, "Chan-Seed", -48, 11, "WPA2", 102, NULL);

    tick_once(&s);
    int found = 0;
    for (int i = 0; i < s.channel_count; i++)
        if (s.channels[i].channel == 11 && s.channels[i].ap_count >= 1)
            found = 1;
    ASSERT(found);
    pcap_case_reset();
}

void run_poll_capture_path_tests(void) {
    TEST_SUITE("poll_tick end to end, WITH_PCAP stages (#113)");
    RUN_TEST(test_transit_alert_fires_same_tick);
    RUN_TEST(test_twin_episode_sees_this_ticks_beacons);
    RUN_TEST(test_jsonl_state_emitted_after_snapshot);
    RUN_TEST(test_channel_summary_sees_this_ticks_beacons);
}
#else
/* The no-flag build (sloth_test_noflags, #116) is link-only. */
void run_poll_capture_path_tests(void) {}
#endif
