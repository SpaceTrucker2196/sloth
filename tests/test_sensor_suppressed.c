#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "sloth_clock.h"
#include "fake_platform.h"
#include "sys_status.h"
#include "sensor_health.h"
#include "cov_interval.h"
#include "capture_side.h"
#include "rule_coverage_live.h"
#include "tune.h"
#include "alerts/rules.h"
#ifdef WITH_PCAP
#include "capture/probe.h"
#include "frame_build.h"
#endif

/*
 * SENSOR_SUPPRESSED (#242 item 4, src/alerts/rules_sensor.c): the
 * eviction, drop and silent-channel signals, each its own incident,
 * their recovery, and the `partly` / `suppressed` statuses they put on
 * the rules whose evidence they cost.
 *
 * Every tick runs the poll's three stages in its order: the health
 * stage (sys_status_poll, then cov_live_poll), then the rules. Both
 * clocks are pinned. The handles' counters are the state fields
 * src/sys_status_capture.c reads, seeded by hand as
 * tests/test_sensor_rules.c does; the flood acceptance drives real
 * hand-built probe requests through the monitor callback.
 *
 * Every absence assertion names the mutation it was seen red under
 * (agents/AGENTS.md).
 */

TEST_STATE(g_s);

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }

static int  g_created, g_resolved;
static char g_reason[32];

static void hook(const alert_t *a, time_t now, const char *reason) {
    (void)now;
    if (a->type != ALERT_TYPE_SENSOR_SUPPRESSED) return;
    if (reason) {
        g_resolved++;
        snprintf(g_reason, sizeof(g_reason), "%s", reason);
    } else if (a->event_seq == 1) {
        g_created++;
    }
}

static void begin(void) {
    capture_side_install();
    g_mono = 5000000;
    g_wall = (time_t)1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    cov_iv_reset();
    sh_evict_reset();
    tune_reset();
    alerts_clear();
    rules_sensor_reset();
    memset(&g_s, 0, sizeof(g_s));
    g_created = g_resolved = 0;
    g_reason[0] = '\0';
    alerts_set_incident_hook(hook);
}

static void end(void) {
    alerts_set_incident_hook(NULL);
    alerts_clear();
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    cov_iv_reset();
    sh_evict_reset();
    tune_reset();
    sloth_clock_test_set(NULL, NULL);
}

/* Per tick, what the handles add: received and dropped. */
static uint64_t g_mon_recv_ps, g_mon_drop_ps, g_cap_recv_ps, g_cap_drop_ps;

static void tick(void) {
    g_mono += 1000;
    g_wall += 1;
    if (g_s.mon_health.open) {
        g_s.mon_health.ps_recv += g_mon_recv_ps;
        g_s.mon_health.ps_drop += g_mon_drop_ps;
        g_s.mon_health.last_frame_ts = g_wall;
    }
    if (g_s.cap_health.open) {
        g_s.cap_health.ps_recv += g_cap_recv_ps;
        g_s.cap_health.ps_ifdrop += g_cap_drop_ps;
        g_s.cap_health.last_frame_ts = g_wall;
    }
    sys_status_poll(&g_s, g_wall, g_mono);
    cov_live_poll(&g_s);
    alerts_update(&g_s);
}

static void ticks(int n) { for (int i = 0; i < n; i++) tick(); }

static void health_up(capture_health_t *h) {
    h->open = 1;
    h->running = 1;
    h->stats_valid = 1;
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

static void rates(uint64_t mon_recv, uint64_t mon_drop, uint64_t cap_recv, uint64_t cap_drop) {
    g_mon_recv_ps = mon_recv; g_mon_drop_ps = mon_drop;
    g_cap_recv_ps = cap_recv; g_cap_drop_ps = cap_drop;
}

static const alert_t *open_of(const char *key) {
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == ALERT_TYPE_SENSOR_SUPPRESSED && !g_s.alerts[i].resolved &&
            (!key || !strcmp(g_s.alerts[i].key, key)))
            return &g_s.alerts[i];
    return NULL;
}

static int status_is(alert_type_t t, cov_status_t st, cov_reason_t why) {
    cov_status_t s = COV_OBSERVABLE;
    cov_reason_t w = COV_R_NONE;
    if (!cov_live_get(t, &s, &w)) return 0;
    return s == st && w == why;
}

static cov_reason_t reason_of(alert_type_t t) {
    cov_reason_t w = COV_R_NONE;
    cov_live_get(t, NULL, &w);
    return w;
}

static void evict_n(sh_evict_t k, int n) { for (int i = 0; i < n; i++) sh_evict_note(k); }

/* ── evictions ────────────────────────────────────────────────────── */

#ifdef WITH_PCAP
/* A probe request (IEEE 802.11-2020 9.3.3.9: FC 0x40, DA broadcast,
 * SA the station, BSSID wildcard, then the SSID element, empty for a
 * wildcard request) from a locally administered address numbered
 * `ordinal`, behind a radiotap header naming 2437 MHz. */
static int probe_req(uint8_t *buf, int cap, int ordinal) {
    static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const uint8_t sa[6] = { 0x02, 0x00, 0x5a,
                            (uint8_t)((ordinal >> 16) & 0xff),
                            (uint8_t)((ordinal >> 8) & 0xff),
                            (uint8_t)(ordinal & 0xff) };
    fb_t b;
    fb_init(&b, buf, cap);
    fb_rt_t rt;
    memset(&rt, 0, sizeof(rt));
    rt.has_channel = 1;
    rt.freq_mhz = 2437;
    fb_radiotap(&b, &rt);
    fb_mgmt(&b, 4, 0, bcast, sa, bcast, (uint16_t)((ordinal & 0xfff) << 4), 0);
    fb_ssid(&b, "");
    return fb_ok(&b) ? b.len : -1;
}

/* `n` distinct stations' probe requests through the monitor callback. */
static void spray(int first, int n) {
    enum { CHUNK = 64, FL = 64 };
    static uint8_t bufs[CHUNK][FL];
    const uint8_t *fs[CHUNK];
    int ls[CHUNK];
    static sloth_state_t ds;
    memset(&ds, 0, sizeof(ds));
    for (int done = 0; done < n; ) {
        int batch = n - done < CHUNK ? n - done : CHUNK;
        for (int i = 0; i < batch; i++) {
            ls[i] = probe_req(bufs[i], FL, first + done + i);
            ASSERT(ls[i] > 0);
            fs[i] = bufs[i];
        }
        ASSERT_EQ(probe_test_dispatch(&ds, fs, ls, NULL, NULL, batch), batch);
        done += batch;
    }
}

/* #242's acceptance: a flood that fills a table raises
 * SENSOR_SUPPRESSED. A thousand stations' probe requests in one minute
 * overrun the 128-row probing-client table 872 times, past the 600 a
 * minute default, and with it the probe-latency and sequence-number
 * tables, which key on the same transmitters. One incident, WARN,
 * naming the worst table and that there are others; while it is open
 * every 802.11 rule reads `partly`, `suppressed` (the sequence-number
 * table every 802.11 rule's spoof checks lean on is among them) and
 * the wired rules do not. */
static void test_probe_spray_raises_it(void) {
    begin();
    probe_clear();
    monitor_up();
    capture_up();
    rates(100, 0, 100, 0);
    tick();
    spray(1, 1000);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_PROBE_CLIENT), 1000 - MAX_PROBE_CLIENTS);
    ASSERT((long long)sh_evict_count(SH_EVICT_SEQNUM_CLIENT) >= 600);
    ticks(59);
    /* The minute is not over: nothing judged yet. Seen red with the
     * window test removed (judged every tick). */
    ASSERT(open_of(NULL) == NULL);
    tick();
    const alert_t *a = open_of("suppressed:evict");
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->sev, ALERT_SEV_WARN);
        ASSERT_STR(a->technique, "");
        ASSERT(strstr(a->detail, " (and other tables) evicted 600 or more rows in a minute") != NULL);
    }
    ASSERT_EQ(g_created, 1);
    tick();
    ASSERT(status_is(ALERT_TYPE_PROBE_FLOOD, COV_PARTLY, COV_R_SUPPRESSED));
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_PARTLY, COV_R_SUPPRESSED));
    ASSERT(status_is(ALERT_TYPE_MY_NETWORK_RECON, COV_BLIND, COV_R_NO_OWN_NET));
    ASSERT(status_is(ALERT_TYPE_THREAT_DOMAIN, COV_OBSERVABLE, COV_R_NONE));
    ASSERT(status_is(ALERT_TYPE_SENSOR_SUPPRESSED, COV_OBSERVABLE, COV_R_NONE));
    probe_clear();
    end();
}
#endif

/* Recovery: a minute under the threshold starts the hold, and the
 * incident closes `recovered` SENSOR_RECOVER_S later, not before; the
 * statuses go back with it. One incident for the whole episode. */
static void test_evict_recovers(void) {
    begin();
    monitor_up();
    rates(100, 0, 0, 0);
    tick();                                   /* the window opens */
    evict_n(SH_EVICT_BEACON_AP, 700);
    ticks(60);                                /* minute 1: over */
    ASSERT(open_of("suppressed:evict") != NULL);
    ticks(1);
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_PARTLY, COV_R_SUPPRESSED));
    /* Beacons only: a probe-request rule is not suppressed. */
    ASSERT(reason_of(ALERT_TYPE_PROBE_FLOOD) != COV_R_SUPPRESSED);
    evict_n(SH_EVICT_BEACON_AP, 650);
    ticks(59);                                /* minute 2: over again */
    ASSERT(open_of("suppressed:evict") != NULL);
    ticks(60);                                /* minute 3: clear, hold starts */
    ticks(SENSOR_RECOVER_S - 1);
    /* Seen red with SENSOR_RECOVER_S read as 60 in hold_clear(). */
    ASSERT(open_of("suppressed:evict") != NULL);
    ASSERT_EQ(g_resolved, 0);
    tick();
    ASSERT(open_of("suppressed:evict") == NULL);
    ASSERT_EQ(g_resolved, 1);
    ASSERT_STR(g_reason, "recovered");
    ASSERT_EQ(g_created, 1);
    tick();
    /* Seen red with both of what drops the scope at the close removed:
     * rules_sensor_suppressed()'s open test and the reset of the
     * signal's inputs in rule_sensor_suppressed() (EVIL_TWIN still
     * suppressed). Either alone is enough, so neither alone goes red. */
    ASSERT(reason_of(ALERT_TYPE_EVIL_TWIN) != COV_R_SUPPRESSED);
    end();
}

/* Under the threshold by one, and the tallies the rule does not judge:
 * no incident. The 599 is seen red with `n < thr` made `n + 1 < thr`;
 * evidence_frame, dns_log and alert each seen red, one at a time, made
 * a judged table at the top of evict_scope(). */
static void test_evict_absences(void) {
    begin();
    monitor_up();
    rates(100, 0, 0, 0);
    tick();
    evict_n(SH_EVICT_PROBE_CLIENT, 599);
    evict_n(SH_EVICT_EVIDENCE_FRAME, 9000);
    evict_n(SH_EVICT_DNS_LOG, 9000);
    evict_n(SH_EVICT_ALERT, 9000);
    ticks(60);
    ASSERT(open_of(NULL) == NULL);
    ASSERT_EQ(g_created, 0);
    /* Spread over two minutes, 1000 is 500 a minute: under. Seen red
     * with take_window() not re-taken at the window's end. */
    evict_n(SH_EVICT_PROBE_CLIENT, 500);
    ticks(60);
    evict_n(SH_EVICT_PROBE_CLIENT, 500);
    ticks(60);
    ASSERT(open_of(NULL) == NULL);
    /* The knob moves it: 400 a minute is over a 300 threshold. */
    ASSERT_EQ(tune_set_id(TUNE_SUPPRESS_EVICT_PER_MIN, 300), 1);
    evict_n(SH_EVICT_PROBE_CLIENT, 400);
    ticks(60);
    ASSERT(open_of("suppressed:evict") != NULL);
    end();
}

/* The device table is every source's: its loss suppresses the IP
 * rules as well as the 802.11 ones, and not BLE's. No BLE source is up
 * here, so BLE_ADV_FLOOD reads blind / no_source whatever the scope and
 * its status cannot show the BLE bit; the scope itself is asserted. Seen
 * red with SH_EVICT_DEVICE's scope or-ed with 1u << COV_IN_BLE_ADV in
 * evict_scope(). */
static void test_evict_device_table_reaches_both_inputs(void) {
    begin();
    monitor_up();
    capture_up();
    rates(100, 0, 100, 0);
    tick();
    evict_n(SH_EVICT_DEVICE, 600);
    ticks(61);
    ASSERT(open_of("suppressed:evict") != NULL);
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_PARTLY, COV_R_SUPPRESSED));
    ASSERT(status_is(ALERT_TYPE_THREAT_DOMAIN, COV_PARTLY, COV_R_SUPPRESSED));
    unsigned in = 0, fr = 0;
    rules_sensor_suppressed(&in, &fr);
    ASSERT_EQ(in, (1u << COV_IN_DOT11) | (1u << COV_IN_IP));
    ASSERT_EQ(fr, 0u);
    end();
}

/* ── drops ────────────────────────────────────────────────────────── */

/* The monitor handle dropping 2 % of what it received for a minute:
 * one incident naming the handle, every 802.11 rule `suppressed`, the
 * wired rules not. */
static void test_monitor_drops(void) {
    begin();
    monitor_up();
    capture_up();
    rates(1000, 20, 1000, 0);
    tick();
    ticks(60);
    const alert_t *a = open_of("suppressed:drop");
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->sev, ALERT_SEV_WARN);
        ASSERT(strstr(a->detail, "the monitor handle (mon0) dropped 1% or more") != NULL);
    }
    ASSERT(open_of("suppressed:evict") == NULL);
    tick();
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_PARTLY, COV_R_SUPPRESSED));
    ASSERT(status_is(ALERT_TYPE_HANDSHAKE_HARVEST, COV_PARTLY, COV_R_SUPPRESSED));
    ASSERT(status_is(ALERT_TYPE_THREAT_DOMAIN, COV_OBSERVABLE, COV_R_NONE));

    /* Drops stop: recovered after the hold. */
    rates(1000, 0, 1000, 0);
    ticks(58 + SENSOR_RECOVER_S);
    ASSERT(open_of("suppressed:drop") != NULL);
    tick();
    ASSERT(open_of("suppressed:drop") == NULL);
    ASSERT_STR(g_reason, "recovered");
    end();
}

/* The IP capture's drops suppress the wired rules and not the 802.11
 * ones. */
static void test_capture_drops(void) {
    begin();
    monitor_up();
    capture_up();
    rates(1000, 0, 1000, 50);
    tick();
    ticks(61);
    const alert_t *a = open_of("suppressed:drop");
    ASSERT(a != NULL);
    if (a) ASSERT(strstr(a->detail, "the capture handle (eth0)") != NULL);
    ASSERT(status_is(ALERT_TYPE_THREAT_DOMAIN, COV_PARTLY, COV_R_SUPPRESSED));
    ASSERT(reason_of(ALERT_TYPE_EVIL_TWIN) != COV_R_SUPPRESSED);
    end();
}

/* Under the share, under the count, and a handle with no stats: no
 * incident. 0.5 % seen red with the share test removed; 60 drops at
 * 1.2 % seen red with the drop_min test removed; the stats-less handle
 * seen red with handle_ok() returning h->open. */
static void test_drop_absences(void) {
    begin();
    monitor_up();
    rates(1000, 5, 0, 0);                     /* 300 a minute, 0.5 % */
    tick();
    ticks(60);
    ASSERT(open_of(NULL) == NULL);

    rates(83, 1, 0, 0);                       /* 60 a minute, 1.2 % */
    ticks(60);
    ASSERT(open_of(NULL) == NULL);

    g_s.mon_health.stats_valid = 0;
    rates(1000, 500, 0, 0);
    ticks(120);
    ASSERT(open_of(NULL) == NULL);
    ASSERT_EQ(g_created, 0);
    end();
}

/* ── a silent channel ─────────────────────────────────────────────── */

/* One coverage interval: each of `n` channels visited 5 s with the
 * frames given, then the rule's tick that reads it. */
static void interval(const int *mhz, const uint64_t *frames, int n) {
    if (!cov_iv_is_open()) cov_iv_open(g_wall, g_mono);
    for (int i = 0; i < n; i++) cov_iv_add(0, mhz[i], 0, 5000, frames[i]);
    ticks(60);
    cov_iv_close(g_wall, g_mono, NULL, 0, 0, 0, 0, 0, 0);
    tick();
}

static const int k_24[3] = { 2412, 2437, 2462 };   /* channels 1, 6, 11 */

/* Channel 6 heard, then silent three minutes running while 1 and 11
 * are heard: one incident naming 2437 MHz; every 802.11 rule
 * `suppressed`. Heard again, it recovers. */
static void test_silent_channel(void) {
    begin();
    monitor_up();
    rates(100, 0, 0, 0);
    tick();
    const uint64_t all[3] = { 40, 90, 30 }, six_quiet[3] = { 40, 0, 30 };
    interval(k_24, all, 3);
    interval(k_24, six_quiet, 3);
    interval(k_24, six_quiet, 3);
    /* Two in a row is under the three. Seen red with the run compared
     * `> need - 2`. */
    ASSERT(open_of(NULL) == NULL);
    interval(k_24, six_quiet, 3);
    const alert_t *a = open_of("suppressed:silent");
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->sev, ALERT_SEV_WARN);
        ASSERT(strstr(a->detail, "2437 MHz (2.4 GHz band) heard nothing for 3 or more minutes") != NULL);
    }
    tick();
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_PARTLY, COV_R_SUPPRESSED));
    ASSERT(status_is(ALERT_TYPE_PROBE_FLOOD, COV_PARTLY, COV_R_SUPPRESSED));

    interval(k_24, all, 3);                   /* heard again: hold starts */
    ticks(SENSOR_RECOVER_S - 1);
    ASSERT(open_of("suppressed:silent") != NULL);
    tick();
    ASSERT(open_of("suppressed:silent") == NULL);
    ASSERT_STR(g_reason, "recovered");
    ASSERT_EQ(g_created, 1);
    end();
}

/* The operator's `c` (alerts_clear()) mid-episode: the incident closes
 * `cleared`, and the channel stays one this run has heard, so while it
 * is still silent the signal opens again after the full run of
 * intervals, not before. The reopen seen red with suppressed_forget()
 * zeroing the heard channels; the two intervals' absence seen red with
 * it keeping each channel's run. */
static void test_silent_survives_a_clear(void) {
    begin();
    monitor_up();
    rates(100, 0, 0, 0);
    tick();
    const uint64_t all[3] = { 40, 90, 30 }, six_quiet[3] = { 40, 0, 30 };
    interval(k_24, all, 3);
    for (int i = 0; i < 3; i++) interval(k_24, six_quiet, 3);
    ASSERT(open_of("suppressed:silent") != NULL);
    ASSERT_EQ(g_created, 1);
    alerts_clear();
    ASSERT_EQ(g_resolved, 1);
    ASSERT_STR(g_reason, "cleared");
    interval(k_24, six_quiet, 3);
    interval(k_24, six_quiet, 3);
    ASSERT(open_of(NULL) == NULL);
    interval(k_24, six_quiet, 3);
    ASSERT(open_of("suppressed:silent") != NULL);
    ASSERT_EQ(g_created, 2);
    tick();
    ASSERT(status_is(ALERT_TYPE_EVIL_TWIN, COV_PARTLY, COV_R_SUPPRESSED));
    end();

    /* A new run (rules_sensor_reset(), the test registry's) starts from
     * nothing: 2437 heard before it is not heard after. Seen red with
     * rules_sensor_reset() calling suppressed_forget() instead. */
    begin();
    monitor_up();
    tick();
    interval(k_24, all, 3);
    rules_sensor_reset();
    for (int i = 0; i < 5; i++) interval(k_24, six_quiet, 3);
    ASSERT(open_of(NULL) == NULL);
    end();
}

/* What is not a suppressed channel. Each case seen red under its own
 * mutation of judge_silent_iv():
 *   always empty        `c->heard` dropped from the run's condition;
 *   whole band quiet    band_heard forced 1;
 *   another band heard  the band compare `ivb[o] == ivb[j]` dropped;
 *   a skipped visit     the not-visited reset removed. */
static void test_silent_absences(void) {
    begin();
    monitor_up();
    rates(100, 0, 0, 0);
    tick();
    /* Channel 6 never heard. */
    const uint64_t never[3] = { 40, 0, 30 };
    for (int i = 0; i < 5; i++) interval(k_24, never, 3);
    ASSERT(open_of(NULL) == NULL);
    end();

    begin();
    monitor_up();
    tick();
    /* The whole band goes quiet at once. */
    const uint64_t all[3] = { 40, 90, 30 }, none[3] = { 0, 0, 0 };
    interval(k_24, all, 3);
    for (int i = 0; i < 5; i++) interval(k_24, none, 3);
    ASSERT(open_of(NULL) == NULL);
    end();

    begin();
    monitor_up();
    tick();
    /* 2.4 GHz quiet, 5 GHz heard: not this band's neighbours. */
    const int mixed[3] = { 2412, 2437, 5180 };
    const uint64_t on[3] = { 40, 90, 30 }, off[3] = { 0, 0, 30 };
    interval(mixed, on, 3);
    for (int i = 0; i < 5; i++) interval(mixed, off, 3);
    ASSERT(open_of(NULL) == NULL);
    end();

    begin();
    monitor_up();
    tick();
    /* Silent twice, not visited, silent twice: never three in a row. */
    const uint64_t quiet6[3] = { 40, 0, 30 };
    const int two[2] = { 2412, 2462 };
    const uint64_t two_f[2] = { 40, 30 };
    interval(k_24, on, 3);
    interval(k_24, quiet6, 3);
    interval(k_24, quiet6, 3);
    interval(two, two_f, 2);
    interval(k_24, quiet6, 3);
    interval(k_24, quiet6, 3);
    ASSERT(open_of(NULL) == NULL);
    ASSERT_EQ(g_created, 0);
    end();
}

/* ── a replay ─────────────────────────────────────────────────────── */

/* A --replay fills tables at file speed: nothing is judged. Seen red
 * with the replaying() test removed from rule_sensor_suppressed(). */
static void test_replay_never_raises_it(void) {
    begin();
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "replay");
    health_up(&g_s.mon_health);
    rates(1000, 500, 0, 0);
    tick();
    evict_n(SH_EVICT_PROBE_CLIENT, 5000);
    ticks(130);
    ASSERT(open_of(NULL) == NULL);
    ASSERT_EQ(g_created, 0);
    end();
}

/* The signals are independent incidents, keyed apart. */
static void test_signals_are_separate_incidents(void) {
    begin();
    monitor_up();
    rates(1000, 50, 0, 0);
    tick();
    evict_n(SH_EVICT_ASSOC_REQ, 800);
    ticks(60);
    ASSERT(open_of("suppressed:evict") != NULL);
    ASSERT(open_of("suppressed:drop") != NULL);
    ASSERT_EQ(g_created, 2);
    unsigned in = 0, fr = 0;
    rules_sensor_suppressed(&in, &fr);
    ASSERT_EQ(fr, (unsigned)COV_F_ASSOC);
    ASSERT_EQ(in, 1u << COV_IN_DOT11);
    end();
}

void run_sensor_suppressed_tests(void) {
    TEST_SUITE("SENSOR_SUPPRESSED (#242 item 4)");
#ifdef WITH_PCAP
    RUN_TEST(test_probe_spray_raises_it);
#endif
    RUN_TEST(test_evict_recovers);
    RUN_TEST(test_evict_absences);
    RUN_TEST(test_evict_device_table_reaches_both_inputs);
    RUN_TEST(test_monitor_drops);
    RUN_TEST(test_capture_drops);
    RUN_TEST(test_drop_absences);
    RUN_TEST(test_silent_channel);
    RUN_TEST(test_silent_survives_a_clear);
    RUN_TEST(test_silent_absences);
    RUN_TEST(test_replay_never_raises_it);
    RUN_TEST(test_signals_are_separate_incidents);
}
