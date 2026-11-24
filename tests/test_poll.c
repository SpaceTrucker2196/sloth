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
#include "tmp_dir.h"
#include "ownership.h"
#include "gps.h"
#include "adsb.h"
#include "aprs.h"
#include "rtl433.h"
#include "bt_stream.h"
#include "rf_profile.h"

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
 * WITH_PCAP and main_test.c calls both groups.
 *
 * Since #212 the table is data the application passes. There were
 * three until the cutover (#216); there are two: g_poll_wifi, what
 * sloth-wifi runs, and g_poll_rf, sloth-rf's. The older cases below run
 * g_poll_wifi, as main.c does; the #212 group spells each table out,
 * holds the stages they share to one body, and runs each alone. */

/* A fixed wall clock far from any real one: the assertions below compare
 * against it, never against the host's time (CI VMs may be seconds old). */
#define POLL_SENTINEL_WALL ((time_t)2000000000)

static time_t   sentinel_wall(void) { return POLL_SENTINEL_WALL; }
static uint64_t sentinel_mono(void) { return 5000000ULL; }

static int g_chanhop_calls;
static void count_chanhop(sloth_state_t *s) { (void)s; g_chanhop_calls++; }

static char poll_tmp[TEST_TMP_MAX];

static void sink_open(void) {
    snprintf(poll_tmp, sizeof(poll_tmp), "%s/sloth_poll_XXXXXX", test_tmpdir());
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
    poll_tick(&g_poll_wifi, s, &ctx);
}

/* ── table invariants ─────────────────────────────────────── */

static const poll_table_t *const g_tables[] = {
    &g_poll_wifi, &g_poll_rf
};
static const char *const g_table_names[] = { "wifi", "rf" };
#define TABLE_COUNT ((int)(sizeof(g_tables) / sizeof(g_tables[0])))

/* The table is the contract: a stage placed after a later phase's stage
 * would run out of order whatever its phase field says. Every table. */
static void test_phases_are_monotonic(void) {
    for (int k = 0; k < TABLE_COUNT; k++) {
        const poll_table_t *t = g_tables[k];
        ASSERT_GT(t->count, 0);
        for (int i = 1; i < t->count; i++) {
            if (t->stages[i].phase < t->stages[i - 1].phase)
                fprintf(stderr, "    %s: stage %s (phase %d) follows %s (phase %d)\n",
                        g_table_names[k],
                        t->stages[i].name, (int)t->stages[i].phase,
                        t->stages[i - 1].name, (int)t->stages[i - 1].phase);
            ASSERT(t->stages[i].phase >= t->stages[i - 1].phase);
        }
    }
}

/* Every stage has a body and a unique name — poll_stage_index() would
 * otherwise answer for the wrong one — and the table a capturing
 * daemon runs populates every phase. The RF table has no SNAPSHOT or
 * POST stage by design (its sources fill s in their health polls), so
 * it is held only to the phases it must have. */
static void test_every_phase_has_a_stage_and_names_are_unique(void) {
    for (int k = 0; k < TABLE_COUNT; k++) {
        const poll_table_t *t = g_tables[k];
        int seen[PH_DURABLE + 1];
        memset(seen, 0, sizeof(seen));
        for (int i = 0; i < t->count; i++) {
            ASSERT(t->stages[i].fn != NULL);
            ASSERT(t->stages[i].name != NULL);
            ASSERT_EQ(poll_stage_index(t, t->stages[i].name), i);
            seen[t->stages[i].phase]++;
        }
        if (t == &g_poll_rf) {
            ASSERT_GT(seen[PH_PLATFORM], 0);
            ASSERT_GT(seen[PH_DERIVE], 0);
            ASSERT_GT(seen[PH_ALERTS], 0);
            ASSERT_GT(seen[PH_EMIT], 0);
            ASSERT_GT(seen[PH_DURABLE], 0);
        } else {
            for (int p = PH_PLATFORM; p <= PH_DURABLE; p++) ASSERT_GT(seen[p], 0);
        }
        ASSERT_EQ(poll_stage_index(t, "no_such_stage"), -1);
        ASSERT_EQ(poll_stage_index(t, NULL), -1);
    }
    ASSERT_EQ(poll_stage_index(NULL, "alerts"), -1);
}

/* #111's ring copy has to precede everything that reads s->packets. */
static void test_capture_ring_is_the_first_snapshot_stage(void) {
    const poll_table_t *both[] = { &g_poll_wifi };
    for (int k = 0; k < 1; k++) {
        const poll_table_t *t = both[k];
        int ring = poll_stage_index(t, "capture_ring");
        ASSERT_GE(ring, 0);
        if (ring < 0) continue;
        ASSERT_EQ(t->stages[ring].phase, PH_SNAPSHOT);
        for (int i = 0; i < ring; i++)
            ASSERT(t->stages[i].phase < PH_SNAPSHOT);
    }
}

/* The named orderings #113 fixed, by name, so a reorder that keeps the
 * phases monotonic but moves one of these still goes red. */
static void test_fixed_orderings_hold(void) {
    const poll_table_t *both[] = { &g_poll_wifi };
    for (int k = 0; k < 1; k++) {
        const poll_table_t *t = both[k];
        int alerts = poll_stage_index(t, "alerts");
        int jsonl  = poll_stage_index(t, "jsonl");
        int sens   = poll_stage_index(t, "sensors_wifi");
        int twins  = poll_stage_index(t, "twins");
        int ring   = poll_stage_index(t, "capture_ring");
        ASSERT_GE(alerts, 0); ASSERT_GE(jsonl, 0); ASSERT_GE(sens, 0);
        ASSERT_GE(twins, 0);
        ASSERT_LT(ring, twins);
        ASSERT_LT(twins, alerts);
        ASSERT_LT(sens, jsonl);
        ASSERT_LT(alerts, jsonl);
        ASSERT_EQ(poll_stage_index(t, "db"), t->count - 1);
    }
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
    poll_tick(&g_poll_wifi, &s, &ctx);
    ASSERT_EQ(s.iface_count, 1);
    ASSERT_STR(s.ifaces[0].name, "eth0");
    ASSERT_EQ(s.stats_init, 1);          /* PLATFORM baseline ran */
    ASSERT_EQ(s.stats_base_count, 1);
    ASSERT_EQ(g_chanhop_calls, 1);

    ctx.chanhop = NULL;                  /* must not crash, must not count */
    poll_tick(&g_poll_wifi, &s, &ctx);
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

/* #183: the self roster is sourced from the iface records the PLATFORM
 * phase already polls, so it must be populated by the first tick — the
 * phase order puts PLATFORM ahead of the alert rules, which means there
 * is no tick on which a rule can see a probe from the host's own card
 * before the roster knows the address. */
static void test_tick_rosters_the_hosts_own_iface_macs(void) {
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    fake_net_reset();
    ownership_clear();
    const uint8_t eth[6] = {0x24,0x41,0x8c,0x00,0x00,0x01};
    const uint8_t mon[6] = {0x00,0xc0,0xca,0xbb,0x51,0x82};
    snprintf(g_fake_net.ifaces[0].name, sizeof(g_fake_net.ifaces[0].name),
             "eth0");
    memcpy(g_fake_net.ifaces[0].mac, eth, 6);
    g_fake_net.ifaces[0].mode = IFACE_MODE_ETHER;
    snprintf(g_fake_net.ifaces[1].name, sizeof(g_fake_net.ifaces[1].name),
             "alfa0");
    memcpy(g_fake_net.ifaces[1].mac, mon, 6);
    g_fake_net.ifaces[1].mode = IFACE_MODE_MONITOR;
    g_fake_net.iface_count = 2;

    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    poll_tick(&g_poll_wifi, &s, &ctx);
    ASSERT_EQ(ownership_is_self_mac(eth), 1);
    ASSERT_EQ(ownership_is_self_mac(mon), 1);
    ASSERT_EQ(ownership_self_count(), 2);
    /* An address the host does not have stays a stranger. */
    const uint8_t other[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
    ASSERT_EQ(ownership_is_self_mac(other), 0);
    ownership_clear();
    fake_net_reset();
}

/* ── the stage table is data (#212) ───────────────────────── */

/* The runner runs what it is handed, in order, and nothing else: a
 * table of the test's own, with no stage from any shipped table. */
static char g_trace[16];
static void trace_a(sloth_state_t *s, const poll_ctx_t *c) {
    (void)s; (void)c; strncat(g_trace, "a", sizeof(g_trace) - strlen(g_trace) - 1);
}
static void trace_b(sloth_state_t *s, const poll_ctx_t *c) {
    (void)s; (void)c; strncat(g_trace, "b", sizeof(g_trace) - strlen(g_trace) - 1);
}
static void test_runner_runs_the_table_it_is_given(void) {
    static const poll_stage_t st[] = {
        { "first",  PH_PLATFORM, trace_b },
        { "second", PH_DERIVE,   trace_a },
        { "third",  PH_EMIT,     trace_b },
    };
    const poll_table_t t = { st, 3 };
    TEST_STATE(s);
    memset(&s, 0, sizeof(s));
    fake_net_reset();
    snprintf(g_fake_net.ifaces[0].name, sizeof(g_fake_net.ifaces[0].name), "eth0");
    g_fake_net.iface_count = 1;
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    g_trace[0] = '\0';
    poll_tick(&t, &s, &ctx);
    ASSERT_STR(g_trace, "bab");
    /* No stage of sloth's ran: the platform was never read. */
    ASSERT_EQ(s.iface_count, 0);
    ASSERT_EQ(poll_stage_index(&t, "second"), 1);
    ASSERT_EQ(poll_stage_index(&t, "alerts"), -1);
    /* A missing table, state or context is a no-op, not a crash. */
    poll_tick(NULL, &s, &ctx);
    poll_tick(&t, NULL, &ctx);
    poll_tick(&t, &s, NULL);
    ASSERT_STR(g_trace, "bab");
    fake_net_reset();
}

/* What sloth-wifi runs, stage for stage. It is the table the one binary
 * ran before the split with exactly two stages gone at the cutover
 * (#216): health_rf, which stood between health_gnss and health_host,
 * and sensors_rf, between sensors_gnss and twins. Nothing else moved.
 * Spelled out rather than derived: this list IS the order, and a diff
 * to it is a change someone has to mean. */
static void test_wifi_table_is_the_order_sloth_always_ran(void) {
    static const struct { const char *name; poll_phase_t phase; } want[] = {
        { "platform_net",      PH_PLATFORM },
        { "health_capture",    PH_PLATFORM },
        { "health_gnss",       PH_PLATFORM },
        { "health_host",       PH_PLATFORM },
        { "capture_scope",     PH_PLATFORM },
        { "stats_baseline",    PH_PLATFORM },
        { "capture_ring",      PH_SNAPSHOT },
#ifdef WITH_PCAP
        { "wifi_snapshots",    PH_SNAPSHOT },
        { "wired_snapshots",   PH_SNAPSHOT },
#endif
        { "eap_track",         PH_SNAPSHOT },
        { "ble",               PH_SNAPSHOT },
        { "history_bw",        PH_DERIVE   },
#ifdef WITH_PCAP
        { "channel_rf",        PH_DERIVE   },
#endif
        { "scan",              PH_DERIVE   },
        { "beacon_detect",     PH_DERIVE   },
#ifdef WITH_PCAP
        { "transit",           PH_DERIVE   },
#endif
        { "sensors_wifi",      PH_DERIVE   },
        { "sensors_gnss",      PH_DERIVE   },
        { "twins",             PH_DERIVE   },
        { "alerts",            PH_ALERTS   },
        { "research_coverage", PH_POST     },
        { "karma",             PH_POST     },
        { "alert_hot",         PH_POST     },
        { "devices_hosts",     PH_POST     },
        { "positions",         PH_POST     },
        { "chanhop",           PH_POST     },
        { "coverage_iv",       PH_POST     },
        { "jsonl",             PH_EMIT     },
        { "db",                PH_DURABLE  },
    };
    int n = (int)(sizeof(want) / sizeof(want[0]));
    ASSERT_EQ(g_poll_wifi.count, n);
    for (int i = 0; i < n && i < g_poll_wifi.count; i++) {
        ASSERT_STR(g_poll_wifi.stages[i].name, want[i].name);
        ASSERT_EQ(g_poll_wifi.stages[i].phase, want[i].phase);
    }
}

static int table_has(const poll_table_t *t, const char *name) {
    return poll_stage_index(t, name) >= 0;
}

/* The two tables against each other (#216). sloth-wifi's has no RF
 * stage; sloth-rf's is exactly its nine, so a capture stage cannot ride
 * in unnoticed ("positions" joined on the ruling that both daemons
 * write the sensor's track). The stages both carry are one body, one
 * phase and the same relative order in each - the receiver's two, the
 * host's status, the engine, the track and the database - except
 * "jsonl", which is each daemon's own emitter under one name.
 *
 * Seen red (2026-11-15): with health_rf put back in wifi_stages[] the
 * first two assertions fail; with sensors_rf, the second pair. */
static void test_tables_share_only_what_both_daemons_run(void) {
    ASSERT(!table_has(&g_poll_wifi, "health_rf"));
    for (int i = 0; i < g_poll_wifi.count; i++)
        ASSERT(g_poll_wifi.stages[i].fn != poll_st_health_rf);
    ASSERT(!table_has(&g_poll_wifi, "sensors_rf"));
    for (int i = 0; i < g_poll_wifi.count; i++)
        ASSERT(g_poll_wifi.stages[i].fn != poll_st_sensors_rf);
    for (int i = 0; i < g_poll_wifi.count; i++)
        ASSERT(g_poll_wifi.stages[i].fn != poll_st_jsonl_rf);

    static const char *const rf[] = {
        "health_gnss", "health_rf", "health_host",
        "sensors_gnss", "sensors_rf", "alerts", "positions", "jsonl", "db"
    };
    int n = (int)(sizeof(rf) / sizeof(rf[0]));
    ASSERT_EQ(g_poll_rf.count, n);
    for (int i = 0; i < n && i < g_poll_rf.count; i++)
        ASSERT_STR(g_poll_rf.stages[i].name, rf[i]);

    static const char *const shared[] = {
        "health_gnss", "health_host", "sensors_gnss", "alerts",
        "positions", "jsonl", "db"
    };
    int nshared = 0, last_w = -1, last_r = -1, own = 0;
    for (int i = 0; i < g_poll_rf.count; i++) {
        const poll_stage_t *r = &g_poll_rf.stages[i];
        int w = poll_stage_index(&g_poll_wifi, r->name);
        if (w < 0) continue;
        ASSERT(nshared < 7);
        if (nshared < 7) ASSERT_STR(r->name, shared[nshared]);
        nshared++;
        ASSERT_EQ(g_poll_wifi.stages[w].phase, r->phase);
        ASSERT_GT(w, last_w);
        ASSERT_GT(i, last_r);
        last_w = w; last_r = i;
        if (g_poll_wifi.stages[w].fn != r->fn) {
            own++;
            ASSERT_STR(r->name, "jsonl");
        }
    }
    ASSERT_EQ(nshared, 7);
    ASSERT_EQ(own, 1);
    int j = poll_stage_index(&g_poll_rf, "jsonl");
    ASSERT(j >= 0 && g_poll_rf.stages[j].fn == poll_st_jsonl_rf);
    j = poll_stage_index(&g_poll_wifi, "jsonl");
    ASSERT(j >= 0 && g_poll_wifi.stages[j].fn == poll_st_jsonl);
    ASSERT(poll_st_jsonl_rf != poll_st_jsonl);
}

/* The two orders poll.h calls part of the contract, in every table that
 * has the stages: the receiver before the decoders (the APRS region
 * check reads s->gps) and both before the host's own status (which
 * reads every source); and radios, receiver, decoders for the registry,
 * because a sensor's id is its slot. */
static void test_contract_orders_hold_in_every_table(void) {
    static const char *const health[]  = { "health_capture", "health_gnss",
                                           "health_rf", "health_host" };
    static const char *const sensors[] = { "sensors_wifi", "sensors_gnss",
                                           "sensors_rf" };
    for (int k = 0; k < TABLE_COUNT; k++) {
        const poll_table_t *t = g_tables[k];
        int last = -1;
        for (int i = 0; i < 4; i++) {
            int at = poll_stage_index(t, health[i]);
            if (at < 0) continue;
            ASSERT_GT(at, last);
            last = at;
        }
        ASSERT_GE(poll_stage_index(t, "health_host"), 0);
        ASSERT_GE(poll_stage_index(t, "health_gnss"), 0);
        last = -1;
        for (int i = 0; i < 3; i++) {
            int at = poll_stage_index(t, sensors[i]);
            if (at < 0) continue;
            ASSERT_GT(at, last);
            last = at;
        }
        ASSERT_GE(poll_stage_index(t, "sensors_gnss"), 0);
    }
}

/* Every source sloth can register, configured at once: a monitor radio
 * and a Bluetooth controller (state members main.c sets), the Ubertooth
 * stream, a receiver and the three decoders (module state the health
 * and snapshot stages copy in). */
#define POLL_WIFI_IFACE  "wlan9mon"
#define POLL_BT_IFACE    "hci9"
#define POLL_GPS_LABEL   "gpsd:192.0.2.7:2947"
#define POLL_ADSB_LABEL  "file:/run/test/aircraft.json"
#define POLL_APRS_LABEL  "file:/run/test/aprs.log"
#define POLL_RTL_LABEL   "file:/run/test/events.jsonl"

static void configure_every_source(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    sloth_reset_all();
    fake_net_reset();
    snprintf(g_fake_net.ifaces[0].name, sizeof(g_fake_net.ifaces[0].name), "eth0");
    g_fake_net.iface_count = 1;
    snprintf(s->probe_iface, sizeof(s->probe_iface), POLL_WIFI_IFACE);
    snprintf(s->bt_iface, sizeof(s->bt_iface), POLL_BT_IFACE);
    bt_stream_configure();
    gps_location_set_gps(POLL_GPS_LABEL);
    adsb_set_source(POLL_ADSB_LABEL);
    aprs_set_source(POLL_APRS_LABEL);
    rtl433_set_source(POLL_RTL_LABEL);
}

static void sources_done(void) {
    sloth_reset_all();
    fake_net_reset();
}

static int count_kind(const sloth_state_t *s, int kind) {
    int n = 0;
    for (int i = 0; i < s->sensor_count; i++)
        if (s->sensors[i].kind == kind) n++;
    return n;
}

/* The sensor id is the registry slot, and wifi_merged publishes it
 * (sensor_mask, best_sensor), so the slot order is part of the stream.
 * With everything configured sloth-wifi gives each of its sources the
 * slot the single st_sensors() gave it: radio 0, HCI 1, Ubertooth 2,
 * receiver 3. The decoders took 4, 5 and 6 there until the cutover
 * (#216); they are sloth-rf's now, from its own slot 1 (the next test).
 * A second tick moves nothing. */
static void test_wifi_sensor_slots_are_unchanged(void) {
    TEST_STATE(s);
    configure_every_source(&s);
    static const struct { int kind; const char *iface; } want[] = {
        { SENSOR_WIFI,   POLL_WIFI_IFACE  },
        { SENSOR_BLE,    POLL_BT_IFACE    },
        { SENSOR_BLE,    BT_CAPTURE_IFACE },
        { SENSOR_GPS,    POLL_GPS_LABEL   },
    };
    for (int pass = 0; pass < 2; pass++) {
        tick_once(&s);
        ASSERT_EQ(s.sensor_count, 4);
        for (int i = 0; i < 4 && i < s.sensor_count; i++) {
            ASSERT_EQ(s.sensors[i].kind, want[i].kind);
            ASSERT_STR(s.sensors[i].iface, want[i].iface);
        }
    }
    sources_done();
}

/* The RF half alone, on a host with no capture at all: the receiver and
 * the decoders register from slot 0, the alert engine and both sinks'
 * stages run, and nothing of the capture side does - although the state
 * names a monitor radio and a Bluetooth controller and the platform has
 * an interface to report. (Each "nothing" below was seen red with the
 * platform_net, stats_baseline, ble and sensors_wifi stages added to
 * the RF table.) */
static void test_rf_half_runs_alone_without_capture(void) {
    TEST_STATE(s);
    rf_profile_select();
    configure_every_source(&s);
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    sink_open();
    poll_tick(&g_poll_rf, &s, &ctx);
    const char *out = sink_read();

    ASSERT_EQ(s.sensor_count, 4);
    static const int want[] = { SENSOR_GPS, SENSOR_ADSB, SENSOR_APRS, SENSOR_RTL433 };
    for (int i = 0; i < 4 && i < s.sensor_count; i++)
        ASSERT_EQ(s.sensors[i].kind, want[i]);
    /* The health stages ran: the module state is in s. */
    ASSERT_EQ(s.gps.has_gps, 1);
    ASSERT_EQ(s.adsb.configured, 1);
    ASSERT_EQ(s.aprs.configured, 1);
    ASSERT_EQ(s.rtl433.configured, 1);
    /* The EMIT stage ran, and health_host fed it. */
    ASSERT(strstr(out, "\"type\":\"sensor_health\"") != NULL);
    ASSERT(strstr(out, "\"type\":\"sys_status\"") != NULL);
    ASSERT(strstr(out, POLL_ADSB_LABEL) != NULL);

    /* No capture-side stage. */
    ASSERT_EQ(count_kind(&s, SENSOR_WIFI), 0);
    ASSERT_EQ(count_kind(&s, SENSOR_BLE), 0);
    ASSERT_EQ(s.iface_count, 0);          /* platform_net did not run */
    ASSERT_EQ(s.stats_init, 0);           /* nor stats_baseline */
    ASSERT_EQ(s.btcap.configured, 0);     /* nor the BLE snapshot */
    /* The sensor record, by its name: sensor_health states the
     * configured monitor interface whichever stages run. */
    ASSERT(strstr(out, "\"name\":\"Wi-Fi monitor\"") == NULL);
    ASSERT(strstr(out, "\"name\":\"GNSS receiver\"") != NULL);
    sources_done();
}

/* The Wi-Fi half alone, on a host whose decoders are configured: it
 * registers the radios and the receiver - the radio still slot 0, the
 * receiver straight after the radios - and never polls or registers a
 * decoder. (Seen red with health_rf and sensors_rf added to the Wi-Fi
 * table.) */
static void test_wifi_half_runs_alone_without_rf(void) {
    TEST_STATE(s);
    configure_every_source(&s);
    poll_ctx_t ctx;
    poll_ctx_init(&ctx);
    sink_open();
    poll_tick(&g_poll_wifi, &s, &ctx);
    const char *out = sink_read();

    ASSERT_EQ(s.sensor_count, 4);
    static const int want[] = { SENSOR_WIFI, SENSOR_BLE, SENSOR_BLE, SENSOR_GPS };
    for (int i = 0; i < 4 && i < s.sensor_count; i++)
        ASSERT_EQ(s.sensors[i].kind, want[i]);
    ASSERT_EQ(s.iface_count, 1);          /* the platform was read */
    ASSERT_EQ(s.stats_init, 1);
    ASSERT_EQ(s.gps.has_gps, 1);          /* the shared receiver stage ran */
    ASSERT(strstr(out, "\"type\":\"sensor_health\"") != NULL);

    /* No RF stage. */
    ASSERT_EQ(count_kind(&s, SENSOR_ADSB), 0);
    ASSERT_EQ(count_kind(&s, SENSOR_APRS), 0);
    ASSERT_EQ(count_kind(&s, SENSOR_RTL433), 0);
    ASSERT_EQ(s.adsb.configured, 0);      /* health_rf did not run */
    ASSERT_EQ(s.aprs.configured, 0);
    ASSERT_EQ(s.rtl433.configured, 0);
    ASSERT(strstr(out, "\"name\":\"ADS-B decoder\"") == NULL);
    ASSERT(strstr(out, POLL_ADSB_LABEL) == NULL);
    ASSERT(strstr(out, "\"name\":\"Wi-Fi monitor\"") != NULL);
    sources_done();
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
    RUN_TEST(test_tick_rosters_the_hosts_own_iface_macs);

    TEST_SUITE("poll stage tables: sloth-wifi's and sloth-rf's (#212, #216)");
    RUN_TEST(test_runner_runs_the_table_it_is_given);
    RUN_TEST(test_wifi_table_is_the_order_sloth_always_ran);
    RUN_TEST(test_tables_share_only_what_both_daemons_run);
    RUN_TEST(test_contract_orders_hold_in_every_table);
    RUN_TEST(test_wifi_sensor_slots_are_unchanged);
    RUN_TEST(test_rf_half_runs_alone_without_capture);
    RUN_TEST(test_wifi_half_runs_alone_without_rf);
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
    const uint8_t a[6] = {0xa8, 0xbb, 0xcc, 0x01, 0x02, 0x03};
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

/* What the slot order is for: wifi_merged publishes the radio's sensor
 * id. With every other source configured beside it the merged entry
 * still names sensor 0, bit 0 (#212). */
static void test_wifi_merged_publishes_the_radio_as_sensor_0(void) {
    const poll_table_t *both[] = { &g_poll_wifi };
    for (int k = 0; k < 1; k++) {
        pcap_case_reset();
        TEST_STATE(s);
        configure_every_source(&s);
        const uint8_t a[6] = {0x02, 0x31, 0x32, 0x33, 0x34, 0x35};
        beacon_record(a, "Slot-Seed", -47, 1, "WPA2", 102, NULL);
        poll_ctx_t ctx;
        poll_ctx_init(&ctx);
        poll_tick(both[k], &s, &ctx);
        ASSERT_EQ(s.beacon_count, 1);
        ASSERT_EQ(s.wifi_merged.count, 1);
        if (s.wifi_merged.count == 1) {
            ASSERT_EQ(s.wifi_merged.ents[0].best_sensor, 0);
            ASSERT_EQ(s.wifi_merged.ents[0].sensor_mask, 1u);
        }
        ASSERT_EQ(s.sensors[0].kind, SENSOR_WIFI);
        sources_done();
    }
    pcap_case_reset();
}

void run_poll_capture_path_tests(void) {
    TEST_SUITE("poll_tick end to end, WITH_PCAP stages (#113)");
    RUN_TEST(test_transit_alert_fires_same_tick);
    RUN_TEST(test_twin_episode_sees_this_ticks_beacons);
    RUN_TEST(test_jsonl_state_emitted_after_snapshot);
    RUN_TEST(test_channel_summary_sees_this_ticks_beacons);
    RUN_TEST(test_wifi_merged_publishes_the_radio_as_sensor_0);
}
#else
/* The no-flag build (sloth_test_noflags, #116) is link-only. */
void run_poll_capture_path_tests(void) {}
#endif
