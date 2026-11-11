#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "sloth_clock.h"
#include "fake_platform.h"
#include "sys_status.h"
#include "alerts/rules.h"

/*
 * SENSOR_UNDERVOLT and SENSOR_SOURCE_DOWN (src/alerts/rules_sensor.c).
 *
 * The under-voltage alarm is served through the fake platform's /sys
 * table, the hwmon files src/sys_status.c reads (Documentation/hwmon/
 * sysfs-interface: inN_lcrit_alarm, 0 or 1), so the rule reads the
 * snapshot sys_status_poll() builds from it. The sources are the state
 * fields src/sys_status.c's fill_sources() derives source_status from
 * (cap_health, mon_health, adsb, btcap), seeded by hand. Both clocks are
 * pinned; every tick runs the two hooks in the poll's order.
 *
 * Every absence assertion names the mutation it was seen red under
 * (agents/AGENTS.md).
 */

TEST_STATE(g_s);

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }

/* What the engine's incident hook saw, for the two kinds. */
static int  g_created[ALERT_TYPE_COUNT], g_resolved[ALERT_TYPE_COUNT];
static char g_last_reason[32];
static char g_last_key[ALERT_KEY_LEN];

static void hook(const alert_t *a, time_t now, const char *reason) {
    (void)now;
    if (a->type != ALERT_TYPE_SENSOR_UNDERVOLT &&
        a->type != ALERT_TYPE_SENSOR_SOURCE_DOWN) return;
    if (reason) {
        g_resolved[a->type]++;
        snprintf(g_last_reason, sizeof(g_last_reason), "%s", reason);
    } else if (a->event_seq == 1) {
        g_created[a->type]++;
        snprintf(g_last_key, sizeof(g_last_key), "%s", a->key);
    }
}

static void begin(void) {
    g_mono = 5000000;
    g_wall = (time_t)1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    fake_net_reset();
    sys_status_reset();
    alerts_clear();
    memset(&g_s, 0, sizeof(g_s));
    memset(g_created, 0, sizeof(g_created));
    memset(g_resolved, 0, sizeof(g_resolved));
    g_last_reason[0] = g_last_key[0] = '\0';
    alerts_set_incident_hook(hook);
}

static void end(void) {
    alerts_set_incident_hook(NULL);
    alerts_clear();
    fake_net_reset();
    sys_status_reset();
    sloth_clock_test_set(NULL, NULL);
}

/* One second on, the way the poll runs it: the health stage, then the
 * rules. */
static void tick(void) {
    g_mono += 1000;
    g_wall += 1;
    sys_status_poll(&g_s, g_wall, g_mono);
    alerts_update(&g_s);
}

static void ticks(int n) { for (int i = 0; i < n; i++) tick(); }

static const alert_t *open_of(alert_type_t ty, const char *key) {
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == ty && !g_s.alerts[i].resolved &&
            (!key || !strcmp(g_s.alerts[i].key, key)))
            return &g_s.alerts[i];
    return NULL;
}

static void put_pi_alarm(const char *v) {
    fake_sys_put("/sys/class/hwmon/hwmon1/name", "rpi_volt\n");
    fake_sys_put("/sys/class/hwmon/hwmon1/in0_lcrit_alarm", v);
}

/* ── SENSOR_UNDERVOLT ─────────────────────────────────────────────── */

/* The alarm reading 1 fires WARN on the first poll, naming the node and
 * the driver; reading 0 clears it once held SENSOR_RECOVER_S, not
 * before, with the reason `recovered`. */
static void test_undervolt_fires_and_clears(void) {
    begin();
    put_pi_alarm("1\n");
    tick();
    const alert_t *a = open_of(ALERT_TYPE_SENSOR_UNDERVOLT, "undervolt:host");
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->sev, ALERT_SEV_WARN);
        ASSERT(strstr(a->detail, "under-voltage alarm on hwmon1/in0 (rpi_volt)") != NULL);
        ASSERT_STR(a->technique, "");
    }
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_UNDERVOLT], 1);
    ticks(60);
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_UNDERVOLT], 1);

    put_pi_alarm("0\n");
    /* The next sample is within 10 s; then 120 s clear. At 100 s the
     * incident is still open (seen red with SENSOR_RECOVER_S at 0). */
    ticks(100);
    ASSERT(open_of(ALERT_TYPE_SENSOR_UNDERVOLT, NULL) != NULL);
    ASSERT_EQ(g_resolved[ALERT_TYPE_SENSOR_UNDERVOLT], 0);
    ticks(40);
    ASSERT(open_of(ALERT_TYPE_SENSOR_UNDERVOLT, NULL) == NULL);
    ASSERT_EQ(g_resolved[ALERT_TYPE_SENSOR_UNDERVOLT], 1);
    ASSERT_STR(g_last_reason, "recovered");
    end();
}

/* Two alarm nodes: the detail names the first and counts the other. */
static void test_undervolt_names_every_sensor(void) {
    begin();
    put_pi_alarm("1\n");
    fake_sys_put("/sys/class/hwmon/hwmon2/name", "ina219\n");
    fake_sys_put("/sys/class/hwmon/hwmon2/in1_input", "4610\n");
    fake_sys_put("/sys/class/hwmon/hwmon2/in1_lcrit_alarm", "1\n");
    tick();
    const alert_t *a = open_of(ALERT_TYPE_SENSOR_UNDERVOLT, NULL);
    ASSERT(a != NULL);
    if (a) ASSERT(strstr(a->detail, "hwmon1/in0 (rpi_volt), and 1 other sensor:") != NULL);
    end();
}

/* A supply toggling every 10 s for ten minutes is one incident, and it
 * closes only after the toggling stops. Seen red with hold_clear()
 * resolving at once. */
static void test_undervolt_flapping_is_one_incident(void) {
    begin();
    for (int k = 0; k < 60; k++) {
        put_pi_alarm(k % 2 ? "0\n" : "1\n");
        ticks(10);
    }
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_UNDERVOLT], 1);
    ASSERT_EQ(g_resolved[ALERT_TYPE_SENSOR_UNDERVOLT], 0);
    put_pi_alarm("0\n");
    ticks(140);
    ASSERT_EQ(g_resolved[ALERT_TYPE_SENSOR_UNDERVOLT], 1);
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_UNDERVOLT], 1);
    end();
}

/* Never fires: a host with no alarm node, and one whose alarm reads 0.
 * The 0 case was seen red with the `!sn->undervolt` test removed. The
 * no-node case cannot be isolated by mutating the rule: sys_status
 * zeroes `undervolt` with `has_undervolt`, so the rule without its
 * has_undervolt guard still reads 0 and stays quiet; the assertion
 * pins the snapshot's half (has_undervolt 0) instead. */
static void test_undervolt_quiet_without_alarm(void) {
    begin();
    fake_sys_put("/sys/class/hwmon/hwmon0/name", "cpu_thermal\n");
    fake_sys_put("/sys/class/hwmon/hwmon0/temp1_input", "48850\n");
    ticks(400);
    ASSERT_EQ(sys_status_get()->has_undervolt, 0);
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_UNDERVOLT], 0);
    put_pi_alarm("0\n");
    ticks(400);
    ASSERT_EQ(sys_status_get()->has_undervolt, 1);
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_UNDERVOLT], 0);
    end();
}

/* ── SENSOR_SOURCE_DOWN ───────────────────────────────────────────── */

/* A capture that never opened is down from the first poll: it opens
 * after SENSOR_SRC_DOWN_HOLD_S, not before, CRIT, keyed on the name.
 * The "not before" was seen red with the down hold set to 0. */
static void test_capture_down_at_startup(void) {
    begin();
    snprintf(g_s.pkt_iface, sizeof(g_s.pkt_iface), "eth0");
    g_s.pkt_linktype = 1;
    g_s.cap_health.open = 0;
    g_s.cap_health.stale_secs = -1;            /* never delivered */
    ticks(SENSOR_SRC_DOWN_HOLD_S - 1);
    ASSERT(open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, NULL) == NULL);
    tick();
    tick();
    const alert_t *a = open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, "srcdown:capture");
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->sev, ALERT_SEV_CRIT);
        ASSERT(strstr(a->detail, "configured source capture (ip-capture, eth0) is down: "
                                 "not open; last delivery never") != NULL);
        ASSERT_STR(a->technique, "");
    }
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_SOURCE_DOWN], 1);
    end();
}

/* The monitor radio is CRIT too; an ADS-B decoder in error is WARN. */
static void test_severity_by_source(void) {
    begin();
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "wlan1mon");
    g_s.mon_health.open = 1;
    g_s.mon_health.running = 0;
    g_s.mon_health.exit_reason = CAPTURE_EXIT_IFACE_GONE;
    g_s.adsb.configured = 1;
    snprintf(g_s.adsb.src, sizeof(g_s.adsb.src), "beast:127.0.0.1:30005");
    g_s.adsb.state = ADSB_ERROR;
    snprintf(g_s.adsb.err, sizeof(g_s.adsb.err), "connection refused");
    ticks(SENSOR_SRC_DOWN_HOLD_S + 1);
    const alert_t *m = open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, "srcdown:monitor");
    const alert_t *d = open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, "srcdown:adsb");
    ASSERT(m != NULL);
    ASSERT(d != NULL);
    if (m) ASSERT_EQ(m->sev, ALERT_SEV_CRIT);
    if (d) {
        ASSERT_EQ(d->sev, ALERT_SEV_WARN);
        ASSERT(strstr(d->detail, "error: connection refused") != NULL);
    }
    end();
}

/* Stale opens only after SENSOR_SRC_STALE_S without an `ok`. Seen red
 * with that span set to 0. */
static void test_stale_past_threshold(void) {
    begin();
    g_s.adsb.configured = 1;
    snprintf(g_s.adsb.src, sizeof(g_s.adsb.src), "beast:127.0.0.1:30005");
    g_s.adsb.state = ADSB_STALE;
    g_s.adsb.age_s = 90;
    ticks(SENSOR_SRC_STALE_S - 1);
    ASSERT(open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, NULL) == NULL);
    ticks(2);
    const alert_t *a = open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, "srcdown:adsb");
    ASSERT(a != NULL);
    if (a) {
        ASSERT_EQ(a->sev, ALERT_SEV_WARN);
        ASSERT(strstr(a->detail, "is stale:") != NULL);
    }
    end();
}

/* Recovery clears after SENSOR_RECOVER_S of `ok`, with `recovered`. */
static void test_recovery_clears(void) {
    begin();
    snprintf(g_s.pkt_iface, sizeof(g_s.pkt_iface), "eth0");
    g_s.cap_health.open = 1;
    g_s.cap_health.running = 0;
    g_s.cap_health.exit_reason = CAPTURE_EXIT_IFACE_GONE;
    ticks(30);
    ASSERT(open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, "srcdown:capture") != NULL);
    g_s.cap_health.running = 1;
    g_s.cap_health.exit_reason = CAPTURE_EXIT_NONE;
    g_s.cap_health.stale_secs = 1;
    ticks(SENSOR_RECOVER_S - 5);
    ASSERT(open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, "srcdown:capture") != NULL);
    ticks(10);
    ASSERT(open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, NULL) == NULL);
    ASSERT_EQ(g_resolved[ALERT_TYPE_SENSOR_SOURCE_DOWN], 1);
    ASSERT_STR(g_last_reason, "recovered");
    end();
}

/* An open incident is re-asserted in every state but `ok`, so down then
 * stale is one incident whose detail follows the state. Seen red (the
 * detail stayed "is down") with `!h->open` dropped from the condition
 * that skips a source. */
static void test_down_then_stale_is_one_incident(void) {
    begin();
    snprintf(g_s.pkt_iface, sizeof(g_s.pkt_iface), "eth0");
    g_s.cap_health.open = 1;
    g_s.cap_health.running = 0;
    g_s.cap_health.exit_reason = CAPTURE_EXIT_IFACE_GONE;
    ticks(20);
    g_s.cap_health.running = 1;
    g_s.cap_health.exit_reason = CAPTURE_EXIT_NONE;
    g_s.cap_health.stale_secs = -1;            /* reopened, no frame yet */
    ticks(30);
    const alert_t *a = open_of(ALERT_TYPE_SENSOR_SOURCE_DOWN, "srcdown:capture");
    ASSERT(a != NULL);
    if (a) ASSERT(strstr(a->detail, "is stale: no frame yet") != NULL);
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_SOURCE_DOWN], 1);
    end();
}

/* Down 15 s, ok 30 s, for ten minutes: one incident, closed once the
 * flapping stops. Seen red with hold_clear() resolving at once. */
static void test_flapping_source_is_one_incident(void) {
    begin();
    snprintf(g_s.pkt_iface, sizeof(g_s.pkt_iface), "eth0");
    g_s.cap_health.open = 1;
    for (int k = 0; k < 13; k++) {
        g_s.cap_health.running = 0;
        g_s.cap_health.exit_reason = CAPTURE_EXIT_IFACE_GONE;
        ticks(15);
        g_s.cap_health.running = 1;
        g_s.cap_health.exit_reason = CAPTURE_EXIT_NONE;
        g_s.cap_health.stale_secs = 1;
        ticks(30);
    }
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_SOURCE_DOWN], 1);
    ASSERT_EQ(g_resolved[ALERT_TYPE_SENSOR_SOURCE_DOWN], 0);
    ticks(SENSOR_RECOVER_S);
    ASSERT_EQ(g_resolved[ALERT_TYPE_SENSOR_SOURCE_DOWN], 1);
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_SOURCE_DOWN], 1);
    end();
}

/* A source the command line did not enable never fires, however its
 * reader's fields read. The bare state lists all seven not_configured.
 * Seen red with the not_configured branch removed (the rows then
 * opened once SENSOR_SRC_STALE_S had passed). */
static void test_not_configured_never_fires(void) {
    begin();
    g_s.btcap.state = BT_CAP_REFUSED;          /* configured = 0 */
    g_s.gps.configured = 1; g_s.gps.has_fixed = 1;   /* --location only */
    ticks(SENSOR_SRC_STALE_S + 60);
    for (int i = 0; i < SYS_SRC_COUNT; i++)
        ASSERT_EQ(sys_status_get()->src[i].state, SYS_ST_NOT_CONFIGURED);
    ASSERT_EQ(g_created[ALERT_TYPE_SENSOR_SOURCE_DOWN], 0);
    end();
}

void run_sensor_rules_tests(void) {
    TEST_SUITE("sensor own-state rules (SENSOR_UNDERVOLT, SENSOR_SOURCE_DOWN)");
    RUN_TEST(test_undervolt_fires_and_clears);
    RUN_TEST(test_undervolt_names_every_sensor);
    RUN_TEST(test_undervolt_flapping_is_one_incident);
    RUN_TEST(test_undervolt_quiet_without_alarm);
    RUN_TEST(test_capture_down_at_startup);
    RUN_TEST(test_severity_by_source);
    RUN_TEST(test_stale_past_threshold);
    RUN_TEST(test_recovery_clears);
    RUN_TEST(test_down_then_stale_is_one_incident);
    RUN_TEST(test_flapping_source_is_one_incident);
    RUN_TEST(test_not_configured_never_fires);
}
