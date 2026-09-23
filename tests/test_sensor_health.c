#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "sensor_health.h"
#include "probe_pnl.h"
#include "alerts.h"
#include "top_hosts.h"
#include "devices.h"

/* ── Table-overflow accounting — issue #91 slice 3 ──────────
 *
 * Every bounded table in sloth discards observations when it fills, and
 * until now did so invisibly: a sensor at max occupancy and a sensor on
 * a quiet segment produced the same empty delta. The tally is what makes
 * "not observing" separable from "nothing to observe".
 *
 * The first block is pure counter logic — no radio, no capture. The
 * second drives the real modules past their caps with hand-seeded state,
 * because a counter nobody calls reads as a permanently healthy sensor. */

static void test_tally_starts_at_zero(void) {
    sh_evict_reset();
    ASSERT_EQ((int)sh_evict_total(), 0);
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++)
        ASSERT_EQ((int)sh_evict_count((sh_evict_t)k), 0);
}

static void test_tally_counts_per_kind(void) {
    sh_evict_reset();
    sh_evict_note(SH_EVICT_ALERT);
    sh_evict_note(SH_EVICT_ALERT);
    sh_evict_note(SH_EVICT_PNL_SSID);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_ALERT),    2);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_SSID), 1);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_TOP_HOST), 0);
    ASSERT_EQ((int)sh_evict_total(),                  3);
}

static void test_tally_is_monotonic(void) {
    /* Lifetime, never decremented: a counter that clears has no meaning
     * to a consumer sampling it twice. */
    sh_evict_reset();
    for (int i = 0; i < 100; i++) sh_evict_note(SH_EVICT_DEVICE);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_DEVICE), 100);
    sh_evict_note(SH_EVICT_DEVICE);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_DEVICE), 101);
}

static void test_tally_ignores_out_of_range_kinds(void) {
    sh_evict_reset();
    sh_evict_note((sh_evict_t)SH_EVICT_KIND_COUNT);
    sh_evict_note((sh_evict_t)-1);
    sh_evict_note((sh_evict_t)9999);
    ASSERT_EQ((int)sh_evict_total(), 0);
    ASSERT_EQ((int)sh_evict_count((sh_evict_t)-1), 0);
}

static void test_evict_names_are_stable_and_distinct(void) {
    /* Part of the `sensor_health` JSONL contract. */
    ASSERT_STR(sh_evict_name(SH_EVICT_ALERT),       "alert");
    ASSERT_STR(sh_evict_name(SH_EVICT_TOP_HOST),    "top_host");
    ASSERT_STR(sh_evict_name(SH_EVICT_PNL_CLIENT),  "pnl_client");
    ASSERT_STR(sh_evict_name(SH_EVICT_PNL_SSID),    "pnl_ssid");
    ASSERT_STR(sh_evict_name(SH_EVICT_DHCP_EVENT),  "dhcp_event");
    ASSERT_STR(sh_evict_name(SH_EVICT_EAP_SESSION), "eap_session");
    ASSERT_STR(sh_evict_name(SH_EVICT_DEVICE),      "device");
    ASSERT_STR(sh_evict_name((sh_evict_t)SH_EVICT_KIND_COUNT), "");
    /* Every kind must have a name — an unnamed bucket emits "" into the
     * record, which a consumer reads as a missing field. */
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++)
        ASSERT(sh_evict_name((sh_evict_t)k)[0] != '\0');
}

/* ── wiring: real tables must reach the tally ─────────────── */

static void test_pnl_ssid_overflow_is_counted(void) {
    /* MAX_PNL_SSIDS_PER_CLI SSIDs fit; the next shifts the oldest out. */
    probe_pnl_clear();
    sh_evict_reset();
    uint8_t mac[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    char ssid[40];
    for (int i = 0; i < MAX_PNL_SSIDS_PER_CLI; i++) {
        snprintf(ssid, sizeof(ssid), "net-%d", i);
        probe_pnl_observe(mac, ssid, "", "");
    }
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_SSID), 0);   /* still fits */
    probe_pnl_observe(mac, "one-too-many", "", "");
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_SSID), 1);
    probe_pnl_clear();
}

static void test_pnl_client_overflow_is_counted(void) {
    probe_pnl_clear();
    sh_evict_reset();
    uint8_t mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    for (int i = 0; i < MAX_PNL_CLIENTS; i++) {
        mac[4] = (uint8_t)((i >> 8) & 0xff);
        mac[5] = (uint8_t)(i & 0xff);
        probe_pnl_observe(mac, "shared-ssid", "", "");
    }
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_CLIENT), 0);
    mac[3] = 0xff; mac[4] = 0xff; mac[5] = 0xff;
    probe_pnl_observe(mac, "shared-ssid", "", "");
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PNL_CLIENT), 1);
    probe_pnl_clear();
}

static void test_top_host_overflow_is_counted(void) {
    /* Public addresses only — the table ignores private, loopback,
     * link-local and multicast, so 10.x would never reach the cap. */
    top_hosts_clear();
    sh_evict_reset();
    sloth_state_t *s = calloc(1, sizeof(*s));
    ASSERT(s != NULL);
    if (!s) return;
    int n = 200;   /* comfortably past the internal TOP_HOSTS_CAP */
    for (int i = 0; i < n; i++) {
        conn_t *c = &s->conns[i];
        snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.2");
        snprintf(c->remote_addr, sizeof(c->remote_addr), "8.%d.%d.%d",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        c->remote_port = 443;
        c->proto       = 6;
    }
    s->conn_count = n;
    top_hosts_update(s);
    ASSERT_GT((int)sh_evict_count(SH_EVICT_TOP_HOST), 0);
    top_hosts_clear();
    free(s);
}

static void test_device_table_refusal_is_counted(void) {
    /* devices.c refuses a NEW device when full rather than evicting one.
     * Different mechanism, same sensor-health meaning: an observation did
     * not make it into the table. ARP alone fills it exactly, so the
     * beacons behind it are what get refused. */
    sloth_state_t *s = calloc(1, sizeof(*s));
    ASSERT(s != NULL);
    if (!s) return;
    sh_evict_reset();
    for (int i = 0; i < MAX_ARP_ENTRIES; i++) {
        arp_entry_t *a = &s->arp_entries[i];
        snprintf(a->ip, sizeof(a->ip), "10.%d.%d.%d",
                 (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
        a->mac[0] = 0x02;
        a->mac[4] = (uint8_t)((i >> 8) & 0xff);
        a->mac[5] = (uint8_t)(i & 0xff);
        snprintf(a->iface, sizeof(a->iface), "eth0");
    }
    s->arp_count = MAX_ARP_ENTRIES;
    for (int i = 0; i < 4; i++) {
        beacon_ap_t *b = &s->beacon_aps[i];
        b->bssid[0] = 0x06;            /* distinct from every ARP MAC above */
        b->bssid[5] = (uint8_t)i;
        snprintf(b->ssid, sizeof(b->ssid), "ap-%d", i);
        b->channel = 6;
    }
    s->beacon_count = 4;
    devices_update(s);
    ASSERT_EQ(s->device_count, MAX_DEVICES);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_DEVICE), 4);
    free(s);
}

static void test_alert_overflow_is_counted(void) {
    /* More distinct weak-TLS sources than MAX_ALERTS holds; each fires
     * its own dedup key, so the engine must start evicting. */
    alerts_clear();
    sh_evict_reset();
    sloth_state_t *s = calloc(1, sizeof(*s));
    ASSERT(s != NULL);
    if (!s) return;
    for (int i = 0; i < MAX_TLS_LOG; i++) {
        tls_log_entry_t *e = &s->tls_log[i];
        snprintf(e->src,     sizeof(e->src),     "203.0.%d.%d",
                 (i >> 8) & 0xff, i & 0xff);
        snprintf(e->dst,     sizeof(e->dst),     "198.51.100.1");
        snprintf(e->tls_ver, sizeof(e->tls_ver), "TLS 1.0");
        e->ts = 1700000000;
    }
    s->tls_log_count = MAX_TLS_LOG;
    alerts_update(s);
    ASSERT_GT((int)sh_evict_count(SH_EVICT_ALERT), 0);
    alerts_clear();
    free(s);
}

void run_sensor_health_tests(void) {
    TEST_SUITE("sensor health — table-overflow tally (#91 slice 3)");
    RUN_TEST(test_tally_starts_at_zero);
    RUN_TEST(test_tally_counts_per_kind);
    RUN_TEST(test_tally_is_monotonic);
    RUN_TEST(test_tally_ignores_out_of_range_kinds);
    RUN_TEST(test_evict_names_are_stable_and_distinct);

    TEST_SUITE("sensor health — eviction sites reach the tally (#91 slice 3)");
    RUN_TEST(test_pnl_ssid_overflow_is_counted);
    RUN_TEST(test_pnl_client_overflow_is_counted);
    RUN_TEST(test_top_host_overflow_is_counted);
    RUN_TEST(test_device_table_refusal_is_counted);
    RUN_TEST(test_alert_overflow_is_counted);

    sh_evict_reset();   /* leave the tally clean for later suites */
}
