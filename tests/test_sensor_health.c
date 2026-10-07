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
#include "beacon_snoop.h"
#include "seqnum_track.h"
#include "assoc_track.h"

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

/* Read a whole text file; the doc-pin test compares prose to the
 * compiled enum. Path is repo-root relative, as elsewhere in the suite. */
static char *slurp_text(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

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
    ASSERT_STR(sh_evict_name(SH_EVICT_BEACON_AP),     "beacon_ap");
    ASSERT_STR(sh_evict_name(SH_EVICT_SEQNUM_CLIENT), "seqnum_client");
    ASSERT_STR(sh_evict_name(SH_EVICT_ASSOC_PAIR),    "assoc_pair");
    ASSERT_STR(sh_evict_name(SH_EVICT_ASSOC_REQ),     "assoc_req");
    ASSERT_STR(sh_evict_name(SH_EVICT_WPS_SESSION),   "wps_session");
    ASSERT_STR(sh_evict_name(SH_EVICT_EVIDENCE_FRAME), "evidence_frame");
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

/* ââ wiring: beacon / seqnum / assoc tables (#91 wave 6) âââ */

static void test_beacon_table_overflow_is_counted(void) {
    beacon_clear();
    sh_evict_reset();
    uint8_t bssid[6] = {0x02, 0, 0, 0, 0, 0};
    for (int i = 0; i < MAX_BEACON_APS + 3; i++) {
        bssid[4] = (uint8_t)(i >> 8);
        bssid[5] = (uint8_t)i;
        beacon_record(bssid, "net", -40, 6, "wpa2", 100, NULL);
    }
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_BEACON_AP), 3);
    /* Updating a known AP must not evict. */
    beacon_record(bssid, "net", -40, 6, "wpa2", 100, NULL);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_BEACON_AP), 3);
    beacon_clear();
    sh_evict_reset();
}

static void test_seqnum_table_overflow_is_counted(void) {
    seqnum_clear();
    sh_evict_reset();
    uint8_t mac[6] = {0x02, 1, 0, 0, 0, 0};
    for (int i = 0; i < MAX_SEQNUM_CLIENTS + 2; i++) {
        mac[4] = (uint8_t)(i >> 8);
        mac[5] = (uint8_t)i;
        seqnum_track_observe_at(mac, (uint16_t)i, (time_t)(1000 + i));
    }
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_SEQNUM_CLIENT), 2);
    seqnum_track_observe_at(mac, 9, (time_t)9999);   /* known: no evict */
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_SEQNUM_CLIENT), 2);
    seqnum_clear();
    sh_evict_reset();
}

static void test_assoc_tables_overflow_is_counted(void) {
    assoc_clear();
    sh_evict_reset();
    uint8_t bssid[6] = {0x02, 2, 0, 0, 0, 0};
    uint8_t sta[6]   = {0x02, 3, 0, 0, 0, 0};
    for (int i = 0; i < MAX_ASSOC_ENTRIES + 4; i++) {
        sta[4] = (uint8_t)(i >> 8);
        sta[5] = (uint8_t)i;
        assoc_observe(bssid, sta, "net", 0, -40, 6);
    }
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_ASSOC_PAIR), 4);
    /* Re-observing a resident pair must not evict. */
    assoc_observe(bssid, sta, "net", 0, -40, 6);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_ASSOC_PAIR), 4);
    assoc_clear();
    sh_evict_reset();
}

static void test_assoc_request_table_overflow_is_counted(void) {
    assoc_clear();
    sh_evict_reset();
    assoc_req_t req;
    memset(&req, 0, sizeof(req));
    req.bssid[0] = 0x02;
    req.sta[0]   = 0x02;
    for (int i = 0; i < MAX_ASSOC_ENTRIES + 2; i++) {
        req.sta[4] = (uint8_t)(i >> 8);
        req.sta[5] = (uint8_t)i;
        req.ts     = (time_t)(1000 + i);
        assoc_request_observe(&req, -40, 6);
    }
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_ASSOC_REQ), 2);
    assoc_clear();
    sh_evict_reset();
}

/* The schema doc tells an operator which quiet tables are trustworthy
 * silence and which are unmeasured, so its counted list is part of the
 * contract — and it went stale the moment the 802.11 tables joined the
 * tally, because nobody re-read the prose. Pin it: every kind the build
 * counts must appear in the doc's counted list, so adding a kind without
 * documenting it fails here instead of misleading a consumer. */
static void test_schema_doc_lists_every_counted_table(void) {
    char *doc = slurp_text("docs/wiki/jsonl-schema.md");
    ASSERT(doc != NULL);
    if (!doc) return;

    /* Parse the one delimited list rather than searching the section.
     * The looser form this replaces — substring anywhere between the
     * heading and "**Not** counted:" — was shown in review to pass with
     * `wps_session` deleted from the authoritative list, because the
     * name also occurs in the prose that follows it inside the same
     * bounds. Exact set comparison, both directions. */
    const char *start = strstr(doc, "and this is the whole set:");
    ASSERT(start != NULL);
    if (!start) { free(doc); return; }
    start += strlen("and this is the whole set:");
    const char *end = strstr(start, ". ");
    ASSERT(end != NULL);
    if (!end) { free(doc); return; }

    /* Every backticked token in that span is a claimed counted kind. */
    int seen[SH_EVICT_KIND_COUNT];
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) seen[k] = 0;
    int doc_names = 0, unknown = 0;
    for (const char *q = start; q < end; ) {
        const char *a = memchr(q, '`', (size_t)(end - q));
        if (!a) break;
        const char *b = memchr(a + 1, '`', (size_t)(end - a - 1));
        if (!b) break;
        size_t nlen = (size_t)(b - a - 1);
        doc_names++;
        int matched = 0;
        for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) {
            const char *nm = sh_evict_name((sh_evict_t)k);
            if (strlen(nm) == nlen && strncmp(nm, a + 1, nlen) == 0) {
                seen[k] = 1; matched = 1; break;
            }
        }
        if (!matched) {
            unknown++;
            fprintf(stderr, "    jsonl-schema.md counts `%.*s`, which is "
                            "not an sh_evict_t kind\n", (int)nlen, a + 1);
        }
        q = b + 1;
    }

    /* doc subset of enum: a stale or invented name is a false coverage
       claim, which is the failure this prose exists to prevent. */
    ASSERT_EQ(unknown, 0);
    /* enum subset of doc: adding a kind without documenting it would
       otherwise mislead a consumer reading the list as complete. */
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) {
        if (!seen[k])
            fprintf(stderr, "    sh_evict_t counts %s; jsonl-schema.md's "
                            "list omits it\n", sh_evict_name((sh_evict_t)k));
        ASSERT(seen[k]);
    }
    /* The list is exactly the enum, not a superset that happens to
       contain it. */
    ASSERT_EQ(doc_names, (int)SH_EVICT_KIND_COUNT);

    /* The uncounted side must name a live example and refuse to read as
     * full coverage: prose listing only what is counted implies the rest
     * is loss-free. */
    ASSERT(strstr(end, "probe_client") != NULL);
    ASSERT(strstr(end, "not \"all loss\"") != NULL);
    free(doc);
}

void run_sensor_health_tests(void) {
    TEST_SUITE("sensor health — table-overflow tally (#91 slice 3)");
    RUN_TEST(test_tally_starts_at_zero);
    RUN_TEST(test_tally_counts_per_kind);
    RUN_TEST(test_tally_is_monotonic);
    RUN_TEST(test_tally_ignores_out_of_range_kinds);
    RUN_TEST(test_evict_names_are_stable_and_distinct);
    RUN_TEST(test_schema_doc_lists_every_counted_table);

    TEST_SUITE("sensor health — eviction sites reach the tally (#91 slice 3)");
    RUN_TEST(test_pnl_ssid_overflow_is_counted);
    RUN_TEST(test_pnl_client_overflow_is_counted);
    RUN_TEST(test_top_host_overflow_is_counted);
    RUN_TEST(test_device_table_refusal_is_counted);
    RUN_TEST(test_beacon_table_overflow_is_counted);
    RUN_TEST(test_seqnum_table_overflow_is_counted);
    RUN_TEST(test_assoc_tables_overflow_is_counted);
    RUN_TEST(test_assoc_request_table_overflow_is_counted);
    RUN_TEST(test_alert_overflow_is_counted);

    sh_evict_reset();   /* leave the tally clean for later suites */
}
