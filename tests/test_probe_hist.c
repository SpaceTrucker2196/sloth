/* Directed-probe history (src/probe_hist.h): the per-(MAC, SSID,
 * 10-minute bucket) counter the --db writer drains into probe_history. */
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "probe_hist.h"
#include "probe_pnl.h"
#include "sensor_health.h"
#include "sloth_clock.h"

/* A bucket start, 1700000400 = 2833334 x 600. */
#define B0 ((time_t)1700000400)

static void mac_n(uint8_t out[6], unsigned n) {
    out[0] = 0x02; out[1] = 0x00;
    out[2] = (uint8_t)(n >> 24); out[3] = (uint8_t)(n >> 16);
    out[4] = (uint8_t)(n >> 8);  out[5] = (uint8_t)n;
}

static probe_hist_row_t g_out[PROBE_HIST_SLOTS];

/* Every key drained, in one array. */
static int drain_all(void) {
    int n = 0, k;
    while ((k = probe_hist_drain(g_out + n, PROBE_HIST_SLOTS - n)) > 0) n += k;
    return n;
}

static const probe_hist_row_t *find(int n, const uint8_t mac[6],
                                    const char *ssid, time_t bucket) {
    for (int i = 0; i < n; i++)
        if (!memcmp(g_out[i].mac, mac, 6) && !strcmp(g_out[i].ssid, ssid) &&
            g_out[i].bucket == bucket)
            return &g_out[i];
    return NULL;
}

/* Nothing is counted with no sink: no --db, and sloth-rf. Seen red
 * with the g_sink test dropped from probe_hist_note(). */
static void test_no_sink_counts_nothing(void) {
    uint8_t m[6]; mac_n(m, 1);
    probe_hist_note(m, "net", B0);
    ASSERT_EQ(probe_hist_keys(), 0);
    ASSERT_EQ(drain_all(), 0);
}

/* A wildcard probe names no network and is not a key. */
static void test_wildcard_not_counted(void) {
    probe_hist_set_sink(1);
    uint8_t m[6]; mac_n(m, 1);
    probe_hist_note(m, "", B0);
    probe_hist_note(m, NULL, B0);
    ASSERT_EQ(probe_hist_keys(), 0);
    ASSERT_EQ(probe_hist_dropped(), 0);
}

/* One key per (MAC, SSID, bucket): probes coalesce, the bucket is the
 * 600 s floor, and first / last are the span of the counted probes. */
static void test_counts_coalesce_per_bucket(void) {
    probe_hist_set_sink(1);
    uint8_t a[6], b[6]; mac_n(a, 1); mac_n(b, 2);
    probe_hist_note(a, "net", B0 + 5);
    probe_hist_note(a, "net", B0 + 599);
    probe_hist_note(a, "net", B0 + 1);
    probe_hist_note(a, "other", B0 + 10);
    probe_hist_note(b, "net", B0 + 20);
    probe_hist_note(a, "net", B0 + 600);    /* the next bucket */
    ASSERT_EQ(probe_hist_keys(), 4);
    int n = drain_all();
    ASSERT_EQ(n, 4);
    const probe_hist_row_t *r = find(n, a, "net", B0);
    ASSERT(r != NULL);
    if (r) {
        ASSERT_EQ((int)r->count, 3);
        ASSERT_EQ((long long)r->first_seen, (long long)(B0 + 1));
        ASSERT_EQ((long long)r->last_seen, (long long)(B0 + 599));
    }
    r = find(n, a, "net", B0 + 600);
    ASSERT(r != NULL);
    if (r) ASSERT_EQ((int)r->count, 1);
    r = find(n, a, "other", B0);
    ASSERT(r != NULL && r->count == 1);
    r = find(n, b, "net", B0);
    ASSERT(r != NULL && r->count == 1);
}

/* A drain writes what was counted since the last one: a second drain
 * with nothing new returns nothing, and a probe after a drain is a
 * count of 1 on the same key, with its own first / last. */
static void test_drain_writes_deltas(void) {
    probe_hist_set_sink(1);
    uint8_t a[6]; mac_n(a, 1);
    probe_hist_note(a, "net", B0 + 1);
    probe_hist_note(a, "net", B0 + 2);
    ASSERT_EQ(drain_all(), 1);
    ASSERT_EQ((int)g_out[0].count, 2);
    ASSERT_EQ(drain_all(), 0);
    probe_hist_note(a, "net", B0 + 30);
    ASSERT_EQ(probe_hist_keys(), 1);
    ASSERT_EQ(drain_all(), 1);
    ASSERT_EQ((int)g_out[0].count, 1);
    ASSERT_EQ((long long)g_out[0].first_seen, (long long)(B0 + 30));
    ASSERT_EQ((long long)g_out[0].last_seen, (long long)(B0 + 30));
}

/* Drained in pieces: `max` at a time, every key once. */
static void test_drain_in_pieces(void) {
    probe_hist_set_sink(1);
    for (unsigned i = 0; i < 10; i++) {
        uint8_t m[6]; mac_n(m, i);
        probe_hist_note(m, "net", B0);
    }
    probe_hist_row_t part[3];
    int total = 0, k, calls = 0;
    while ((k = probe_hist_drain(part, 3)) > 0) { total += k; calls++; }
    ASSERT_EQ(total, 10);
    ASSERT_EQ(calls, 4);
}

/* A key is held until a drain after its bucket ended, so a bucket's
 * keys are counted against its cap however often it is drained; then it
 * is freed. Seen red with compact() keeping every written key (the
 * ended bucket's key stayed after the drain). */
static void test_ended_bucket_freed_after_drain(void) {
    probe_hist_set_sink(1);
    uint8_t a[6], b[6]; mac_n(a, 1); mac_n(b, 2);
    probe_hist_note(a, "net", B0 + 1);
    ASSERT_EQ(drain_all(), 1);
    ASSERT_EQ(probe_hist_keys(), 1);       /* its bucket is the newest */
    probe_hist_note(b, "net", B0 + 600);
    ASSERT_EQ(probe_hist_keys(), 2);
    ASSERT_EQ(drain_all(), 1);
    ASSERT_EQ(probe_hist_keys(), 1);       /* B0's key freed */
    /* An ended bucket's key not yet written stays until it is. */
    probe_hist_note(a, "net", B0 + 2);     /* late, the clock stepped back */
    probe_hist_note(b, "net", B0 + 1200);
    ASSERT_EQ(probe_hist_keys(), 3);
    probe_hist_row_t one[1];
    ASSERT_EQ(probe_hist_drain(one, 1), 1);
    ASSERT_EQ(probe_hist_keys(), 3);
    ASSERT_EQ(drain_all(), 1);
    ASSERT_EQ(probe_hist_keys(), 1);
}

/* A burst of randomised addresses: past PROBE_HIST_BUCKET_KEYS keys in
 * one bucket a new key is refused and counted (probe_hist_dropped and
 * evict_probe_hist), a key already held still counts, and the next
 * bucket has its own cap. Seen red with the per-bucket test dropped
 * from probe_hist_note() (the burst took every slot). */
static void test_burst_capped_per_bucket(void) {
    probe_hist_set_sink(1);
    uint64_t ev0 = sh_evict_count(SH_EVICT_PROBE_HIST);
    for (unsigned i = 0; i < PROBE_HIST_BUCKET_KEYS + 100; i++) {
        uint8_t m[6]; mac_n(m, i);
        probe_hist_note(m, "net", B0 + 3);
    }
    ASSERT_EQ(probe_hist_keys(), PROBE_HIST_BUCKET_KEYS);
    ASSERT_EQ((long long)probe_hist_dropped(), 100);
    ASSERT_EQ((long long)(sh_evict_count(SH_EVICT_PROBE_HIST) - ev0), 100);
    uint8_t first[6]; mac_n(first, 0);
    probe_hist_note(first, "net", B0 + 4);           /* held: counted */
    ASSERT_EQ((long long)probe_hist_dropped(), 100);
    /* A drain does not free the bucket's keys while it is the newest. */
    ASSERT_EQ(drain_all(), PROBE_HIST_BUCKET_KEYS);
    ASSERT_EQ(probe_hist_keys(), PROBE_HIST_BUCKET_KEYS);
    uint8_t late[6]; mac_n(late, 900000);
    probe_hist_note(late, "net", B0 + 5);
    ASSERT_EQ((long long)probe_hist_dropped(), 101);
    /* The next bucket fills to its own cap beside the old one. */
    for (unsigned i = 0; i < PROBE_HIST_BUCKET_KEYS + 1; i++) {
        uint8_t m[6]; mac_n(m, 1000000 + i);
        probe_hist_note(m, "net", B0 + 600);
    }
    ASSERT_EQ(probe_hist_keys(), PROBE_HIST_SLOTS);
    ASSERT_EQ((long long)probe_hist_dropped(), 102);
    /* A third bucket while both are held: no slot left. */
    uint8_t third[6]; mac_n(third, 2000000);
    probe_hist_note(third, "net", B0 + 1200);
    ASSERT_EQ((long long)probe_hist_dropped(), 103);
    ASSERT_EQ(probe_hist_keys(), PROBE_HIST_SLOTS);
    /* The drain writes the open bucket's keys and frees B0's, and the
     * third bucket's keys fit. */
    ASSERT_EQ(drain_all(), PROBE_HIST_BUCKET_KEYS);
    ASSERT_EQ(drain_all(), 0);
    probe_hist_note(third, "net", B0 + 1200);
    ASSERT_EQ((long long)probe_hist_dropped(), 103);
    ASSERT_EQ(probe_hist_keys(), PROBE_HIST_BUCKET_KEYS + 1);
}

static time_t g_wall;
static time_t fixed_wall(void) { return g_wall; }

/* probe_pnl_observe() is the one feed: a directed probe is counted at
 * the wall clock, a wildcard is not. Seen red with the call taken out
 * of probe_pnl_observe(). */
static void test_pnl_observe_feeds_history(void) {
    probe_hist_set_sink(1);
    g_wall = B0 + 42;
    sloth_clock_test_set(NULL, fixed_wall);
    uint8_t a[6]; mac_n(a, 7);
    probe_pnl_observe(a, "net", NULL, NULL);
    probe_pnl_observe(a, "net", NULL, NULL);
    probe_pnl_observe(a, "", NULL, NULL);
    sloth_clock_test_set(NULL, NULL);
    ASSERT_EQ(drain_all(), 1);
    ASSERT_EQ((int)g_out[0].count, 2);
    ASSERT_EQ((long long)g_out[0].bucket, (long long)B0);
    ASSERT_EQ((long long)g_out[0].first_seen, (long long)(B0 + 42));
    ASSERT_STR(g_out[0].ssid, "net");
}

static void test_eviction_kind_named(void) {
    ASSERT_STR(sh_evict_name(SH_EVICT_PROBE_HIST), "probe_hist");
    ASSERT(!sh_evict_is_flow_ring(SH_EVICT_PROBE_HIST));
}

void run_probe_hist_tests(void) {
    RUN_TEST(test_no_sink_counts_nothing);
    RUN_TEST(test_wildcard_not_counted);
    RUN_TEST(test_counts_coalesce_per_bucket);
    RUN_TEST(test_drain_writes_deltas);
    RUN_TEST(test_drain_in_pieces);
    RUN_TEST(test_ended_bucket_freed_after_drain);
    RUN_TEST(test_burst_capped_per_bucket);
    RUN_TEST(test_pnl_observe_feeds_history);
    RUN_TEST(test_eviction_kind_named);
}
