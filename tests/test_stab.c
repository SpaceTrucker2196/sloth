/* tests/test_stab.c — the bounded keyed table behind the snoopers (#110).
 *
 * Every table here is driven with an explicit `now`, so the eviction
 * order is a property of the stamps the test chose and not of the wall
 * clock. The per-module tests (tests/test_<mod>_snoop.c) prove the
 * same policies through each parser; this file proves the policies
 * themselves, including the branches no current table exercises. */

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "runner.h"
#include "stab.h"
#include "sensor_health.h"

typedef struct {
    char   key[16];
    int    v;
    time_t last_seen;
} trow_t;

static int trow_eq(const void *row, const void *key) {
    return strcmp(((const trow_t *)row)->key, (const char *)key) == 0;
}

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

STAB_DECL(g_old, trow_t, 4, last_seen, STAB_OLDEST,
          SH_EVICT_ARP_HIST, NULL, trow_eq);
STAB_DECL_AGE(g_age, trow_t, 2, last_seen, STAB_REFUSE_AGING, 3600,
              SH_EVICT_MDNS_SERVICE, NULL, trow_eq);
STAB_DECL(g_ring, trow_t, 3, last_seen, STAB_RING,
          SH_EVICT_NBNS_NAME, NULL, trow_eq);
STAB_DECL(g_locked, trow_t, 2, last_seen, STAB_OLDEST,
          SH_EVICT_BGP_SESSION, &g_mu, trow_eq);

/* Find-or-allocate and fill the key the way a snooper does. */
static trow_t *put(stab_t *t, const char *k, time_t now, int *created) {
    int c = 0;
    trow_t *r = stab_get(t, k, now, &c);
    if (r && c) snprintf(r->key, sizeof(r->key), "%s", k);
    if (created) *created = c;
    return r;
}

static void reset_all(void) {
    stab_clear(&g_old);
    stab_clear(&g_age);
    stab_clear(&g_ring);
    stab_clear(&g_locked);
    sh_evict_reset();
}

/* ── creation and lookup ─────────────────────────────────── */

static void test_get_creates_then_finds(void) {
    reset_all();
    int created = -1;
    trow_t *a = put(&g_old, "a", 100, &created);
    ASSERT(a != NULL);
    ASSERT_EQ(created, 1);
    ASSERT_EQ(stab_count(&g_old), 1);
    ASSERT_EQ((long)a->last_seen, 100L);   /* stamped on creation */
    a->v = 7;
    trow_t *again = put(&g_old, "a", 200, &created);
    ASSERT(again == a);
    ASSERT_EQ(created, 0);
    ASSERT_EQ(again->v, 7);                /* an existing row is not touched */
    ASSERT_EQ((long)again->last_seen, 100L);
    ASSERT_EQ(stab_count(&g_old), 1);
    ASSERT(stab_find(&g_old, "a") == a);
    ASSERT_EQ((int)sh_evict_total(), 0);
}

static void test_find_never_allocates(void) {
    reset_all();
    ASSERT(stab_find(&g_old, "nope") == NULL);
    ASSERT_EQ(stab_count(&g_old), 0);
    ASSERT(stab_at(&g_old, 0) == NULL);
}

static void test_at_respects_bounds(void) {
    reset_all();
    put(&g_old, "a", 1, NULL);
    put(&g_old, "b", 2, NULL);
    ASSERT(stab_at(&g_old, -1) == NULL);
    ASSERT(stab_at(&g_old, 2) == NULL);
    ASSERT_STR(((trow_t *)stab_at(&g_old, 0))->key, "a");
    ASSERT_STR(((trow_t *)stab_at(&g_old, 1))->key, "b");
}

/* ── STAB_OLDEST ─────────────────────────────────────────── */

static void test_oldest_evicts_smallest_last_seen_and_tallies(void) {
    reset_all();
    put(&g_old, "a", 100, NULL);
    put(&g_old, "b", 101, NULL);
    put(&g_old, "c", 102, NULL);
    put(&g_old, "d", 103, NULL);
    ASSERT_EQ(stab_count(&g_old), 4);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_ARP_HIST), 0);   /* full is not loss */
    int created = 0;
    trow_t *e = put(&g_old, "e", 200, &created);
    ASSERT(e != NULL);
    ASSERT_EQ(created, 1);
    ASSERT_EQ(stab_count(&g_old), 4);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_ARP_HIST), 1);
    ASSERT(stab_find(&g_old, "a") == NULL);                  /* the oldest went */
    ASSERT(stab_find(&g_old, "b") != NULL);
    ASSERT(stab_find(&g_old, "e") == e);
    ASSERT(stab_at(&g_old, 0) == e);                         /* into its slot */
}

static void test_oldest_picks_by_stamp_not_by_slot(void) {
    /* Survivors staggered so a scan that compared the wrong way, or one
     * that always took slot 0, lands on a different victim. */
    reset_all();
    trow_t *a = put(&g_old, "a", 100, NULL);
    put(&g_old, "b", 101, NULL);
    put(&g_old, "c", 102, NULL);
    put(&g_old, "d", 103, NULL);
    a->last_seen = 500;                                      /* a was just seen */
    put(&g_old, "e", 600, NULL);
    ASSERT(stab_find(&g_old, "a") != NULL);
    ASSERT(stab_find(&g_old, "b") == NULL);                  /* now the oldest */
    ASSERT(stab_at(&g_old, 1) == stab_find(&g_old, "e"));
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_ARP_HIST), 1);
}

static void test_oldest_ties_evict_lowest_slot(void) {
    /* Equal stamps — a table filled within one second — evict in
     * insertion order. `<=` in the scan would take the LAST row. */
    reset_all();
    put(&g_old, "a", 100, NULL);
    put(&g_old, "b", 100, NULL);
    put(&g_old, "c", 100, NULL);
    put(&g_old, "d", 100, NULL);
    put(&g_old, "e", 100, NULL);
    ASSERT(stab_find(&g_old, "a") == NULL);
    ASSERT(stab_find(&g_old, "d") != NULL);
    /* "e" now sits in slot 0 with the same stamp as everyone else, so
     * it is the next victim — lowest slot among equals, every time.
     * `<=` would have taken "d" both times. */
    put(&g_old, "f", 100, NULL);
    ASSERT(stab_find(&g_old, "e") == NULL);
    ASSERT(stab_find(&g_old, "b") != NULL);
    ASSERT(stab_find(&g_old, "d") != NULL);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_ARP_HIST), 2);
}

static void test_recycled_row_is_zeroed_and_stamped(void) {
    reset_all();
    trow_t *a = put(&g_old, "a", 100, NULL);
    a->v = 99;
    put(&g_old, "b", 101, NULL);
    put(&g_old, "c", 102, NULL);
    put(&g_old, "d", 103, NULL);
    trow_t *e = put(&g_old, "e", 777, NULL);
    ASSERT(e == a);                                          /* same slot */
    ASSERT_EQ(e->v, 0);                                      /* nothing leaks */
    ASSERT_EQ((long)e->last_seen, 777L);
}

/* ── STAB_REFUSE_AGING ───────────────────────────────────── */

static void test_refuse_aging_reclaims_stale_row(void) {
    reset_all();
    put(&g_age, "a", 100, NULL);
    put(&g_age, "b", 100, NULL);
    int created = 0;
    trow_t *c = put(&g_age, "c", 3700, &created);           /* both are 3600 s stale */
    ASSERT(c != NULL);
    ASSERT_EQ(created, 1);
    ASSERT_EQ(stab_count(&g_age), 2);
    ASSERT(stab_find(&g_age, "a") == NULL);                  /* oldest slot reclaimed */
    ASSERT(stab_find(&g_age, "b") != NULL);
    /* A reclaim is a TTL expiry, not a refusal: nothing current was
     * lost, so the tally does not move. */
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_MDNS_SERVICE), 0);
}

static void test_refuse_aging_does_not_reclaim_fresh_rows(void) {
    /* Absence claim, mutation-proved: a stab_get that ignored age_secs
     * (reclaiming on any full table) reddens the NULL, the count and
     * the tally assertions. */
    reset_all();
    put(&g_age, "a", 100, NULL);
    put(&g_age, "b", 100, NULL);
    int created = -1;
    trow_t *c = put(&g_age, "c", 3699, &created);           /* one second short */
    ASSERT(c == NULL);
    ASSERT_EQ(created, 0);
    ASSERT_EQ(stab_count(&g_age), 2);
    ASSERT(stab_find(&g_age, "a") != NULL);
    ASSERT(stab_find(&g_age, "b") != NULL);
    ASSERT(stab_find(&g_age, "c") == NULL);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_MDNS_SERVICE), 1); /* the refusal is the loss */
    /* And exactly at the boundary the row IS reclaimable. */
    ASSERT(put(&g_age, "c", 3700, NULL) != NULL);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_MDNS_SERVICE), 1);
}

static void test_refuse_aging_reclaims_only_the_stale_one(void) {
    reset_all();
    put(&g_age, "a", 100, NULL);
    put(&g_age, "b", 3000, NULL);
    ASSERT(put(&g_age, "c", 3700, NULL) != NULL);           /* a is stale, b is not */
    ASSERT(stab_find(&g_age, "a") == NULL);
    ASSERT(stab_find(&g_age, "b") != NULL);
    ASSERT(put(&g_age, "d", 3700, NULL) == NULL);           /* b (700 s) and c (0 s) are fresh */
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_MDNS_SERVICE), 1);
    ASSERT_EQ(stab_count(&g_age), 2);
}

static void test_refuse_aging_still_finds_existing_when_full(void) {
    /* A refusal is for NEW keys only; an existing key always resolves. */
    reset_all();
    trow_t *a = put(&g_age, "a", 100, NULL);
    put(&g_age, "b", 100, NULL);
    int created = -1;
    ASSERT(put(&g_age, "a", 101, &created) == a);
    ASSERT_EQ(created, 0);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_MDNS_SERVICE), 0);
}

/* ── STAB_RING ───────────────────────────────────────────── */

static void test_ring_overwrites_in_insertion_order(void) {
    /* Stamps run backwards so an oldest-by-stamp policy would pick the
     * other end; the ring must ignore them. */
    reset_all();
    put(&g_ring, "a", 300, NULL);
    put(&g_ring, "b", 200, NULL);
    put(&g_ring, "c", 100, NULL);
    put(&g_ring, "d", 50, NULL);
    ASSERT(stab_find(&g_ring, "a") == NULL);
    ASSERT(stab_find(&g_ring, "c") != NULL);
    put(&g_ring, "e", 50, NULL);
    ASSERT(stab_find(&g_ring, "b") == NULL);
    put(&g_ring, "f", 50, NULL);
    ASSERT(stab_find(&g_ring, "c") == NULL);
    put(&g_ring, "g", 50, NULL);                             /* wraps to slot 0 */
    ASSERT(stab_find(&g_ring, "d") == NULL);
    ASSERT(stab_at(&g_ring, 0) == stab_find(&g_ring, "g"));
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_NBNS_NAME), 4);
    ASSERT_EQ(stab_count(&g_ring), 3);
}

/* ── snapshot / clear ────────────────────────────────────── */

static void test_snapshot_copies_slot_order_and_clamps(void) {
    reset_all();
    put(&g_old, "a", 1, NULL)->v = 1;
    put(&g_old, "b", 2, NULL)->v = 2;
    put(&g_old, "c", 3, NULL)->v = 3;
    trow_t out[2];
    memset(out, 0, sizeof(out));
    ASSERT_EQ(stab_snapshot(&g_old, out, 2), 2);
    ASSERT_STR(out[0].key, "a");
    ASSERT_EQ(out[1].v, 2);
    trow_t big[8];
    ASSERT_EQ(stab_snapshot(&g_old, big, 8), 3);             /* never past n */
    ASSERT_STR(big[2].key, "c");
    ASSERT_EQ(stab_snapshot(&g_old, big, 0), 0);
}

static void test_clear_empties_rows_and_resets_ring(void) {
    reset_all();
    put(&g_ring, "a", 1, NULL);
    put(&g_ring, "b", 1, NULL);
    put(&g_ring, "c", 1, NULL);
    put(&g_ring, "d", 1, NULL);                              /* head now at slot 1 */
    stab_clear(&g_ring);
    ASSERT_EQ(stab_count(&g_ring), 0);
    ASSERT(stab_find(&g_ring, "d") == NULL);
    ASSERT(stab_at(&g_ring, 0) == NULL);
    ASSERT_EQ(((trow_t *)g_ring.rows)[0].key[0], '\0');      /* rows zeroed */
    /* Head reset: the first overwrite after refilling is slot 0, not
     * wherever the previous run left the head. */
    put(&g_ring, "p", 1, NULL);
    put(&g_ring, "q", 1, NULL);
    put(&g_ring, "r", 1, NULL);
    put(&g_ring, "s", 1, NULL);
    ASSERT(stab_find(&g_ring, "p") == NULL);
    ASSERT(stab_find(&g_ring, "q") != NULL);
    /* Clear leaves the lifetime tally alone. */
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_NBNS_NAME), 2);
}

/* ── optional mutex ──────────────────────────────────────── */

static void test_mutex_is_taken_and_released(void) {
    /* Each entry point must leave the lock free afterwards; a trylock
     * that fails would mean one returned while still holding it. */
    reset_all();
    put(&g_locked, "a", 1, NULL);
    put(&g_locked, "b", 1, NULL);
    put(&g_locked, "c", 1, NULL);                            /* eviction path */
    put(&g_age, "x", 1, NULL);
    ASSERT(stab_find(&g_locked, "b") != NULL);
    ASSERT_EQ(stab_count(&g_locked), 2);
    ASSERT(stab_at(&g_locked, 0) != NULL);
    trow_t out[2];
    ASSERT_EQ(stab_snapshot(&g_locked, out, 2), 2);
    stab_clear(&g_locked);
    ASSERT_EQ(pthread_mutex_trylock(&g_mu), 0);
    pthread_mutex_unlock(&g_mu);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_BGP_SESSION), 1);
}

void run_stab_tests(void) {
    TEST_SUITE("stab — bounded keyed table (#110)");
    RUN_TEST(test_get_creates_then_finds);
    RUN_TEST(test_find_never_allocates);
    RUN_TEST(test_at_respects_bounds);
    RUN_TEST(test_oldest_evicts_smallest_last_seen_and_tallies);
    RUN_TEST(test_oldest_picks_by_stamp_not_by_slot);
    RUN_TEST(test_oldest_ties_evict_lowest_slot);
    RUN_TEST(test_recycled_row_is_zeroed_and_stamped);
    RUN_TEST(test_refuse_aging_reclaims_stale_row);
    RUN_TEST(test_refuse_aging_does_not_reclaim_fresh_rows);
    RUN_TEST(test_refuse_aging_reclaims_only_the_stale_one);
    RUN_TEST(test_refuse_aging_still_finds_existing_when_full);
    RUN_TEST(test_ring_overwrites_in_insertion_order);
    RUN_TEST(test_snapshot_copies_slot_order_and_clamps);
    RUN_TEST(test_clear_empties_rows_and_resets_ring);
    RUN_TEST(test_mutex_is_taken_and_released);
    reset_all();
}
