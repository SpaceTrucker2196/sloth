#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "runner.h"
#include "evidence_ring.h"
#include "sensor_health.h"

/* ── Bounded raw 802.11 evidence ring — issue #92 ─────────────
 *
 * The ring exists so a wireless alert with no IP to match on can still
 * ship the frames that triggered it. What has to hold:
 *
 *   - retrieval is keyed by event ID alone (the whole point: no IP, no
 *     flow, no time window);
 *   - a record carries the frame's own capture clock, both lengths and
 *     an explicit truncation flag;
 *   - the whole frame is retained, radiotap included — not the general
 *     ring's min(caplen, 64);
 *   - memory is bounded and every eviction is counted;
 *   - an evicted ID reads as absent, never as a different frame.
 *
 * Frames here are hand-built radiotap + 802.11 byte arrays per
 * AGENTS.md, not captures. For most cases the ring is a byte store and
 * the content is arbitrary — but a byte store whose tests only ever
 * push zeroes cannot show that the bytes came back intact, so the
 * frames carry a real radiotap header and a recognisable payload.
 */

#define RT_LEN 8

/* Minimal radiotap (8 bytes, present=0) + an 802.11 header, then a
 * payload byte pattern seeded from `tag` so a retrieved record can be
 * proven to be the frame that was stored and not its neighbour. */
static int build_frame(uint8_t *f, int total, uint8_t fc0, uint8_t tag) {
    memset(f, 0, (size_t)total);
    f[0] = 0x00;                       /* it_version */
    f[1] = 0x00;                       /* it_pad     */
    f[2] = (uint8_t)RT_LEN;            /* it_len lo  */
    f[3] = 0x00;                       /* it_len hi  */
    if (total > RT_LEN)     f[RT_LEN] = fc0;
    for (int i = RT_LEN + 1; i < total; i++)
        f[i] = (uint8_t)(tag + i);
    return total;
}

/* Every case starts from a known ring and a known eviction tally. */
static void ring_setup(size_t budget) {
    evidence_ring_shutdown();
    sh_evict_reset();
    ASSERT_EQ(evidence_ring_init(budget), 0);
}

/* ── Budget sizing (owner ruling, 2026-09-30) ──────────────── */

static void test_budget_is_one_percent_of_memtotal(void) {
    /* 1 GiB box: 1 % is ~10.7 MiB, inside the clamp, so the 1 % figure
       is what comes out. Asserted as a band rather than an exact byte
       count because the implementation divides before multiplying to
       stay clear of overflow on a 32-bit size_t. */
    size_t b = evidence_budget_from_mem_kb(1024u * 1024u);   /* 1 GiB in kB */
    ASSERT_GT(b, 10u * 1024u * 1024u);
    ASSERT_LT(b, 11u * 1024u * 1024u);
}

static void test_budget_pins_to_the_floor_on_a_small_box(void) {
    /* 64 MiB box: 1 % is 640 KiB, below the floor. */
    size_t b = evidence_budget_from_mem_kb(64u * 1024u);
    ASSERT_EQ((long long)b, (long long)EVIDENCE_BUDGET_FLOOR);
    /* And the degenerate inputs land on the floor too, rather than on
       zero — a sensor that cannot size itself keeps evidence. */
    ASSERT_EQ((long long)evidence_budget_from_mem_kb(0),
              (long long)EVIDENCE_BUDGET_FLOOR);
    ASSERT_EQ((long long)evidence_budget_from_mem_kb(1),
              (long long)EVIDENCE_BUDGET_FLOOR);
}

static void test_budget_pins_to_the_ceiling_on_a_large_box(void) {
    /* 64 GiB box: 1 % is 640 MiB, far above the ceiling. */
    size_t b = evidence_budget_from_mem_kb(64ull * 1024u * 1024u);
    ASSERT_EQ((long long)b, (long long)EVIDENCE_BUDGET_CEIL);
    /* An absurd MemTotal must clamp, not wrap. */
    ASSERT_EQ((long long)evidence_budget_from_mem_kb(0xFFFFFFFFFFFFFFFFull),
              (long long)EVIDENCE_BUDGET_CEIL);
}

static void test_budget_boundaries_are_inclusive(void) {
    /* Exactly at each clamp edge: 200 MiB is 1 % == floor, 3.2 GiB is
       1 % == ceiling. Neither may step over its own bound. */
    ASSERT_EQ((long long)evidence_budget_from_mem_kb(200u * 1024u),
              (long long)EVIDENCE_BUDGET_FLOOR);
    ASSERT_EQ((long long)evidence_budget_from_mem_kb(3276800u),
              (long long)EVIDENCE_BUDGET_CEIL);
}

/* A /proc/meminfo-shaped file, written to a temp path. */
static int write_tmp(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    if (!f) return 0;
    fputs(text, f);
    fclose(f);
    return 1;
}

static void test_meminfo_memtotal_is_parsed(void) {
    const char *p = "/tmp/sloth_test_meminfo_ok";
    ASSERT(write_tmp(p,
        "MemTotal:        1048576 kB\n"
        "MemFree:          123456 kB\n"
        "MemAvailable:     654321 kB\n"));
    size_t b = evidence_budget_from_meminfo(p);
    /* Same 1 GiB box as the mem_kb case, reached through the parser. */
    ASSERT_EQ((long long)b, (long long)evidence_budget_from_mem_kb(1048576u));
    unlink(p);
}

static void test_meminfo_ignores_a_prefix_lookalike(void) {
    /* "MemTotalFoo:" and "SwapTotal:" must not be read as MemTotal, and
       a MemTotal that is not first must still be found. */
    const char *p = "/tmp/sloth_test_meminfo_lookalike";
    ASSERT(write_tmp(p,
        "MemTotalFoo:     64 kB\n"
        "SwapTotal:       64 kB\n"
        "MemTotal:        1048576 kB\n"));
    ASSERT_EQ((long long)evidence_budget_from_meminfo(p),
              (long long)evidence_budget_from_mem_kb(1048576u));
    unlink(p);
}

static void test_meminfo_unreadable_or_malformed_falls_back_to_the_floor(void) {
    /* Not the ceiling and not zero: the floor. A box whose /proc is
       missing, restricted or garbage still keeps evidence. */
    ASSERT_EQ((long long)evidence_budget_from_meminfo("/tmp/sloth_no_such_meminfo_xyz"),
              (long long)EVIDENCE_BUDGET_FLOOR);
    ASSERT_EQ((long long)evidence_budget_from_meminfo(NULL),
              (long long)EVIDENCE_BUDGET_FLOOR);

    const char *p = "/tmp/sloth_test_meminfo_bad";
    ASSERT(write_tmp(p, "MemFree: 123 kB\nnot a meminfo file at all\n"));
    ASSERT_EQ((long long)evidence_budget_from_meminfo(p),
              (long long)EVIDENCE_BUDGET_FLOOR);
    unlink(p);

    ASSERT(write_tmp(p, "MemTotal:        no-number kB\n"));
    ASSERT_EQ((long long)evidence_budget_from_meminfo(p),
              (long long)EVIDENCE_BUDGET_FLOOR);
    unlink(p);

    /* A leading minus is the case strtoull does NOT reject: it parses
       and wraps, so a corrupt read would size the ring at the ceiling
       instead of the floor. The floor is the right answer for any
       MemTotal that is not a plain number. */
    ASSERT(write_tmp(p, "MemTotal:        -5 kB\n"));
    ASSERT_EQ((long long)evidence_budget_from_meminfo(p),
              (long long)EVIDENCE_BUDGET_FLOOR);
    unlink(p);
}

/* ── Init and footprint ────────────────────────────────────── */

static void test_init_refuses_a_budget_too_small_to_hold_a_frame(void) {
    evidence_ring_shutdown();
    ASSERT_EQ(evidence_ring_init(0), -1);
    ASSERT_EQ(evidence_ring_init(EVIDENCE_MIN_BUDGET - 1), -1);
    /* A refused init leaves no ring, and note() is then a no-op that
       returns no event ID rather than pretending to have stored. */
    uint8_t f[64];
    int n = build_frame(f, 64, 0x80, 1);
    ASSERT_EQ((long long)evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                            1700000000, 1, 2412, -40), 0);
    ASSERT_EQ(evidence_ring_count(), 0);
    ASSERT_EQ((long long)evidence_ring_footprint(), 0);
    /* The smallest accepted budget does come up. */
    ASSERT_EQ(evidence_ring_init(EVIDENCE_MIN_BUDGET), 0);
    ASSERT_GT(evidence_ring_capacity(), (size_t)EVIDENCE_FRAME_MAX - 1);
    evidence_ring_shutdown();
}

static void test_footprint_stays_inside_the_budget(void) {
    /* The boundedness claim, at both clamp ends and in between: arena
       plus metadata never exceeds what the budget authorised. */
    const size_t budgets[4] = { EVIDENCE_MIN_BUDGET, 64u * 1024u,
                                EVIDENCE_BUDGET_FLOOR, EVIDENCE_BUDGET_CEIL };
    for (int i = 0; i < 4; i++) {
        ring_setup(budgets[i]);
        ASSERT(evidence_ring_footprint() <= budgets[i]);
        ASSERT_GT(evidence_ring_footprint(), (size_t)0);
        /* And the arena really is most of it — a split that gave the
           metadata ring the whole budget would also satisfy the bound
           above while storing nothing. */
        ASSERT_GT(evidence_ring_capacity(), budgets[i] / 2);
    }
    evidence_ring_shutdown();
}

static void test_a_full_frame_is_retained_not_truncated_to_64(void) {
    /* The defect in the issue's second bullet: the general packet ring
       keeps min(caplen, 64), which on radiotap is the header and little
       else. 1500 bytes in, 1500 bytes out. */
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    static uint8_t f[1500];
    int n = build_frame(f, (int)sizeof(f), 0x80, 7);
    uint64_t id = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                     1700000000, 250000, 5180, -55);
    ASSERT_GT((long long)id, 0);

    evidence_rec_t rec;
    static uint8_t out[2048];
    int got = evidence_ring_get(id, &rec, out, sizeof(out));
    ASSERT_EQ(got, n);
    ASSERT_EQ((long long)rec.cap_len, n);
    ASSERT_EQ((long long)rec.orig_len, n);
    ASSERT_EQ(rec.truncated, 0);
    /* Byte-for-byte, radiotap header included — the retained radiotap
       is what makes the record reconstructable. */
    ASSERT_EQ(memcmp(out, f, (size_t)n), 0);
    ASSERT_EQ(out[2], RT_LEN);
    evidence_ring_shutdown();
}

/* ── Record fidelity ───────────────────────────────────────── */

static void test_record_carries_the_frames_own_clock(void) {
    /* Two stamps far apart and far from any plausible "now", so a
       time(NULL) regression cannot coincidentally match either. */
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[128];
    int n = build_frame(f, 128, 0x80, 3);
    uint64_t a = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                    1000000000, 1, 2412, -40);
    uint64_t b = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                    1500000000, 999999, 2412, -40);
    evidence_rec_t ra, rb;
    ASSERT_GE(evidence_ring_get(a, &ra, NULL, 0), 0);
    ASSERT_GE(evidence_ring_get(b, &rb, NULL, 0), 0);
    ASSERT_EQ((long long)ra.ts_sec,  1000000000LL);
    ASSERT_EQ((long long)ra.ts_usec, 1LL);
    ASSERT_EQ((long long)rb.ts_sec,  1500000000LL);
    ASSERT_EQ((long long)rb.ts_usec, 999999LL);
    evidence_ring_shutdown();
}

static void test_record_keeps_a_bad_clock_rather_than_substituting(void) {
    /* Same policy as 5a4658c: a frame is stamped with what the capture
       says, always. A zero is kept as a zero. */
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[64];
    int n = build_frame(f, 64, 0x80, 4);
    uint64_t id = evidence_ring_note(f, (uint32_t)n, (uint32_t)n, 0, 0, 0, -40);
    evidence_rec_t rec;
    ASSERT_GE(evidence_ring_get(id, &rec, NULL, 0), 0);
    ASSERT_EQ((long long)rec.ts_sec, 0LL);
    evidence_ring_shutdown();
}

static void test_record_keeps_both_lengths_and_flags_a_kernel_snap(void) {
    /* caplen < len: the kernel snapped the frame before libpcap saw it.
       Both lengths survive and the flag is set. */
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[128];
    int n = build_frame(f, 128, 0x80, 5);
    uint64_t id = evidence_ring_note(f, (uint32_t)n, 1600,
                                     1700000000, 0, 2437, -60);
    evidence_rec_t rec;
    uint8_t out[256];
    int got = evidence_ring_get(id, &rec, out, sizeof(out));
    ASSERT_EQ(got, n);
    ASSERT_EQ((long long)rec.cap_len,  n);
    ASSERT_EQ((long long)rec.orig_len, 1600);
    ASSERT_EQ(rec.truncated, 1);
    evidence_ring_shutdown();
}

static void test_record_flags_the_rings_own_per_frame_cap(void) {
    /* The other truncation source: a frame larger than
       EVIDENCE_FRAME_MAX. cap_len reports what is really held — it must
       not claim the full length the way the pre-35838d2 EAPOL writer
       did — and the flag is set even though orig_len was honest. */
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    const int big = EVIDENCE_FRAME_MAX + 500;
    uint8_t *f = malloc((size_t)big);
    ASSERT(f != NULL);
    if (!f) return;
    build_frame(f, big, 0x80, 9);
    uint64_t id = evidence_ring_note(f, (uint32_t)big, (uint32_t)big,
                                     1700000000, 0, 2412, -40);
    evidence_rec_t rec;
    uint8_t *out = malloc((size_t)big);
    ASSERT(out != NULL);
    if (!out) { free(f); return; }
    int got = evidence_ring_get(id, &rec, out, (size_t)big);
    ASSERT_EQ(got, EVIDENCE_FRAME_MAX);
    ASSERT_EQ((long long)rec.cap_len,  (long long)EVIDENCE_FRAME_MAX);
    ASSERT_EQ((long long)rec.orig_len, (long long)big);
    ASSERT_EQ(rec.truncated, 1);
    /* What IS held is the FRONT of the frame — radiotap and the 802.11
       header, the part a reconstruction needs. */
    ASSERT_EQ(memcmp(out, f, EVIDENCE_FRAME_MAX), 0);
    free(out);
    free(f);
    evidence_ring_shutdown();
}

static void test_truncation_is_flagged_when_orig_len_is_unreported(void) {
    /* A capture claiming a shorter length than it handed over is
       malformed. The ring keeps orig_len as reported — it is not sloth's
       to correct — but still flags the record, because `truncated` means
       "this is not provably the whole frame". With orig_len 0 the
       (cap_len < orig_len) test alone would read as untruncated. */
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    const int big = EVIDENCE_FRAME_MAX + 64;
    uint8_t *f = malloc((size_t)big);
    ASSERT(f != NULL);
    if (!f) return;
    build_frame(f, big, 0x80, 11);
    uint64_t id = evidence_ring_note(f, (uint32_t)big, 0,
                                     1700000000, 0, 2412, -40);
    evidence_rec_t rec;
    ASSERT_GE(evidence_ring_get(id, &rec, NULL, 0), 0);
    ASSERT_EQ((long long)rec.orig_len, 0);
    ASSERT_EQ((long long)rec.cap_len,  (long long)EVIDENCE_FRAME_MAX);
    ASSERT_EQ(rec.truncated, 1);
    free(f);
    evidence_ring_shutdown();
}

static void test_record_carries_frequency_and_signal(void) {
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[128];
    int n = build_frame(f, 128, 0x80, 6);
    uint64_t id = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                     1700000000, 0, 5955, -82);
    evidence_rec_t rec;
    ASSERT_GE(evidence_ring_get(id, &rec, NULL, 0), 0);
    ASSERT_EQ((int)rec.freq_mhz, 5955);          /* 6 GHz, UNII-5 */
    ASSERT_EQ((int)rec.signal_dbm, -82);
    evidence_ring_shutdown();
}

/* ── Event IDs and retrieval ───────────────────────────────── */

static void test_event_ids_are_unique_and_monotonic(void) {
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[64];
    int n = build_frame(f, 64, 0x80, 2);
    uint64_t prev = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t id = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                         1700000000 + i, 0, 2412, -40);
        ASSERT_GT((long long)id, (long long)prev);
        prev = id;
    }
    ASSERT_EQ((long long)evidence_ring_last_id(), (long long)prev);
    evidence_ring_shutdown();
}

static void test_retrieval_is_keyed_by_event_id_alone(void) {
    /* The issue's first problem bullet: the exporter requires an IP
       match, so a wireless alert gets nothing. Nothing in this lookup
       takes an address, a port or a window — three interleaved frames
       are each pulled back by ID and the bytes prove which is which. */
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t a[200], b[300], c[120];
    int an = build_frame(a, (int)sizeof(a), 0x80, 0x10);   /* beacon  */
    int bn = build_frame(b, (int)sizeof(b), 0xC0, 0x40);   /* deauth  */
    int cn = build_frame(c, (int)sizeof(c), 0xB0, 0x70);   /* auth    */
    uint64_t ia = evidence_ring_note(a, (uint32_t)an, (uint32_t)an,
                                     1700000001, 0, 2412, -40);
    uint64_t ib = evidence_ring_note(b, (uint32_t)bn, (uint32_t)bn,
                                     1700000002, 0, 2412, -41);
    uint64_t ic = evidence_ring_note(c, (uint32_t)cn, (uint32_t)cn,
                                     1700000003, 0, 2412, -42);

    evidence_rec_t rec;
    uint8_t out[512];
    /* Out of order, which a flow-keyed lookup could not do. */
    ASSERT_EQ(evidence_ring_get(ib, &rec, out, sizeof(out)), bn);
    ASSERT_EQ(memcmp(out, b, (size_t)bn), 0);
    ASSERT_EQ((long long)rec.ts_sec, 1700000002LL);
    ASSERT_EQ(evidence_ring_get(ia, &rec, out, sizeof(out)), an);
    ASSERT_EQ(memcmp(out, a, (size_t)an), 0);
    ASSERT_EQ(evidence_ring_get(ic, &rec, out, sizeof(out)), cn);
    ASSERT_EQ(memcmp(out, c, (size_t)cn), 0);
    /* And the same ID twice gives the same frame — a pull is not a pop. */
    ASSERT_EQ(evidence_ring_get(ic, &rec, out, sizeof(out)), cn);
    ASSERT_EQ(memcmp(out, c, (size_t)cn), 0);
    evidence_ring_shutdown();
}

static void test_retrieval_reports_a_short_caller_buffer(void) {
    /* A caller with less room than the frame gets a prefix and the real
       cap_len, so it can tell it got a prefix. Silently reporting the
       short count as the frame length is the error class #92 is about. */
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[400];
    int n = build_frame(f, (int)sizeof(f), 0x80, 0x20);
    uint64_t id = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                     1700000000, 0, 2412, -40);
    evidence_rec_t rec;
    uint8_t out[100];
    int got = evidence_ring_get(id, &rec, out, sizeof(out));
    ASSERT_EQ(got, 100);
    ASSERT_EQ((long long)rec.cap_len, n);         /* the record is longer */
    ASSERT_EQ(memcmp(out, f, 100), 0);
    /* Metadata-only lookup: no buffer at all is a hit, not an error. */
    ASSERT_EQ(evidence_ring_get(id, &rec, NULL, 0), 0);
    ASSERT_EQ((long long)rec.cap_len, n);
    evidence_ring_shutdown();
}

static void test_unknown_and_future_ids_miss(void) {
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[64];
    int n = build_frame(f, 64, 0x80, 0x30);
    uint64_t id = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                     1700000000, 0, 2412, -40);
    evidence_rec_t rec;
    ASSERT_EQ(evidence_ring_get(0, &rec, NULL, 0), -1);           /* never valid */
    ASSERT_EQ(evidence_ring_get(id + 1, &rec, NULL, 0), -1);      /* not issued  */
    ASSERT_EQ(evidence_ring_get(0xFFFFFFFFull, &rec, NULL, 0), -1);
    ASSERT_EQ(evidence_ring_get(id, NULL, NULL, 0), -1);          /* no out      */
    /* An empty ring misses everything rather than reading slot 0. */
    evidence_ring_reset();
    ASSERT_EQ(evidence_ring_get(id, &rec, NULL, 0), -1);
    evidence_ring_shutdown();
}

static void test_reset_does_not_reissue_event_ids(void) {
    /* An event ID must not come to mean a second frame: after a reset
       the next ID continues upward, so a stale reference misses instead
       of silently resolving to an unrelated record. */
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[64];
    int n = build_frame(f, 64, 0x80, 0x50);
    uint64_t first = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                        1700000000, 0, 2412, -40);
    evidence_ring_reset();
    ASSERT_EQ(evidence_ring_count(), 0);
    uint64_t next = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                       1700000000, 0, 2412, -40);
    ASSERT_GT((long long)next, (long long)first);
    evidence_rec_t rec;
    ASSERT_EQ(evidence_ring_get(first, &rec, NULL, 0), -1);
    evidence_ring_shutdown();
}

static void test_note_rejects_an_empty_frame(void) {
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[64];
    build_frame(f, 64, 0x80, 0x60);
    /* The sequence is process-lifetime, so this is a delta: earlier
       cases in this binary have already issued IDs. */
    uint64_t before = evidence_ring_last_id();
    ASSERT_EQ((long long)evidence_ring_note(NULL, 64, 64,
                                            1700000000, 0, 0, -40), 0);
    ASSERT_EQ((long long)evidence_ring_note(f, 0, 64,
                                            1700000000, 0, 0, -40), 0);
    ASSERT_EQ(evidence_ring_count(), 0);
    /* A refused frame consumes no event ID — IDs name stored records. */
    ASSERT_EQ((long long)evidence_ring_last_id(), (long long)before);
    evidence_ring_shutdown();
}

/* ── Bounded memory and counted eviction ───────────────────── */

static void test_arena_pressure_evicts_the_oldest_and_counts_it(void) {
    /* A budget that holds only a handful of 1 KiB frames. The newest
       survive, the oldest are gone, the tally names the loss. */
    ring_setup(EVIDENCE_MIN_BUDGET * 2);        /* 16 KiB */
    const size_t cap = evidence_ring_capacity();
    static uint8_t f[1024];
    build_frame(f, (int)sizeof(f), 0x80, 0x80);

    uint64_t ids[40];
    for (int i = 0; i < 40; i++)
        ids[i] = evidence_ring_note(f, (uint32_t)sizeof(f), (uint32_t)sizeof(f),
                                    1700000000 + i, 0, 2412, -40);

    /* Bounded: never more arena in use than was allocated. */
    ASSERT(evidence_ring_bytes_used() <= cap);
    /* Lossy, and the loss is counted — not silent. */
    uint64_t evicted = sh_evict_count(SH_EVICT_EVIDENCE_FRAME);
    ASSERT_GT((long long)evicted, 0);
    ASSERT_EQ((long long)evicted, 40 - (long long)evidence_ring_count());
    ASSERT_EQ((long long)sh_evict_total(), (long long)evicted);

    /* The newest is retained and the oldest is gone. */
    evidence_rec_t rec;
    ASSERT_GE(evidence_ring_get(ids[39], &rec, NULL, 0), 0);
    ASSERT_EQ(evidence_ring_get(ids[0], &rec, NULL, 0), -1);
    evidence_ring_shutdown();
}

static void test_slot_pressure_evicts_even_when_bytes_remain(void) {
    /* The other bound. Tiny frames exhaust metadata slots long before
       the arena fills, so a ring counting only byte pressure would grow
       its record count without limit. */
    ring_setup(64u * 1024u);
    uint8_t f[16];
    int n = build_frame(f, (int)sizeof(f), 0xD4, 0x90);   /* ACK-sized */
    const int pushes = 500;
    for (int i = 0; i < pushes; i++)
        evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                           1700000000 + i, 0, 2412, -40);

    ASSERT_LT(evidence_ring_count(), pushes);
    ASSERT(evidence_ring_bytes_used() <= evidence_ring_capacity());
    /* Arena pressure cannot be what did this: every byte ever pushed
       would still fit the arena, so the cap came from the slot ring. */
    ASSERT_LT((size_t)(pushes * n), evidence_ring_capacity());
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_EVIDENCE_FRAME),
              pushes - (long long)evidence_ring_count());
    evidence_ring_shutdown();
}

static void test_wrapped_payloads_come_back_intact(void) {
    /* The arena is circular, so a record that straddles the end is
       stored in two pieces. Pushing well past capacity with a frame
       size that does not divide it guarantees a straddle, and every
       surviving record must still read back byte-exact. */
    ring_setup(EVIDENCE_MIN_BUDGET * 4);
    uint8_t f[333];
    const int pushes = 300;
    uint64_t ids[300];
    for (int i = 0; i < pushes; i++) {
        build_frame(f, (int)sizeof(f), 0x80, (uint8_t)i);
        ids[i] = evidence_ring_note(f, (uint32_t)sizeof(f), (uint32_t)sizeof(f),
                                    1700000000 + i, 0, 2412, -40);
    }
    int checked = 0;
    for (int i = 0; i < pushes; i++) {
        evidence_rec_t rec;
        uint8_t out[512], want[512];
        int got = evidence_ring_get(ids[i], &rec, out, sizeof(out));
        if (got < 0) continue;                       /* evicted, fine */
        build_frame(want, (int)sizeof(f), 0x80, (uint8_t)i);
        ASSERT_EQ(got, (int)sizeof(f));
        ASSERT_EQ(memcmp(out, want, sizeof(f)), 0);
        checked++;
    }
    ASSERT_GT(checked, 1);                           /* some did survive */
    ASSERT_LT(checked, pushes);                      /* and some did not */
    evidence_ring_shutdown();
}

static void test_an_evicted_id_reads_as_absent_not_as_another_frame(void) {
    /* The property that makes the ring usable as evidence: a reference
       to a frame that has aged out must fail, never resolve to whatever
       now occupies the slot. */
    ring_setup(EVIDENCE_MIN_BUDGET * 2);
    static uint8_t f[1024];
    build_frame(f, (int)sizeof(f), 0x80, 0xA0);
    uint64_t first = evidence_ring_note(f, (uint32_t)sizeof(f),
                                        (uint32_t)sizeof(f),
                                        1700000000, 0, 2412, -40);
    evidence_rec_t rec;
    ASSERT_GE(evidence_ring_get(first, &rec, NULL, 0), 0);   /* present now */

    for (int i = 0; i < 60; i++)
        evidence_ring_note(f, (uint32_t)sizeof(f), (uint32_t)sizeof(f),
                           1700000100 + i, 0, 2412, -40);

    ASSERT_EQ(evidence_ring_get(first, &rec, NULL, 0), -1);
    /* ...while the ring is not empty — so the miss is the eviction and
       not a broken lookup. */
    ASSERT_GT(evidence_ring_count(), 0);
    ASSERT_GE(evidence_ring_get(evidence_ring_last_id(), &rec, NULL, 0), 0);
    evidence_ring_shutdown();
}

static void test_shutdown_is_idempotent_and_leaves_a_dead_ring(void) {
    ring_setup(EVIDENCE_BUDGET_FLOOR);
    uint8_t f[64];
    int n = build_frame(f, 64, 0x80, 0xB0);
    uint64_t id = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                     1700000000, 0, 2412, -40);
    evidence_ring_shutdown();
    evidence_ring_shutdown();                        /* twice is safe */
    evidence_rec_t rec;
    ASSERT_EQ(evidence_ring_get(id, &rec, NULL, 0), -1);
    ASSERT_EQ(evidence_ring_count(), 0);
    ASSERT_EQ((long long)evidence_ring_footprint(), 0);
    ASSERT_EQ((long long)evidence_ring_bytes_used(), 0);
    /* A shutdown ring does not count evictions it did not make. */
    sh_evict_reset();
    ASSERT_EQ((long long)evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                            1700000000, 0, 2412, -40), 0);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_EVIDENCE_FRAME), 0);
}

static void test_init_default_is_idempotent_and_keeps_records(void) {
    /* A monitor radio can appear twice — at startup discovery and at an
       [m] retarget — and both call this. The second call must not
       discard what the first collected: retargeting the radio is not a
       reason to drop the evidence already in hand. */
    evidence_ring_shutdown();
    ASSERT_EQ(evidence_ring_init_default(), 0);
    size_t footprint = evidence_ring_footprint();
    ASSERT_GT(footprint, (size_t)0);
    ASSERT(footprint >= EVIDENCE_BUDGET_FLOOR - 1);

    uint8_t f[128];
    int n = build_frame(f, 128, 0x80, 0xD0);
    uint64_t id = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                     1700000000, 0, 2412, -40);
    ASSERT_GT((long long)id, 0);

    ASSERT_EQ(evidence_ring_init_default(), 0);          /* second call */
    ASSERT_EQ((long long)evidence_ring_footprint(), (long long)footprint);
    ASSERT_EQ(evidence_ring_count(), 1);
    evidence_rec_t rec;
    uint8_t out[256];
    ASSERT_EQ(evidence_ring_get(id, &rec, out, sizeof(out)), n);
    ASSERT_EQ(memcmp(out, f, (size_t)n), 0);

    /* And it does bring a dead ring back up rather than reporting
       success on nothing. */
    evidence_ring_shutdown();
    ASSERT_EQ((long long)evidence_ring_footprint(), 0);
    ASSERT_EQ(evidence_ring_init_default(), 0);
    ASSERT_GT(evidence_ring_footprint(), (size_t)0);
    evidence_ring_shutdown();
}

static void test_reinit_replaces_the_ring(void) {
    ring_setup(EVIDENCE_MIN_BUDGET);
    uint8_t f[64];
    int n = build_frame(f, 64, 0x80, 0xC0);
    uint64_t id = evidence_ring_note(f, (uint32_t)n, (uint32_t)n,
                                     1700000000, 0, 2412, -40);
    size_t small = evidence_ring_footprint();
    ASSERT_EQ(evidence_ring_init(EVIDENCE_BUDGET_FLOOR), 0);
    ASSERT_GT(evidence_ring_footprint(), small);
    ASSERT_EQ(evidence_ring_count(), 0);
    evidence_rec_t rec;
    ASSERT_EQ(evidence_ring_get(id, &rec, NULL, 0), -1);
    evidence_ring_shutdown();
}

void run_evidence_ring_tests(void) {
    TEST_SUITE("evidence ring: budget sizing from MemTotal (#92)");
    RUN_TEST(test_budget_is_one_percent_of_memtotal);
    RUN_TEST(test_budget_pins_to_the_floor_on_a_small_box);
    RUN_TEST(test_budget_pins_to_the_ceiling_on_a_large_box);
    RUN_TEST(test_budget_boundaries_are_inclusive);
    RUN_TEST(test_meminfo_memtotal_is_parsed);
    RUN_TEST(test_meminfo_ignores_a_prefix_lookalike);
    RUN_TEST(test_meminfo_unreadable_or_malformed_falls_back_to_the_floor);

    TEST_SUITE("evidence ring: allocation is bounded (#92)");
    RUN_TEST(test_init_refuses_a_budget_too_small_to_hold_a_frame);
    RUN_TEST(test_footprint_stays_inside_the_budget);
    RUN_TEST(test_a_full_frame_is_retained_not_truncated_to_64);

    TEST_SUITE("evidence ring: record fidelity (#92)");
    RUN_TEST(test_record_carries_the_frames_own_clock);
    RUN_TEST(test_record_keeps_a_bad_clock_rather_than_substituting);
    RUN_TEST(test_record_keeps_both_lengths_and_flags_a_kernel_snap);
    RUN_TEST(test_record_flags_the_rings_own_per_frame_cap);
    RUN_TEST(test_truncation_is_flagged_when_orig_len_is_unreported);
    RUN_TEST(test_record_carries_frequency_and_signal);

    TEST_SUITE("evidence ring: retrieval by event ID, no IP match (#92)");
    RUN_TEST(test_event_ids_are_unique_and_monotonic);
    RUN_TEST(test_retrieval_is_keyed_by_event_id_alone);
    RUN_TEST(test_retrieval_reports_a_short_caller_buffer);
    RUN_TEST(test_unknown_and_future_ids_miss);
    RUN_TEST(test_reset_does_not_reissue_event_ids);
    RUN_TEST(test_note_rejects_an_empty_frame);

    TEST_SUITE("evidence ring: eviction is bounded and counted (#92)");
    RUN_TEST(test_arena_pressure_evicts_the_oldest_and_counts_it);
    RUN_TEST(test_slot_pressure_evicts_even_when_bytes_remain);
    RUN_TEST(test_wrapped_payloads_come_back_intact);
    RUN_TEST(test_an_evicted_id_reads_as_absent_not_as_another_frame);
    RUN_TEST(test_shutdown_is_idempotent_and_leaves_a_dead_ring);
    RUN_TEST(test_init_default_is_idempotent_and_keeps_records);
    RUN_TEST(test_reinit_replaces_the_ring);
}
