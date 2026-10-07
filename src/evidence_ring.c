#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "evidence_ring.h"
#include "sensor_health.h"

/* Bounded raw 802.11 evidence ring — contract and rationale in
 * evidence_ring.h.
 *
 * Layout: one heap arena used as a circular byte buffer, plus a FIFO
 * ring of fixed-size metadata slots. Payloads are variable-length, so
 * the arena is the bound that matters for bytes and the slot ring is the
 * bound that matters for record count — a ring watching only one of the
 * two is unbounded in the other direction, which is why both are
 * enforced on every push.
 *
 * Why a byte arena rather than a slot array of EVIDENCE_FRAME_MAX each:
 * most 802.11 frames an attacker generates are tiny (ACK is 14 bytes,
 * a deauth 26), so fixed 4 KiB slots would spend ~99 % of the budget on
 * padding and retain a couple of hundred frames where the arena retains
 * tens of thousands. For an evidence ring, depth is the feature. */

typedef struct {
    evidence_rec_t rec;
    size_t         off;      /* payload start in the arena */
} ev_slot_t;

/* Assumed mean retained-frame size, used only to split the budget
 * between arena and metadata. Deliberately generous relative to real
 * 802.11 traffic: over-estimating costs slots (the cheap resource),
 * under-estimating spends the budget on metadata for records the arena
 * can never hold. */
#define EV_MEAN_FRAME 512u

static uint8_t        *g_arena;
static size_t          g_cap;        /* arena bytes */
static size_t          g_used;       /* arena bytes live */
static size_t          g_write;      /* next arena write offset */
static ev_slot_t      *g_meta;
static size_t          g_slots;      /* metadata ring length */
static size_t          g_tail;       /* oldest live slot */
static size_t          g_count;      /* live slots */
static size_t          g_footprint;  /* arena + metadata, as allocated */
static uint64_t        g_next_id;    /* last ID issued; 0 = none yet */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* ── Budget sizing ───────────────────────────────────────────── */

size_t evidence_budget_from_mem_kb(uint64_t mem_total_kb) {
    /* Divide before multiplying: (kb * 1024) overflows a 32-bit size_t
     * at 4 GiB of RAM — the exact range of box this runs on. The lost
     * precision is under 1 KiB of budget. */
    uint64_t pct_kb = mem_total_kb / 100u;
    /* The ceiling is applied in kB, BEFORE the shift to bytes — not
     * after, which is the obvious way to write it and is wrong. A
     * garbage MemTotal near UINT64_MAX overflows `pct_kb * 1024`, and a
     * wrapped product can land *inside* the clamp: a bad read of /proc
     * yielding a plausible-looking budget is worse than either bound.
     * Clamping first means the multiply never overflows.
     *
     * There is deliberately no second `want > CEIL` test after the
     * multiply. It would be unreachable — `want > CEIL` is algebraically
     * the same condition as the one above — and an unreachable branch in
     * a sizing function reads as a guard that is holding something. */
    if (pct_kb > (uint64_t)EVIDENCE_BUDGET_CEIL / 1024u)
        return EVIDENCE_BUDGET_CEIL;
    uint64_t want = pct_kb * 1024u;
    if (want < EVIDENCE_BUDGET_FLOOR) return EVIDENCE_BUDGET_FLOOR;
    return (size_t)want;
}

size_t evidence_budget_from_meminfo(const char *path) {
    if (!path) return EVIDENCE_BUDGET_FLOOR;
    FILE *f = fopen(path, "r");
    if (!f) return EVIDENCE_BUDGET_FLOOR;
    char line[256];
    uint64_t kb = 0;
    while (fgets(line, sizeof(line), f)) {
        /* The key is matched with its colon attached, so SwapTotal and a
         * MemTotalFoo: line cannot be read as MemTotal. */
        if (strncmp(line, "MemTotal:", 9) != 0) continue;
        const char *p = line + 9;
        while (*p == ' ' || *p == '\t') p++;
        /* Require a digit rather than letting strtoull decide. On
         * non-numeric text strtoull returns 0, which would reach the
         * floor anyway — but on a LEADING MINUS it parses successfully
         * and wraps, so "MemTotal: -5 kB" would size the ring at the
         * 32 MiB ceiling off a corrupt read. Refusing non-digits sends
         * both cases to the floor. */
        if (*p < '0' || *p > '9') break;
        kb = strtoull(p, NULL, 10);
        break;
    }
    fclose(f);
    return evidence_budget_from_mem_kb(kb);
}

/* ── Lifecycle ───────────────────────────────────────────────── */

/* Caller holds g_mu. */
static void ring_free_locked(void) {
    free(g_arena);
    free(g_meta);
    g_arena = NULL;
    g_meta  = NULL;
    g_cap = g_used = g_write = 0;
    g_slots = g_tail = g_count = 0;
    g_footprint = 0;
    /* g_next_id deliberately survives: an event ID must never name two
     * different frames across the process lifetime, so a re-init
     * continues the sequence rather than restarting it. */
}

int evidence_ring_init(size_t budget_bytes) {
    if (budget_bytes < EVIDENCE_MIN_BUDGET) return -1;

    size_t slots = budget_bytes / (EV_MEAN_FRAME + sizeof(ev_slot_t));
    /* Zero slots would make `% g_slots` a division by zero on the first
     * push. Unreachable at EVIDENCE_MIN_BUDGET (which yields a dozen or
     * more), so this is a refusal against a future change to that
     * constant or to EV_MEAN_FRAME, not a case any caller can produce —
     * no test isolates it. */
    if (slots == 0) return -1;
    size_t meta_bytes = slots * sizeof(ev_slot_t);
    if (meta_bytes >= budget_bytes) return -1;
    size_t arena = budget_bytes - meta_bytes;
    /* An arena that cannot hold one maximum-size record would silently
     * truncate every large frame to the arena size instead of to
     * EVIDENCE_FRAME_MAX. EVIDENCE_MIN_BUDGET is chosen so this holds —
     * so, like the slot refusal above, no accepted budget reaches it and
     * no test isolates it. It is here because the split above, not the
     * constant, is what actually decides the arena size. */
    if (arena < EVIDENCE_FRAME_MAX) return -1;

    uint8_t   *a = malloc(arena);
    ev_slot_t *m = calloc(slots, sizeof(ev_slot_t));
    if (!a || !m) { free(a); free(m); return -1; }

    pthread_mutex_lock(&g_mu);
    ring_free_locked();
    g_arena     = a;
    g_cap       = arena;
    g_meta      = m;
    g_slots     = slots;
    g_footprint = arena + meta_bytes;
    pthread_mutex_unlock(&g_mu);
    return 0;
}

void evidence_ring_shutdown(void) {
    pthread_mutex_lock(&g_mu);
    ring_free_locked();
    pthread_mutex_unlock(&g_mu);
}

void evidence_ring_reset(void) {
    pthread_mutex_lock(&g_mu);
    g_used = g_write = 0;
    g_tail = g_count = 0;
    pthread_mutex_unlock(&g_mu);
}

/* ── Record ──────────────────────────────────────────────────── */

/* Drop the oldest record. Caller holds g_mu and has checked g_count. */
static void evict_oldest_locked(void) {
    g_used -= g_meta[g_tail].rec.cap_len;
    /* Clear the ID as the slot leaves the live window. Advancing g_tail
     * alone would leave the evicted record's metadata physically in the
     * array, so the mismatch check in evidence_ring_get() would be
     * comparing against a stale-but-real ID — defence that happens to
     * work rather than defence by construction. */
    g_meta[g_tail].rec.event_id = 0;
    g_tail  = (g_tail + 1) % g_slots;
    g_count--;
    /* An evicted record is a lost observation. #91's rule: a bounded
     * table either reports its losses or is not measured. */
    sh_evict_note(SH_EVICT_EVIDENCE_FRAME);
}

uint64_t evidence_ring_note(const uint8_t *frame,
                            uint32_t cap_len, uint32_t orig_len,
                            time_t ts_sec, long ts_usec,
                            uint16_t freq_mhz, int8_t signal_dbm) {
    if (!frame || cap_len == 0) return 0;

    pthread_mutex_lock(&g_mu);
    if (!g_arena) { pthread_mutex_unlock(&g_mu); return 0; }

    size_t store = cap_len;
    if (store > EVIDENCE_FRAME_MAX) store = EVIDENCE_FRAME_MAX;
    /* Second clamp: what makes the eviction loop below provably
     * terminate. init() guarantees g_cap >= EVIDENCE_FRAME_MAX, so this
     * is unreachable today and no test isolates it — but without it the
     * loop's termination depends on a constant relationship established
     * in another function, and `while (g_used + store > g_cap)` with
     * store > g_cap never exits. */
    if (store > g_cap)              store = g_cap;

    while (g_count == g_slots || g_used + store > g_cap)
        evict_oldest_locked();

    /* The ID is issued only once space is secured, so live IDs stay a
     * contiguous range — which is what makes the lookup below O(1)
     * rather than a scan. */
    uint64_t id = ++g_next_id;

    size_t head = (g_tail + g_count) % g_slots;
    ev_slot_t *sl = &g_meta[head];
    sl->off                = g_write;
    sl->rec.event_id       = id;
    sl->rec.ts_sec         = ts_sec;
    sl->rec.ts_usec        = ts_usec;
    sl->rec.orig_len       = orig_len;
    sl->rec.cap_len        = (uint32_t)store;
    sl->rec.freq_mhz       = freq_mhz;
    sl->rec.signal_dbm     = signal_dbm;
    /* Short of what libpcap handed over (this ring's own cap bit) OR
     * short of the length the capture reports (the kernel snapped it).
     * Either way the record is not provably the whole frame; the flag
     * does not claim which, because from the record alone it cannot be
     * told. A capture reporting orig_len below what it delivered is
     * malformed — orig_len is kept as reported and the first test still
     * flags the record. */
    sl->rec.truncated      = (store < cap_len || store < orig_len) ? 1 : 0;

    /* Circular copy: a payload straddling the arena end goes in two
     * pieces. Splitting is cheaper than refusing to wrap, which would
     * strand up to EVIDENCE_FRAME_MAX of arena on every lap. */
    size_t first = g_cap - g_write;
    if (first > store) first = store;
    memcpy(g_arena + g_write, frame, first);
    if (store > first) memcpy(g_arena, frame + first, store - first);

    g_write = (g_write + store) % g_cap;
    g_used += store;
    g_count++;
    pthread_mutex_unlock(&g_mu);
    return id;
}

/* ── Retrieval ───────────────────────────────────────────────── */

int evidence_ring_get(uint64_t event_id, evidence_rec_t *out,
                      uint8_t *buf, size_t max) {
    if (!out || event_id == 0) return -1;

    pthread_mutex_lock(&g_mu);
    if (!g_arena || g_count == 0) { pthread_mutex_unlock(&g_mu); return -1; }

    /* Two independent reasons a lookup can miss, and they are
     * deliberately BOTH enforced:
     *
     *   1. the range test — IDs are issued one per stored record, so the
     *      live ones form a contiguous [oldest, g_next_id] window, which
     *      is what makes the index below O(1) rather than a scan;
     *   2. the slot's own ID — the index is only as good as that
     *      contiguity invariant, and an evidence lookup that outlived
     *      the invariant must miss, never hand back a different frame
     *      under the requested ID.
     *
     * They overlap by design, and neither can be isolated by any input
     * reaching the public API: (1) covers every miss that an API caller
     * can construct, and (2) fires only on an invariant (1) guarantees.
     * Deleting either leaves the suite green; deleting both does not.
     * Said here because a reader who mutates one of them and sees no
     * test fail should find that documented rather than conclude the
     * check is dead. */
    uint64_t oldest = g_meta[g_tail].rec.event_id;
    if (event_id < oldest || event_id > g_next_id) {
        pthread_mutex_unlock(&g_mu);
        return -1;                      /* evicted, or never issued */
    }
    size_t k = (size_t)((g_tail + (event_id - oldest)) % g_slots);
    ev_slot_t *sl = &g_meta[k];
    if (sl->rec.event_id != event_id) {
        pthread_mutex_unlock(&g_mu);
        return -1;
    }

    *out = sl->rec;
    size_t want = sl->rec.cap_len;
    if (want > max) want = max;         /* out->cap_len still reports the rest */
    if (buf && want) {
        size_t first = g_cap - sl->off;
        if (first > want) first = want;
        memcpy(buf, g_arena + sl->off, first);
        if (want > first) memcpy(buf + first, g_arena, want - first);
    } else {
        want = 0;
    }
    pthread_mutex_unlock(&g_mu);
    return (int)want;
}

/* ── Accessors ───────────────────────────────────────────────── */

int evidence_ring_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = (int)g_count;
    pthread_mutex_unlock(&g_mu);
    return n;
}

uint64_t evidence_ring_last_id(void) {
    pthread_mutex_lock(&g_mu);
    uint64_t n = g_next_id;
    pthread_mutex_unlock(&g_mu);
    return n;
}

size_t evidence_ring_bytes_used(void) {
    pthread_mutex_lock(&g_mu);
    size_t n = g_used;
    pthread_mutex_unlock(&g_mu);
    return n;
}

size_t evidence_ring_capacity(void) {
    pthread_mutex_lock(&g_mu);
    size_t n = g_cap;
    pthread_mutex_unlock(&g_mu);
    return n;
}

size_t evidence_ring_footprint(void) {
    pthread_mutex_lock(&g_mu);
    size_t n = g_footprint;
    pthread_mutex_unlock(&g_mu);
    return n;
}
