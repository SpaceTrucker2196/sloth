#ifndef STAB_H
#define STAB_H

#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "sensor_health.h"

/* ── stab_t: one bounded, keyed synthesis table (#110) ────────────────
 *
 * sloth keeps dozens of module-level static tables with the same shape:
 * a fixed array of rows, a count, a key the rows are looked up by, and a
 * `last_seen` stamp. What differed between them was only what happened
 * when the array filled, and that difference was never a design choice
 * — it was whichever idiom the author of that file copied. Eight
 * snoopers evicted the oldest row by `last_seen` without telling the
 * sensor-health tally; three tables (mDNS, NBNS, the ARP-spoof history)
 * refused every new key for the life of the process once full, so
 * after enough uptime those detectors were blind to anything new and
 * nothing reported it. sensor_health.h states the rule this exists to
 * enforce: a table either reaches an `evict_<name>` tally or its loss
 * is unmeasured. Here the tally is a required field, so a table built
 * on this type cannot forget it.
 *
 * Three policies, chosen per table:
 *
 *   STAB_OLDEST        — on full, the row with the smallest `last_seen`
 *                        is overwritten and the loss is tallied. The
 *                        right choice when the key space is adversary-
 *                        controlled (remote IPs, peer pairs): a spray of
 *                        new identities churns the table but can never
 *                        make it allocate or refuse.
 *   STAB_REFUSE_AGING  — on full, a row is reclaimed only if it has not
 *                        been seen for `age_secs`; otherwise the new key
 *                        is REFUSED and the refusal is tallied. For
 *                        tables whose rows name local, long-lived things
 *                        (an mDNS service, a NetBIOS name) where a row
 *                        seen minutes ago is worth more than one the
 *                        segment has only just started advertising. The
 *                        tally therefore counts observations that did not
 *                        land, not rows reclaimed: a reclaimed row had
 *                        aged out by policy, the way scan.c's TTL rows
 *                        do, and nothing current was lost.
 *   STAB_RING          — on full, overwrite in insertion order and tally.
 *                        For tables where arrival order is the meaning
 *                        and `last_seen` is not maintained.
 *
 * Locking: `mu` NULL means the caller owns the thread model, which is
 * what every current user does — each snooper already holds its own
 * mutex across the get-and-update, and the row pointer this type hands
 * back is only safe to write under that same lock. A non-NULL `mu` is
 * taken around the table's bookkeeping only (find, allocate, snapshot,
 * clear); it cannot protect a caller's writes to a returned row after
 * the call returns, so a caller that passes one must still not mutate
 * rows from more than one thread. */

typedef enum { STAB_OLDEST, STAB_REFUSE_AGING, STAB_RING } stab_policy_t;

typedef struct {
    void           *rows;          /* caller's static array of `cap` rows */
    size_t          row_sz;
    int             cap;           /* > 0 */
    int             n;             /* rows populated, 0..cap */
    size_t          last_seen_off; /* offsetof(row_t, <time_t last_seen>) */
    stab_policy_t   policy;
    time_t          age_secs;      /* STAB_REFUSE_AGING only; ignored otherwise */
    sh_evict_t      tally;         /* required: the kind every loss is noted under */
    pthread_mutex_t *mu;           /* NULL = caller's thread model */
    int           (*key_eq)(const void *row, const void *key);
    int             ring_head;     /* STAB_RING only: next slot to overwrite */
} stab_t;

/* Declare the row array and the table together. `ls_field` must be a
 * time_t member of row_t — the typedef line fails the build with a
 * negative array size if it is not, which is what stands in for a
 * static assertion in C99. `eq` is a key_eq function already declared.
 * `age` is only meaningful under STAB_REFUSE_AGING. */
#define STAB_DECL_AGE(name, row_t, CAP, ls_field, pol, age, kind, mu, eq)     \
    typedef char name##_ls_is_time_t[                                        \
        sizeof(((row_t *)0)->ls_field) == sizeof(time_t) ? 1 : -1];          \
    static row_t  name##_rows[CAP];                                          \
    static stab_t name = { name##_rows, sizeof(row_t), (CAP), 0,             \
                           offsetof(row_t, ls_field), (pol), (age), (kind),  \
                           (mu), (eq), 0 }

#define STAB_DECL(name, row_t, CAP, ls_field, pol, kind, mu, eq)              \
    STAB_DECL_AGE(name, row_t, CAP, ls_field, pol, 0, kind, mu, eq)

/* Row whose key_eq(row, key) is true, or NULL. Never allocates. */
void *stab_find(stab_t *t, const void *key);

/* Find-or-allocate. An existing row is returned with *created = 0 and is
 * not touched. Otherwise a row is allocated per the policy, zeroed, its
 * last_seen stamped `now`, and returned with *created = 1 — the caller
 * then fills the key fields, since this type does not know their layout.
 * Returns NULL only under STAB_REFUSE_AGING when the table is full and
 * no row is older than age_secs; that refusal has already been tallied.
 * `created` may be NULL. */
void *stab_get(stab_t *t, const void *key, time_t now, int *created);

/* Copy up to `max` rows to `out` in slot order; returns the count copied.
 * Slot order is stable for a row's lifetime, so views keyed on index
 * behave as the hand-rolled tables did. */
int   stab_snapshot(stab_t *t, void *out, int max);

int   stab_count(const stab_t *t);

/* Row at slot i (0 <= i < stab_count), or NULL. */
void *stab_at(stab_t *t, int i);

/* Empty the table and zero every row. Does not touch the tally — a
 * counter that clears has no lifetime meaning (sensor_health.h). */
void  stab_clear(stab_t *t);

#endif /* STAB_H */
