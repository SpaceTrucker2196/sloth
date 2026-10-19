#include <string.h>
#include "stab.h"

/* Contract and rationale in stab.h. */

static void *row_of(const stab_t *t, int i) {
    return (char *)t->rows + (size_t)i * t->row_sz;
}

static time_t *ls_of(const stab_t *t, int i) {
    return (time_t *)((char *)row_of(t, i) + t->last_seen_off);
}

static void lock(const stab_t *t)   { if (t->mu) pthread_mutex_lock(t->mu); }
static void unlock(const stab_t *t) { if (t->mu) pthread_mutex_unlock(t->mu); }

static int find_idx(const stab_t *t, const void *key) {
    for (int i = 0; i < t->n; i++)
        if (t->key_eq(row_of(t, i), key)) return i;
    return -1;
}

/* Strict `<`: among equal stamps the lowest slot wins, so a table filled
 * within one second evicts in insertion order, deterministically. */
static int oldest_idx(const stab_t *t) {
    int slot = 0;
    for (int i = 1; i < t->n; i++)
        if (*ls_of(t, i) < *ls_of(t, slot)) slot = i;
    return slot;
}

void *stab_find(stab_t *t, const void *key) {
    lock(t);
    int i = find_idx(t, key);
    unlock(t);
    return i < 0 ? NULL : row_of(t, i);
}

void *stab_get(stab_t *t, const void *key, time_t now, int *created) {
    if (created) *created = 0;
    lock(t);
    int i = find_idx(t, key);
    if (i >= 0) {
        unlock(t);
        return row_of(t, i);
    }

    int slot;
    if (t->n < t->cap) {
        slot = t->n++;
    } else {
        switch (t->policy) {
        case STAB_REFUSE_AGING:
            /* The oldest row is the only candidate: if it is still
             * fresh, every row is, and the new key loses. That is the
             * observation the tally records — not the reclaim below,
             * which retires a row nobody has seen for age_secs. */
            slot = oldest_idx(t);
            if (now - *ls_of(t, slot) < t->age_secs) {
                sh_evict_note(t->tally);
                unlock(t);
                return NULL;
            }
            break;
        case STAB_RING:
            slot = t->ring_head;
            t->ring_head = (t->ring_head + 1) % t->cap;
            sh_evict_note(t->tally);
            break;
        case STAB_OLDEST:
        default:
            slot = oldest_idx(t);
            sh_evict_note(t->tally);
            break;
        }
    }

    void *row = row_of(t, slot);
    memset(row, 0, t->row_sz);
    /* Stamp on creation so a caller that forgets cannot leave a fresh
     * row at last_seen 0, where STAB_OLDEST would pick it as the next
     * victim and STAB_REFUSE_AGING would reclaim it immediately. */
    *ls_of(t, slot) = now;
    if (created) *created = 1;
    unlock(t);
    return row;
}

int stab_snapshot(stab_t *t, void *out, int max) {
    lock(t);
    int n = t->n < max ? t->n : max;
    if (n < 0) n = 0;
    if (n > 0) memcpy(out, t->rows, (size_t)n * t->row_sz);
    unlock(t);
    return n;
}

int stab_count(const stab_t *t) {
    lock(t);
    int n = t->n;
    unlock(t);
    return n;
}

void *stab_at(stab_t *t, int i) {
    lock(t);
    void *row = (i >= 0 && i < t->n) ? row_of(t, i) : NULL;
    unlock(t);
    return row;
}

/* Caller holds the lock. */
static void del_idx(stab_t *t, int i) {
    int last = t->n - 1;
    if (i != last) memcpy(row_of(t, i), row_of(t, last), t->row_sz);
    memset(row_of(t, last), 0, t->row_sz);
    t->n--;
}

int stab_del(stab_t *t, void *row) {
    if (!row || t->policy == STAB_RING) return 0;
    lock(t);
    /* Equality, not subtraction: a pointer from outside the array has
     * no defined difference from it, and a foreign row must be a no-op
     * rather than undefined behaviour. */
    int ok = 0;
    for (int i = 0; i < t->n; i++) {
        if (row_of(t, i) == row) { del_idx(t, i); ok = 1; break; }
    }
    unlock(t);
    return ok;
}

int stab_expire(stab_t *t, time_t now, time_t age) {
    if (t->policy == STAB_RING) return 0;
    lock(t);
    int removed = 0;
    /* Walk down so the row del_idx() swaps in from the end has already
     * been examined. */
    for (int i = t->n - 1; i >= 0; i--) {
        if (now - *ls_of(t, i) > age) { del_idx(t, i); removed++; }
    }
    unlock(t);
    return removed;
}

void stab_clear(stab_t *t) {
    lock(t);
    t->n = 0;
    t->ring_head = 0;
    memset(t->rows, 0, (size_t)t->cap * t->row_sz);
    unlock(t);
}
