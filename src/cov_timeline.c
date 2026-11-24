#include <string.h>
#include "cov_timeline.h"

/* The two histories of cov_timeline.h. Rings in arrival order, which is
 * time order: a note earlier than its predecessor is clamped to it. */

typedef struct {
    int64_t  ms;
    uint16_t freq;
    uint8_t  radio;
} tl_dwell_t;

typedef struct {
    int64_t  ms;
    uint64_t total;
} tl_drop_t;

static tl_dwell_t g_dw[COV_TL_DWELLS];
static int        g_dw_head, g_dw_n;     /* next slot, entries held */
static tl_drop_t  g_dr[COV_TL_DROPS];
static int        g_dr_head, g_dr_n;

void cov_tl_reset(void) {
    memset(g_dw, 0, sizeof(g_dw));
    memset(g_dr, 0, sizeof(g_dr));
    g_dw_head = g_dw_n = 0;
    g_dr_head = g_dr_n = 0;
}

int cov_tl_dwell_count(void) { return g_dw_n; }
int cov_tl_drop_count(void)  { return g_dr_n; }

static const tl_dwell_t *dw_at(int i);

int cov_tl_radio_last(int radio, int *freq_mhz, int64_t *wall_ms) {
    for (int i = g_dw_n - 1; i >= 0; i--) {
        const tl_dwell_t *d = dw_at(i);
        if (d->radio != radio) continue;
        if (freq_mhz) *freq_mhz = d->freq;
        if (wall_ms)  *wall_ms  = d->ms;
        return 1;
    }
    return 0;
}

/* Entry i of a ring, 0 the oldest. */
static const tl_dwell_t *dw_at(int i) {
    return &g_dw[(g_dw_head - g_dw_n + i + COV_TL_DWELLS) % COV_TL_DWELLS];
}
static const tl_drop_t *dr_at(int i) {
    return &g_dr[(g_dr_head - g_dr_n + i + COV_TL_DROPS) % COV_TL_DROPS];
}

void cov_tl_hop_note(int radio, int freq_mhz, int64_t wall_ms) {
    if (radio < 0 || radio >= COV_TL_RADIOS) return;
    if (freq_mhz < 0 || freq_mhz > 0xFFFF) freq_mhz = 0;
    if (g_dw_n > 0 && wall_ms < dw_at(g_dw_n - 1)->ms) wall_ms = dw_at(g_dw_n - 1)->ms;
    tl_dwell_t *e = &g_dw[g_dw_head];
    e->ms    = wall_ms;
    e->freq  = (uint16_t)freq_mhz;
    e->radio = (uint8_t)radio;
    g_dw_head = (g_dw_head + 1) % COV_TL_DWELLS;
    if (g_dw_n < COV_TL_DWELLS) g_dw_n++;
}

void cov_tl_drops_note(int64_t wall_ms, uint64_t total) {
    if (g_dr_n > 0 && wall_ms < dr_at(g_dr_n - 1)->ms) wall_ms = dr_at(g_dr_n - 1)->ms;
    tl_drop_t *e = &g_dr[g_dr_head];
    e->ms    = wall_ms;
    e->total = total;
    g_dr_head = (g_dr_head + 1) % COV_TL_DROPS;
    if (g_dr_n < COV_TL_DROPS) g_dr_n++;
}

/* The pieces of [t0, t1] some radio spent on the channel, at most
 * TL_SPANS of them. A window holding more dwells on one channel than
 * that spans dozens of hop cycles; the pieces past the bound are left
 * out, which can only make the window read less covered than it was,
 * never more. */
#define TL_SPANS 256

int64_t cov_tl_uncovered_ms(int freq_mhz, int64_t t0_ms, int64_t t1_ms) {
    if (g_dw_n == 0) return -1;
    if (t1_ms <= t0_ms) return 0;
    int64_t s[TL_SPANS], e[TL_SPANS];
    int     n = 0;
    /* Newest first: a dwell ends where the same radio's next one
     * starts, and the newest of each radio runs to the window's end. */
    int64_t next[COV_TL_RADIOS];
    for (int r = 0; r < COV_TL_RADIOS; r++) next[r] = t1_ms;
    for (int i = g_dw_n - 1; i >= 0; i--) {
        const tl_dwell_t *d = dw_at(i);
        int64_t end = next[d->radio];
        next[d->radio] = d->ms;
        if (d->freq == 0 || d->freq != (uint16_t)freq_mhz) continue;
        int64_t a = d->ms > t0_ms ? d->ms : t0_ms;
        int64_t b = end < t1_ms ? end : t1_ms;
        if (b <= a || n == TL_SPANS) continue;
        s[n] = a; e[n] = b; n++;
    }
    /* The walk above went newest first, so the pieces are in descending
     * start order, the insertion sort's worst case (quadratic, on the
     * poll loop, per cited channel of every finding judged). Reversed,
     * one radio's pieces are ascending and the sort only interleaves
     * the radios: near-linear. */
    for (int i = 0, j = n - 1; i < j; i++, j--) {
        int64_t ts = s[i], te = e[i];
        s[i] = s[j]; e[i] = e[j];
        s[j] = ts;   e[j] = te;
    }
    /* Union of the pieces: sorted by start (insertion), merged. */
    for (int i = 1; i < n; i++) {
        int64_t ks = s[i], ke = e[i];
        int j = i - 1;
        while (j >= 0 && s[j] > ks) { s[j + 1] = s[j]; e[j + 1] = e[j]; j--; }
        s[j + 1] = ks; e[j + 1] = ke;
    }
    int64_t covered = 0, cs = 0, ce = 0;
    for (int i = 0; i < n; i++) {
        if (i == 0 || s[i] > ce) {
            covered += ce - cs;
            cs = s[i]; ce = e[i];
        } else if (e[i] > ce) {
            ce = e[i];
        }
    }
    covered += ce - cs;
    return (t1_ms - t0_ms) - covered;
}

int cov_tl_drops_in(int64_t t0_ms, int64_t t1_ms) {
    int before = -1, after = -1;
    for (int i = 0; i < g_dr_n; i++) {
        const tl_drop_t *d = dr_at(i);
        if (d->ms <= t0_ms) before = i;
        if (after < 0 && d->ms >= t1_ms) after = i;
    }
    if (before < 0) return -1;
    if (after < 0) after = g_dr_n - 1;
    if (after <= before) return -1;
    return dr_at(after)->total > dr_at(before)->total ? 1 : 0;
}
