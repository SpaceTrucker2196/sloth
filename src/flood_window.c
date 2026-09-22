#include <time.h>
#include "sloth.h"
#include "flood_window.h"

/* ── Clock seam ──────────────────────────────────────────── */

static uint64_t real_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static time_t real_wall(void) { return time(NULL); }

/* Swapped only by tests, before any capture thread exists. */
static flood_mono_fn g_mono = real_mono_ms;
static flood_wall_fn g_wall = real_wall;

uint64_t flood_mono_ms(void) { return g_mono(); }
time_t   flood_wall(void)    { return g_wall(); }

void flood_test_set_clock(flood_mono_fn mono, flood_wall_fn wall) {
    g_mono = mono ? mono : real_mono_ms;
    g_wall = wall ? wall : real_wall;
}

/* ── Window ──────────────────────────────────────────────── */

/* The k-th most recent stored time, k = 1 for the newest. */
static uint64_t nth_recent(const flood_window_t *w, int k) {
    int idx = ((int)w->head - k) % FLOOD_WIN_CAP;
    if (idx < 0) idx += FLOOD_WIN_CAP;
    return w->ts_ms[idx];
}

/* Monotonic time never runs backwards; a caller mixing clocks must not
 * turn that into a huge unsigned age. */
static uint64_t age_ms(uint64_t now_ms, uint64_t then_ms) {
    return now_ms > then_ms ? now_ms - then_ms : 0;
}

int flood_window_note(flood_window_t *w, uint64_t now_ms,
                      int thresh, uint32_t win_ms) {
    if (thresh < 1) thresh = 1;
    if (thresh > FLOOD_WIN_CAP) thresh = FLOOD_WIN_CAP;
    w->ts_ms[w->head] = now_ms;
    w->head = (uint8_t)((w->head + 1) % FLOOD_WIN_CAP);
    if (w->n < FLOOD_WIN_CAP) w->n++;
    if (w->n < thresh) return 0;
    if (age_ms(now_ms, nth_recent(w, thresh)) >= win_ms) return 0;
    w->tripped = 1;
    w->trip_ms = now_ms;
    return 1;
}

int flood_window_count(const flood_window_t *w, uint64_t now_ms,
                       uint32_t win_ms) {
    int c = 0;
    for (int k = 1; k <= w->n; k++) {
        if (age_ms(now_ms, nth_recent(w, k)) >= win_ms) break;
        c++;
    }
    return c;
}

int flood_window_active(const flood_window_t *w, uint64_t now_ms,
                        uint32_t hold_ms) {
    return w->tripped && age_ms(now_ms, w->trip_ms) < hold_ms;
}

/* ── Probe-request flood ─────────────────────────────────── */

#define PROBE_WIN_MS  ((uint32_t)PROBE_FLOOD_WIN_SECS  * 1000u)
#define PROBE_HOLD_MS ((uint32_t)PROBE_FLOOD_HOLD_SECS * 1000u)

void probe_flood_note(probe_client_t *c, uint64_t now_ms, time_t wall) {
    flood_window_t *w = &c->burst_win;
    if (!flood_window_note(w, now_ms, PROBE_FLOOD_FRAMES, PROBE_WIN_MS))
        return;
    /* Evidence for the rule and the operator: the PROBE_FLOOD_FRAMES
     * requests that met the threshold, and how far apart the first and
     * last of them were. */
    int k = PROBE_FLOOD_FRAMES;
    int idx = ((int)w->head - k) % FLOOD_WIN_CAP;
    if (idx < 0) idx += FLOOD_WIN_CAP;
    c->burst_frames  = k;
    c->burst_span_ms = (uint32_t)age_ms(now_ms, w->ts_ms[idx]);
    c->flood         = 1;
    c->flood_last    = wall;
}

void probe_flood_refresh(probe_client_t *c, uint64_t now_ms) {
    c->flood = flood_window_active(&c->burst_win, now_ms, PROBE_HOLD_MS);
}
