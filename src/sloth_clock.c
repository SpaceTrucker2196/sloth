#include "sloth_clock.h"

/* The only libc clock reads in src/ (#109). tests/test_clock_seam.c
 * walks the tree and exempts this file alone. */

static uint64_t real_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static time_t real_wall(void) { return time(NULL); }

static uint64_t (*g_mono)(void) = real_mono_ms;
static time_t   (*g_wall)(void) = real_wall;

time_t   sloth_wall(void)    { return g_wall(); }
uint64_t sloth_mono_ms(void) { return g_mono(); }

void sloth_mono_ts(struct timespec *out) {
    uint64_t ms = g_mono();
    out->tv_sec  = (time_t)(ms / 1000u);
    out->tv_nsec = (long)(ms % 1000u) * 1000000L;
}

void sloth_clock_test_set(uint64_t (*mono)(void), time_t (*wall)(void)) {
    g_mono = mono ? mono : real_mono_ms;
    g_wall = wall ? wall : real_wall;
}
