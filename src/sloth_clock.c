#include "sloth_clock.h"

/* The only libc clock reads in src/ (#109). tests/test_clock_seam.c
 * walks the tree and exempts this file alone. */

static uint64_t real_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static time_t real_wall(void) { return time(NULL); }

static int64_t real_wall_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + (int64_t)(ts.tv_nsec / 1000000);
}

static uint64_t (*g_mono)(void) = real_mono_ms;
static time_t   (*g_wall)(void) = real_wall;
static int64_t  (*g_wall_ms)(void) = NULL;

time_t   sloth_wall(void)    { return g_wall(); }
uint64_t sloth_mono_ms(void) { return g_mono(); }

int64_t sloth_wall_ms(void) {
    if (g_wall_ms) return g_wall_ms();
    if (g_wall != real_wall) return (int64_t)g_wall() * 1000;
    return real_wall_ms();
}

void sloth_mono_ts(struct timespec *out) {
    uint64_t ms = g_mono();
    out->tv_sec  = (time_t)(ms / 1000u);
    out->tv_nsec = (long)(ms % 1000u) * 1000000L;
}

void sloth_clock_test_set(uint64_t (*mono)(void), time_t (*wall)(void)) {
    g_mono = mono ? mono : real_mono_ms;
    g_wall = wall ? wall : real_wall;
    g_wall_ms = NULL;
}

void sloth_clock_test_set_wall_ms(int64_t (*wall_ms)(void)) {
    g_wall_ms = wall_ms;
}
