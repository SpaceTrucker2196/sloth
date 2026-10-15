#include "sloth_clock.h"

/* The only time(NULL) and clock_gettime() that belong in src/ once the
 * migration in #109 completes. */

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

void sloth_clock_test_set(uint64_t (*mono)(void), time_t (*wall)(void)) {
    g_mono = mono ? mono : real_mono_ms;
    g_wall = wall ? wall : real_wall;
}
