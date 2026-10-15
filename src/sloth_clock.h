#ifndef SLOTH_CLOCK_H
#define SLOTH_CLOCK_H

/* The one clock seam (#109).
 *
 * Two clocks, two jobs. Wall time is evidence: first_seen / last_seen,
 * export timestamps, the stamp on a taint. Monotonic time is duration:
 * windows, TTLs, cooldowns, staleness. Mixing them is a bug that no
 * test can see while every caller reads the real clocks — the
 * evil-twin taint was stamped through the seam and checked against
 * time(NULL), so under an injected clock it never matched, and in
 * production an NTP step mis-aged its TTL.
 *
 * Every direct time(NULL) / clock_gettime() in src/ is a site a test
 * cannot drive. Modules migrate here one at a time;
 * tests/test_clock_seam.c holds the list of those that have and fails
 * if one regresses. The #88 flood_wall() / flood_mono_ms() /
 * flood_test_set_clock() names in flood_window.h forward here until
 * their last caller moves. */

#include <stdint.h>
#include <time.h>

/* Wall-clock seconds. Evidence and display only — never a duration. */
time_t sloth_wall(void);

/* CLOCK_MONOTONIC milliseconds. Arbitrary epoch; only differences mean
 * anything. */
uint64_t sloth_mono_ms(void);

/* Test seam: replace either clock. NULL restores the real one. Swapped
 * only by tests, before any capture thread exists — the pointers are
 * read without a lock. */
void sloth_clock_test_set(uint64_t (*mono)(void), time_t (*wall)(void));

#endif /* SLOTH_CLOCK_H */
