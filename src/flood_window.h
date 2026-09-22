#ifndef FLOOD_WINDOW_H
#define FLOOD_WINDOW_H

/* Sliding-window rate detection shared by the deauth and probe flood
 * detectors (#88).
 *
 * "K frames in any W-second window" is answered exactly by keeping the
 * K most recent frame times: the threshold is met at the moment a frame
 * arrives iff the K-th most recent frame (counting this one) is less
 * than W old. A counter that resets when the gap since the previous
 * frame exceeds W answers a different question — "K frames in a chain
 * whose adjacent gaps are each <= W" — and trips on frames at
 * t = 0, 4, 8, 12, 16 although no 5 s interval holds five of them.
 *
 * Durations run on CLOCK_MONOTONIC. Wall-clock time is evidence only
 * (first_seen / last_seen / flood_last shown to the operator and
 * exported): an NTP step or a manual date change must neither create a
 * flood nor dissolve one. Both clocks go through one seam so tests can
 * drive the windows deterministically without sleeping. */

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* Monotonic milliseconds. Arbitrary epoch — only differences mean
 * anything. */
uint64_t flood_mono_ms(void);

/* Wall-clock seconds, for evidence and display only. */
time_t flood_wall(void);

/* Test seam: replace either clock. NULL restores the real one. */
typedef uint64_t (*flood_mono_fn)(void);
typedef time_t   (*flood_wall_fn)(void);
void flood_test_set_clock(flood_mono_fn mono, flood_wall_fn wall);

/* Count one frame at now_ms. Returns 1 iff, including this frame, at
 * least `thresh` counted frames fall inside the half-open window
 * (now_ms - win_ms, now_ms]. thresh must be 1..FLOOD_WIN_CAP. */
int flood_window_note(flood_window_t *w, uint64_t now_ms,
                      int thresh, uint32_t win_ms);

/* Counted frames inside (now_ms - win_ms, now_ms], capped at
 * FLOOD_WIN_CAP. Reads only — a window decays as time passes, with no
 * further frame needed. */
int flood_window_count(const flood_window_t *w, uint64_t now_ms,
                       uint32_t win_ms);

/* 1 while the threshold was last met less than hold_ms before now_ms. */
int flood_window_active(const flood_window_t *w, uint64_t now_ms,
                        uint32_t hold_ms);

/* ── Probe-request flood (#88) ───────────────────────────── */

/* Probe clients carry their window in probe_client_t because the probe
 * table *is* the exported snapshot. These two are what the capture
 * thread's recorder and snapshot call; they live here, not in
 * src/capture/probe.c, so the test build (no libpcap) exercises the
 * same code the capture path runs. */
void probe_flood_note(probe_client_t *c, uint64_t now_ms, time_t wall);
void probe_flood_refresh(probe_client_t *c, uint64_t now_ms);

#endif /* FLOOD_WINDOW_H */
