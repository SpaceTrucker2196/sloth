#ifndef AUTH_TRACK_H
#define AUTH_TRACK_H

#include <stdint.h>
#include <time.h>

/* Passive 802.11 authentication-frame flood tracker (roadmap B1).
 *
 * An auth-request flood (mdk3 'a' mode, or a spoofed-source association
 * DoS) sprays authentication frames at an AP to exhaust its association /
 * state table so legitimate clients can't join. A healthy AP sees only the
 * occasional auth frame (a roam, a reconnect). We count auth frames per
 * destination BSSID over a sliding window and flag the outlier. Purely
 * passive — we only observe frames already on the air. */

/* Record one observed auth frame addressed to `bssid`. Thread-safe. */
void auth_observe(const uint8_t bssid[6], time_t now);

/* If some BSSID received >= thresh auth frames within the last window_s
 * seconds, copy the worst offender into out_bssid and return its count;
 * otherwise return 0. Thread-safe. */
int  auth_flood_bssid(time_t now, int window_s, int thresh, uint8_t out_bssid[6]);

/* Reset all state (tests). */
void auth_clear(void);

#endif /* AUTH_TRACK_H */
