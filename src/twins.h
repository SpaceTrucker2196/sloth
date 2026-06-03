#ifndef TWINS_H
#define TWINS_H

#include "sloth.h"

/* Phase 5 — materialised view of same-cipher same-SSID diff-OUI
 * twin pairs. Walks s->beacon_aps to derive the set, merges in the
 * Phase 2 hash-mismatch signal, Phase 3 RSSI swing, and Phase 4
 * taint state. Idempotent — safe to call once per poll.
 *
 * Drops OPEN networks (the same rule as rule_evil_twin's WARN branch).
 * Caps at MAX_TWIN_EPISODES; further pairs are silently ignored. */
void twins_snapshot(sloth_state_t *s);

/* Test-only: clear any process-wide cached state (currently none —
 * provided for parity with other modules). */
void twins_clear(void);

#endif /* TWINS_H */
