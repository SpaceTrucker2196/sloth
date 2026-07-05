#ifndef KARMA_DETECT_H
#define KARMA_DETECT_H

#include "sloth.h"

/* Rebuild s->karma_aps[] from the current beacon table, client PNLs, and
 * deauth ring. One row per BSSID beaconing >= KARMA_SSID_THRESH distinct
 * SSIDs — the PineAP / mdk4 / airbase-ng lure pattern. Rows are ranked
 * by score (strongest first). Purely passive synthesis: reads state,
 * writes only the karma table. Call once per poll. */
void karma_update(sloth_state_t *s);

/* Minimum distinct SSIDs from one BSSID to be a KARMA candidate — kept
 * in sync with the KARMA_AP alert rule. */
#define KARMA_SSID_THRESH 3

#endif /* KARMA_DETECT_H */
