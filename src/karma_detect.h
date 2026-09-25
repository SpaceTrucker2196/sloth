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

/* Correlation window for the deauth-then-lure chain (#30), shared with
 * the KARMA_AP alert rule and karma_update()'s deauth_chain flag. */
#define KARMA_DEAUTH_WIN_SECS 60

/* Is there a deauth-then-lure chain naming a victim of *this* candidate
 * specifically (#90)? A bare "some flood happened somewhere recently"
 * credits every KARMA candidate in range with any unrelated victim's
 * bad luck, which is the false-positive this replaces: a deauth flood
 * on one BSSID and a benign SSID-cycling AP across the room share
 * nothing but timing.
 *
 * A real chain needs a *shared victim*: someone deauthed off a
 * different BSSID inside the correlation window, who this candidate
 * can independently be shown to be luring — either the victim's PNL
 * already asks for one of the candidate's advertised SSIDs (the PineAP
 * Beacon-Response setup: deauth off the real AP, answer the
 * reconnection probe), or the victim has since associated with the
 * candidate (the lure worked).
 *
 * Returns 1 and, if `victim_out` is non-NULL, copies the victim MAC. */
int karma_deauth_lure_victim(const sloth_state_t *s,
                             const beacon_ap_t *candidate, time_t now,
                             uint8_t victim_out[6]);

#endif /* KARMA_DETECT_H */
