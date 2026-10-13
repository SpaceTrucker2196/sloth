#ifndef KARMA_DETECT_H
#define KARMA_DETECT_H

#include <stddef.h>
#include "sloth.h"
#include "tool_fingerprint.h"

/* Rebuild s->karma_aps[] from the current beacon table, client PNLs, and
 * deauth ring. One row per BSSID beaconing >= KARMA_SSID_THRESH distinct
 * SSIDs — the PineAP / mdk4 / airbase-ng lure pattern. Rows are ranked
 * by score (strongest first). Purely passive synthesis: reads state,
 * writes only the karma table. Call once per poll. */
void karma_update(sloth_state_t *s);

/* Minimum distinct SSIDs from one BSSID to be a KARMA candidate — kept
 * in sync with the KARMA_AP alert rule. */
#include "tune.h"
/* Tunable since #82: karma.ssid_thresh. */
#define KARMA_SSID_THRESH ((int)tune_val(TUNE_KARMA_SSID_THRESH))

/* Correlation window for the deauth-then-lure chain (#30), shared with
 * the KARMA_AP alert rule and karma_update()'s deauth_chain flag. */
#define KARMA_DEAUTH_WIN_SECS 60

/* The alert key for a KARMA candidate, written in ONE place (#90).
 *
 * Two surfaces build this string: rule_karma_ap() when it fires, and
 * the dashboard beacon panel's badge when it looks the alert up to read
 * its severity. They used to format it independently, which makes a
 * silent divergence possible — and a divergence here does not produce
 * an error, it produces a dashboard that quietly stops badging lures
 * and looks like a quiet night.
 *
 * It lives here rather than in the view because src/views/dashboard_grid.c
 * is compiled only under WITH_NCURSES, which the test build does not
 * define, so nothing in that file is reachable from sloth_test. Putting
 * the shared contract in a module the suite DOES link is what makes it
 * testable at all; see tests/test_karma.c.
 *
 * `out` must hold at least ALERT_KEY_LEN. */
void karma_alert_key(const uint8_t bssid[6], char *out, size_t sz);

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

/* The tool signature this candidate matches, or NULL (#68, #90). One
 * observation builder shared by the KARMA_AP rule and the [y] view, so
 * the alert and the table cannot attribute one BSSID to two different
 * rows. `*conf` gets the match confidence; `*pmkid_out`, when non-NULL,
 * whether a PMKID was harvested from this BSSID (a precondition some
 * rows gate on, and the alert's informational `+PMKID` note). */
const sloth_tool_sig_t *karma_tool_match(const sloth_state_t *s,
                                         const beacon_ap_t *candidate,
                                         sloth_tool_conf_t *conf,
                                         int *pmkid_out);

#endif /* KARMA_DETECT_H */
