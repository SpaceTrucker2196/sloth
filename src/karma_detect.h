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
 * Two surfaces build this string: rule_karma_ap() when it fires, and the
 * dashboard beacon panel's badge when it looks the alert up to read its
 * severity. Formatting it independently makes a silent divergence
 * possible, and a divergence here does not error — it produces a
 * dashboard that quietly stops badging lures and reads as a quiet night.
 *
 * It lives here rather than in the view because
 * src/views/dashboard_grid.c compiles only under WITH_NCURSES, which the
 * test build does not define, so nothing in that file is reachable from
 * sloth_test. Putting the shared contract in a module the suite DOES
 * link is what makes it testable at all; see tests/test_karma.c.
 *
 * `out` must hold at least ALERT_KEY_LEN. */
void karma_alert_key(const uint8_t bssid[6], char *out, size_t sz);

/* Advertised SSIDs that *one* station's PNL has to ask for before the
 * PNL signal corroborates anything (#90).
 *
 * The measure used to be the union over every nearby client, and a
 * single hit escalated KARMA_AP to CRIT. One SSID of a benign
 * multi-VAP AP landing in one passer-by's remembered list was enough,
 * and common names ("Starbucks", a carrier hotspot) land there
 * constantly — so the escalator fired on coincidence. The union says
 * "somebody around here remembers one of these names"; it is a
 * description of the neighbourhood, not evidence about this BSSID.
 *
 * PineAP Beacon Response answers a station's probes for *its whole*
 * PNL, so the attack's own shape is several of one station's networks
 * coming back from one radio. Requiring that keeps the gate on a
 * positive, candidate-specific signal, which is the rule #89/#90
 * already settled on for severity.
 *
 * Flagged as a judgement call (dark-factory.md §4.2), same as the
 * KARMA_W_* weights: 2 is the smallest count that cannot be one
 * coincidence. Deliberately not tunable — nothing has asked for it
 * yet, and KARMA_SSID_THRESH is the knob that moves candidate
 * volume. */
#define KARMA_PNL_CORROB_MIN 2

/* How many of this BSSID's advertised SSIDs appear in the union of all
 * nearby clients' preferred-network lists, counting each advertised
 * SSID at most once. Descriptive: it is what the operator is shown
 * (the `, N in client PNLs` note and the [y] PNL column) and the
 * intersection the Jaccard column divides, never a gate. Shared by
 * the KARMA_AP rule and karma_update() so the two surfaces report one
 * number — they each had their own copy of this loop before #90. */
int karma_pnl_union_hits(const sloth_state_t *s, const beacon_ap_t *a);

/* The largest number of this BSSID's advertised SSIDs found in a
 * *single* station's PNL, and that station's MAC in `best_sta_out`
 * (zeroed when the result is 0, so a caller never prints a stale MAC).
 *
 * This is the corroborating measure, and the only PNL input that moves
 * anything: >= KARMA_PNL_CORROB_MIN escalates KARMA_AP to CRIT, adds
 * the PNL confidence weight, and earns the +2 on the [y] score. One
 * rule, stated once, for both surfaces. */
int karma_pnl_client_hits(const sloth_state_t *s, const beacon_ap_t *a,
                          uint8_t best_sta_out[6]);

/* How many *distinct* IE fingerprints this BSSID's advertised SSIDs
 * carry (#187 S4), or 0 when the answer is not knowable.
 *
 * `ap_ie_fingerprint()` (src/beacon_snoop.c) hashes one SSID's security
 * posture as beaconed: encryption, pairwise and group cipher, AKM, MFP
 * and the vendor-IE hash. So this is "how many different security
 * postures came out of this one address", and the collapse to 1 is what
 * #187 calls the IE-fingerprint collapse.
 *
 * Returns 0 if any recorded SSID's fingerprint is the 0 "unknown"
 * sentinel, rather than counting the rest. A count taken over a partly
 * observed set can only *understate* the real variety, and understating
 * variety is the direction that manufactures a collapse — so the honest
 * answer for an incomplete set is "cannot say", not a smaller number.
 * (In the live beacon path this cannot happen: ap_ie_fingerprint()
 * never returns 0 and the fingerprint is written in the same step that
 * appends the SSID. It is reachable from seeded state and from a row
 * loaded with no fingerprints, which is exactly where a silent
 * miscount would go unnoticed.)
 *
 * One definition for both surfaces — the KARMA_AP rule's confidence and
 * detail, and the [y] view's IE column — for the same reason
 * karma_pnl_client_hits() is shared: two independent copies of this
 * loop would let the alert and the table state different numbers about
 * one BSSID, and nothing would error. */
int karma_ie_distinct_fp(const beacon_ap_t *a);

/* 1 when this BSSID's SSIDs collapse onto a single known fingerprint:
 * >= 2 SSIDs advertised and karma_ie_distinct_fp() == 1.
 *
 * What this is worth is narrower than it looks, and the narrow reading
 * is the one the weight and the docs are written to. A BSSID is
 * associated with exactly one BSS, and VAPs on real multi-SSID gear
 * each get their own BSSID, so the "legitimate multi-VAP AP varies its
 * IEs per VAP" contrast this signal is usually explained by describes
 * APs that never reach this code: each of their BSSIDs carries one
 * SSID and so never becomes a candidate. The 802.11ax Multiple BSSID
 * set is the one shape that does put several SSIDs behind one
 * transmitted BSSID, and sloth does not decode its nontransmitted
 * profiles (docs/wiki/fragattacks.md).
 *
 * So the benign population that actually crosses KARMA_SSID_THRESH is
 * a BSS renamed over a long session, or SSID-cycling hotspot gear —
 * and those keep one security posture, so they collapse exactly like a
 * lure does. Collapse is therefore weak, same-direction corroboration
 * and never a severity escalator; the sharper reading is the converse,
 * that genuine IE *variety* argues against one spoofing radio. See
 * research/papers/mbssid-per-bss-ie-variation.md. */
int karma_ie_collapsed(const beacon_ap_t *a);

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
