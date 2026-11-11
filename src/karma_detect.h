#ifndef KARMA_DETECT_H
#define KARMA_DETECT_H

#include <stddef.h>
#include "sloth.h"
#include "tool_fingerprint.h"
#include "dot11_frame.h"

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

/* ── Directed probe-response forgery (#187 S2) ─────────────────
 *
 * Dai Zovi & Macaulay (2005) built KARMA as "a special access point
 * that responded to any Probe Request, allowing us to serve any SSID
 * requested by a client within range"; airbase-ng's -P "causes the
 * fake access point to respond to all probes regardless of the ESSIDs
 * specified" (research/papers/daizovi-macaulay-2005-karma.md,
 * research/tools/airbase-ng.md). Both beacon one
 * name, or none, and answer the rest. KARMA_AP reads the beacon
 * history only, so it is structurally blind to that radio (its
 * assessment says so); this is the observable that is not.
 *
 * What is recorded: a Probe Response (subtype 5) whose DA is a station
 * that sent a *directed* Probe Request (subtype 4) for exactly that
 * SSID within KARMA_FORGE_PAIR_S, from a BSSID whose current name (as
 * the beacon table knows it, revealed hidden names included) is not
 * that SSID. An AP answering for its own name, hidden or not, never
 * reaches the table; nor does any answer to a wildcard probe, which
 * carries the responder's own SSID. Whether the BSSID ever beaconed the
 * name is judged later, at rule time, against its whole beacon history.
 *
 * Fed from the monitor thread (src/capture/probe.c) and from tests.
 * Durations run on sloth_mono_ms() read at observation, for both frame
 * kinds, so an offline replay's capture timestamps cannot split a pair
 * and a wall step cannot age a row; sloth_wall() stamps first/last seen
 * for display only. */
/* `ssid` is the frame's SSID element as the caller's own element walk
 * read it (dot11_ie_ssid(): the probe request's elements, or the probe
 * response's after its 12-octet fixed part), "" for none. Passed in
 * rather than re-read so a frame is walked once and an overrun is
 * tallied once (#126). */
void karma_observe_frame(const dot11_frame_t *f, const char *ssid);
void karma_forge_snapshot(sloth_state_t *s);
void karma_forge_clear(void);
/* Stations, answers and BSS rows displaced by the bounds since the last
 * clear, for tests and the sensor's own accounting. */
unsigned long karma_forge_evictions(void);

/* A response this long after the request is not the answer to it. The
 * real interval is milliseconds — a probing station dwells on a channel
 * for MLME-SCAN's ProbeDelay/MinChannelTime/MaxChannelTime, all in TU —
 * and the bound is generous because a station repeats its directed
 * probes and an AP may answer any repeat: the pairing only has to say
 * "this station asked for this name just now". Monotonic clock. Not
 * tunable: it encodes the protocol, not a judgement about a site. */
#define KARMA_FORGE_PAIR_S 5

/* Directed probe requests remembered for pairing. A flood of random
 * station MACs churns this ring and can make a real answer unpairable,
 * which loses a detection; it never manufactures one, because an
 * unpaired response is ignored. */
#define KARMA_PREQ_RING 128

/* How many distinct never-beaconed SSIDs one BSSID must have answered
 * before KARMA_PROBE_FORGE fires. 2 is the smallest count one BSS cannot
 * produce by being itself: a BSS has one SSID, and a hidden one is
 * filtered as its own name above. The one legitimate shape that could
 * put a second name in an answer from one address is an 802.11ax
 * Multiple BSSID transmitter answering for a nontransmitted profile, if
 * an implementation wrote that profile's SSID into the frame's own SSID
 * element; sloth does not decode nontransmitted profiles and this has
 * not been checked against the clause, which is why the count is a knob
 * (karma.forge_ssids) and not a constant. */
#define KARMA_FORGE_SSID_MIN_DEFAULT 2
#define KARMA_FORGE_SSID_MIN ((int)tune_val(TUNE_KARMA_FORGE_SSIDS))

/* How long an answered SSID stays on a row. Long enough to see two
 * passing phones' PNLs answered by one radio when phones scan only a
 * few times a minute while unassociated; short enough that a name the
 * BSSID answered once an hour ago is not held against it forever.
 * Tunable: karma.forge_window_s. */
#define KARMA_FORGE_WINDOW_DEFAULT_S 600
#define KARMA_FORGE_WINDOW_S ((time_t)tune_val(TUNE_KARMA_FORGE_WINDOW_S))

/* Distinct stations whose own probes drew forged answers before the
 * alert is CRIT without the fan-out corroborator. One station's
 * directed probes answered twice by one radio is already the KARMA
 * shape; the same radio answering *different* people's private network
 * names is the mechanism the 2005 paper describes, and no AP
 * misconfiguration produces it. */
#define KARMA_FORGE_STA_CRIT 2

/* How many of this row's SSIDs its BSSID answered without ever
 * beaconing them, judged against s->beacon_aps[] (#187 S2). 0 when the
 * answer is not knowable: no beacon row for the BSSID (aged out, or
 * never heard on this radio's channels), or a beacon history at
 * MAX_AP_SSID_HISTORY, where a name past the cap is unrecorded rather
 * than unbeaconed. The BSSID's current name (a revealed hidden SSID
 * included) never counts. `sta_n_out` gets the distinct stations those
 * answers went to; `ev_out` (up to `ev_max`) the newest answering frame
 * per counted SSID, `*ev_n` how many. Any out pointer may be NULL.
 *
 * Shared by the KARMA_PROBE_FORGE rule and karma_update() so the alert
 * and the [y] FRG column state one number about one BSSID. */
int karma_forged_ssids(const sloth_state_t *s, const karma_forge_t *r,
                       int *sta_n_out, uint64_t *ev_out, int ev_max,
                       int *ev_n);

#endif /* KARMA_DETECT_H */
