#ifndef ACTION_SNOOP_H
#define ACTION_SNOOP_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* 802.11 Action frames (management subtype 13) — issue #59.
 *
 * Action frames are the carrier for the whole 802.11k/v/r management
 * surface. Until this module they were labelled by probe.c and then
 * discarded, which left BSS Transition Management invisible: a BTM
 * Request with Disassociation Imminent set steers a client off its AP
 * without a deauth, so ALERT_TYPE_DEAUTH_FLOOD never sees it.
 *
 * This module is parse-and-count only. The alert rule that consumes it
 * lands separately, and Categories 5 (RRM) / 6 (FT) / 127 (Vendor) are
 * counted here but deep-parsed by follow-up issues (#61 for RRM).
 *
 * Lives outside src/capture/probe.c deliberately: probe.c is compiled
 * only under WITH_PCAP and is not in TEST_SRCS, so anything placed
 * there is untestable. Same reasoning that moved radiotap_parse out. */

/* Category codes — IEEE 802.11-2020 Table 9-51. */
#define ACTION_CAT_SPECTRUM 0    /* Spectrum Management (802.11h) */
#define ACTION_CAT_RRM      5    /* Radio Measurement   (802.11k) */
#define ACTION_CAT_FT       6    /* Fast BSS Transition (802.11r) */
#define ACTION_CAT_SA_QUERY 8    /* SA Query            (802.11w) */
#define ACTION_CAT_WNM     10    /* Wireless Net Mgmt   (802.11v) */
#define ACTION_CAT_PUBLIC   4    /* Public — never protected      */
#define ACTION_CAT_UNPROT_WNM 11 /* Unprotected WNM — never protected */
#define ACTION_CAT_VENDOR 127    /* Vendor Specific               */

/* SA Query Action field values — §9.6.10. */
#define SAQ_ACT_REQUEST   0
#define SAQ_ACT_RESPONSE  1

/* Spectrum Management Action field values — Table 9-51.
 * 4 is the addressed Channel Switch Announcement (§9.6.2.4): the same
 * announcement a beacon broadcasts, but aimed at one STA. */
#define SPECTRUM_ACT_CHANNEL_SWITCH  4

/* Radio Measurement Action field values — Table 9-361. */
#define RRM_ACT_MEASUREMENT_REQUEST  0
#define RRM_ACT_MEASUREMENT_REPORT   1

/* Measurement Type inside the Measurement Request element (tag 38).
 * 5 is the Beacon Request — "go and look at the air for me". */
#define RRM_MEAS_TYPE_BEACON         5

/* WNM Action field values — IEEE 802.11-2020 Table 9-368. */
#define WNM_ACT_BTM_QUERY     6
#define WNM_ACT_BTM_REQUEST   7
#define WNM_ACT_BTM_RESPONSE  8

/* BTM Request Mode bitfield — IEEE 802.11-2020 Figure 9-924.
 *
 * NOTE the bit numbering: Disassociation Imminent is B2 (mask 0x04).
 * Issue #59 describes it as "bit 3", which read literally is 0x08 —
 * that is BSS Termination Included, a different field entirely. The
 * issue names the semantic field correctly, so the bit number is taken
 * as a 1-indexing slip and the spec wins. Flagged on the issue. */
#define BTM_REQ_PREF_CANDIDATE  0x01  /* B0 Preferred Candidate List   */
#define BTM_REQ_ABRIDGED        0x02  /* B1 Abridged                   */
#define BTM_REQ_DISASSOC_IMM    0x04  /* B2 Disassociation Imminent    */
#define BTM_REQ_BSS_TERM_INCL   0x08  /* B3 BSS Termination Included   */
#define BTM_REQ_ESS_DISASSOC    0x10  /* B4 ESS Disassoc Imminent      */

/* Candidate list bound. Reuses MAX_AP_NEIGHBORS because the candidates
 * are Neighbor Report elements (tag 52) — the same element beacon_rsn_t
 * already bounds — rather than inventing a second limit for one thing. */
#define SLOTH_BTM_MAX_CANDIDATES MAX_AP_NEIGHBORS

typedef struct {
    uint8_t  bssid[6];        /* addr3 — the AP doing the steering */
    uint8_t  target_sta[6];   /* addr1 — the client being steered  */
    uint8_t  dialog_token;
    uint8_t  request_mode;
    uint16_t disassoc_timer;  /* in beacon intervals, 0 = unspecified */
    uint8_t  validity_interval;
    uint8_t  candidate_bssids[SLOTH_BTM_MAX_CANDIDATES][6];
    int      candidate_count;
    int      candidates_truncated;  /* list exceeded the bound */
    time_t   ts;
} sloth_btm_req_t;

/* Read the Category (and WNM/RRM Action) byte from an Action frame.
 *
 * `dot11` starts at the FC byte, post-radiotap, as everywhere else in
 * the capture path. Returns the category on success and writes the
 * following byte to *action_out (may be NULL); returns -1 if the frame
 * is not a well-formed Action frame long enough to carry both.
 *
 * Subtype 14 ("Action No Ack") is deliberately rejected: it shares the
 * body format but not the semantics, and nothing consumes it yet. */
int action_parse_category(const uint8_t *dot11, int len, uint8_t *action_out);

/* Parse a WNM BSS Transition Management Request into *out.
 *
 * Returns 1 on success, 0 if the frame is not a BTM Request or is too
 * short for its own declared contents. `out` is zeroed on entry, so a
 * partial parse never leaves stale candidate entries behind.
 *
 * Optional fields are honoured in the order the standard fixes them:
 * BSS Termination Duration (12 bytes) when B3 is set, then the
 * Session Information URL when B4 is set, then the candidate list.
 * Getting that order wrong silently misreads the candidates, which is
 * why the tests cover each combination. */
int action_parse_btm_req(const uint8_t *dot11, int len, sloth_btm_req_t *out);

/* Record one Action frame. Counts per category, and folds any WNM BTM
 * Request into the per-(BSSID, STA) steering table below. Thread-safe
 * (capture thread). */
void action_observe(const uint8_t *dot11, int len, time_t now);

/* ── BTM steering table (#59 slice 2) ──────────────────────
 *
 * Two structures, for two different questions, following the shape
 * assoc_track.c settled on:
 *
 *   the table  — one durable row per (BSSID, STA), the picture the [a]
 *                view, JSONL and SQLite export. Survives the window.
 *   the ring   — timestamped events, read only by the rate query. A
 *                rolling window cannot be answered from the table
 *                because the table has no history, only a count.
 *
 * Keeping the count in the table *and* the events in the ring is not
 * redundancy: the table's count is "how many ever", the ring's is "how
 * many just now", and the alert needs the second while the operator
 * reading the view needs the first. */

/* Record a parsed BTM Request. Split from action_observe so tests can
 * drive the table directly with a controlled clock — action_observe
 * calls time(NULL) internally the way the rest of the capture path
 * does. Thread-safe. */
void btm_observe(const sloth_btm_req_t *req, time_t now);

/* Busiest (BSSID, STA) pair by BTM Requests carrying Disassociation
 * Imminent within `window_s`, when it reaches `thresh`. Returns that
 * count (0 if none qualifies) and writes the pair out; any output
 * pointer may be NULL. `total_out` receives the pair's total Request
 * count in the window, imminent or not.
 *
 * Only imminent Requests are counted toward the threshold. A Request
 * without B2 set cannot force anything — the client is free to decline
 * — and a busy enterprise AP steering clients for load balancing emits
 * exactly those. Rate alone would alert on ordinary 802.11v roaming,
 * which is the false positive that gets a detector switched off. */
int  btm_forcing_pair(time_t now, int window_s, int thresh,
                      uint8_t out_bssid[6], uint8_t out_sta[6],
                      int *total_out);

/* Look up the durable row for a pair. Returns 1 and fills *out on hit. */
int  btm_find(const uint8_t bssid[6], const uint8_t sta[6],
              btm_steer_t *out);

/* Copy the table into s->btm_steers[], most recently steered first —
 * an operator scanning the section wants the live steering at the top. */
void btm_snapshot(sloth_state_t *s);

/* Test introspection. */
int  btm_pair_count(void);
void btm_clear(void);

/* ── Channel Switch Announcement (#63) ─────────────────────
 *
 * Records every announcement seen, from beacons, probe responses and
 * addressed Action frames alike, in one ring. The rule reads the ring
 * rather than the AP table because the abuse cases are about *who
 * announced what, when* — a spoofed announcement never reaches the AP
 * table at all, since it claims a BSSID whose real beacons say
 * something else. */

/* Record one announcement. `ta` may be NULL when the transmitter is not
 * separable from the BSSID (the beacon path, where they are the same
 * address by construction). */
void csa_observe(const uint8_t bssid[6], const uint8_t *ta,
                 int new_channel, int new_op_class,
                 int switch_mode, int switch_count,
                 int source, int from_channel, time_t now);

/* Parse a Spectrum Management / Channel Switch Announcement Action
 * frame and record it. Returns 1 if one was found, 0 otherwise. */
int  csa_parse_action(const uint8_t *dot11, int len, time_t now);

/* Distinct target channels announced for `bssid` within `window_s`.
 * A legitimate AP picks one destination and commits; several distinct
 * targets in a minute is client churn, not roaming. */
int  csa_distinct_targets(const uint8_t bssid[6], time_t now, int window_s);

/* Most recent announcement for `bssid` in the window, or 0. */
int  csa_latest(const uint8_t bssid[6], time_t now, int window_s,
                sloth_csa_event_t *out);

/* Copy the ring into s->csa_events[], newest first. */
void csa_snapshot(sloth_state_t *s);

int  csa_event_count(void);
void csa_clear(void);

/* ── 802.11k Radio Measurement (#61) ───────────────────────
 *
 * Beacon Requests are counted per (BSSID, STA), split by whether the
 * request named a specific SSID. That split is the detector: a
 * legitimate AP steering its own clients asks about networks *it*
 * advertises, so a request naming an SSID the asker has never beaconed
 * is an outsider fishing through someone else's radio.
 *
 * Beacon *Reports* — the client's reply — are counted and stored but
 * raise nothing on their own. They are evidence a survey succeeded,
 * not evidence one was attempted, and conflating the two would let a
 * chatty client incriminate its own AP. */

/* Parse and record a Radio Measurement action frame. Returns 1 when a
 * Beacon Request or Report was recognised. */
int  rrm_parse_action(const uint8_t *dot11, int len, time_t now);

/* Busiest (BSSID, STA) pair by *targeted* Beacon Requests inside
 * `window_s`, when it reaches `thresh`. Returns that count. */
int  rrm_busiest_pair(time_t now, int window_s, int thresh,
                      uint8_t out_bssid[6], uint8_t out_sta[6]);

int  rrm_find(const uint8_t bssid[6], const uint8_t sta[6],
              sloth_rrm_pair_t *out);
void rrm_snapshot(sloth_state_t *s);
int  rrm_pair_count(void);
void rrm_clear(void);

/* Frames seen for `category` since the last clear. Test introspection
 * and the seam the #61 RRM work reads before it grows a real table. */
/* ── SA Query storms (#76) ───────────────────────────────────────────
 *
 * SA Query is management-frame protection's own mechanism: when an AP
 * receives an *unprotected* disassociation or deauthentication claiming
 * to be from an associated station, it does not act on it. It sends an
 * SA Query Request and waits — a station that is really still there
 * answers, and the spoofed frame is discarded.
 *
 * So a storm of SA Queries is not an attack on the client. It is the
 * *visible symptom* of someone spraying spoofed disassociation frames
 * at an MFP-protected network, which is what deauth flooding becomes
 * once MFP takes the direct route away. The attacker's own frames may
 * never be heard on the channel sloth is sitting on; the AP's response
 * to them is broadcast on the BSS's own channel and is heard.
 *
 * A legitimate exchange is a handful of frames: the AP retries a small
 * number of times over a few hundred milliseconds (§11.13) and stops.
 * Anything sustained is a network answering an attack. */
#define SAQ_FLOOD_WIN_SECS   10
#define SAQ_FLOOD_THRESH     12   /* per (BSSID, STA) in the window */
#define SAQ_MAX_PAIRS        64

/* The busiest (BSSID, STA) pair in the window, or 0 if none reaches
 * `thresh`. Writes the pair and its count. */
int  saq_flood_pair(time_t now, int window_s, int thresh,
                    uint8_t out_bssid[6], uint8_t out_sta[6], int *out_count);
int  saq_pair_count(void);
void saq_clear(void);

/* ── Unprotected robust action frames (#76, CVE-2019-16275) ──────────
 *
 * On a BSS advertising MFP *required*, an individually addressed
 * robust Action frame must be protected. One that is not is either a
 * non-conforming stack or an injected frame, and CVE-2019-16275 is the
 * former being exploitable as the latter.
 *
 * "Robust" is every Action category except the ones the standard
 * defines as never protected — Public (4), Unprotected WNM (11) and
 * Vendor Specific (127). Naming the exclusions rather than listing the
 * inclusions is deliberate: the category space grows, and a detector
 * built on an allow-list goes quiet on every category added after it
 * was written, silently.
 *
 * Individually addressed only. Group-addressed management frames are
 * protected by BIP, which appends a Management MIC element rather than
 * setting the Protected bit — so reading that bit on a broadcast frame
 * answers a question it was never asked. */
int  action_category_is_robust(uint8_t category);

#define MFP_VIOLATION_MAX_BSS 32

/* BSSIDs seen emitting an unprotected robust action frame while their
 * own beacon advertises MFP required. Returns the count; writes the
 * worst offender and its tally when non-zero. */
int  action_mfp_violations(uint8_t out_bssid[6], int *out_count,
                           uint8_t out_category[1]);
void action_mfp_clear(void);

int  action_category_count(uint8_t category);

/* Total Action frames observed, including categories with no handler. */
int  action_total_count(void);

/* Reset all counters. */
void action_clear(void);

#endif /* ACTION_SNOOP_H */
