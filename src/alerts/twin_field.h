#ifndef TWIN_FIELD_H
#define TWIN_FIELD_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* Field data for #193: a measurement, never a verdict.
 *
 * The owner's ruling on #193 (2026-11-11, restated 2026-11-12): leave
 * rule_evil_twin_attack_chain as it is and revisit with field data on
 * "how often a flood coincides with a late-arriving locally
 * administered same-SSID BSSID on a real sensor". This module counts
 * exactly that and nothing reads the counts back: no alert, no detail,
 * no severity and no taint depends on them, which
 * tests/test_twin_field.c pins by running one fixture with the hooks
 * on and off and comparing the alert table byte for byte.
 *
 * The shape (the pair the dropped option would have named):
 *   - a flood: a deauth_victim_t row with `flood` set, DEAUTH_FLOOD's
 *     own condition, whose threshold was last met within
 *     deauth.twin_window_s (the chain rule's window) on a BSSID that
 *     beacons a named, non-OPEN SSID (the chain rule's population);
 *   - a copy: another BSSID with that SSID and security, locally
 *     administered, first heard twin.late_arrival_s or more after the
 *     flooded one by twin_pair_late_arrival()'s test as #194 left it
 *     (both on the air at once, a new name on the address, not while
 *     the sensor moved);
 *   - no other twin evidence: twin_evidence_score() found nothing, so
 *     the chain rule wrote no row (and the pair is not one the operator
 *     declared in the inventory);
 *   - the chain rule did not name the flood with some other pair on
 *     that pass or earlier in the episode.
 *
 * Units, so the rate has its denominators:
 *   floods        flood episodes per BSSID: a rising edge of "some
 *                 victim row of this BSSID has `flood` set"; one
 *                 episode however many ticks and victims it spans
 *   floods_chain  of those, episodes the chain rule examined (the
 *                 flooded BSSID beacons a named non-OPEN SSID and the
 *                 threshold was met inside the window)
 *   named         of those, episodes the chain rule named (twin-chain
 *                 row fired at least once)
 *   late_laa      beacon-table entries that are a late locally
 *                 administered copy of some same-SSID entry (any
 *                 security), once per entry (BSSID, first_seen),
 *                 whether or not anything was flooded: the background
 *   coincide      floods_chain episodes that held the shape at least
 *                 on a pass where the chain had not named the
                 episode (yet); once per episode. One later named on
                 other evidence is in `named` too
 *   excl_*        of `coincide`, how many the existing exclusions would
 *                 have excused had the late-arrival test admitted the
 *                 pair: the carrier SSID list, a faint half (decode
 *                 margin or too few beacons), the sibling test (one
 *                 device's two radios). A pair can be in several;
 *                 excl_any counts it once.
 *
 * Read `coincide / floods_chain` as the rate the ruling asks about and
 * `coincide - excl_any` as the cases the dropped option would have
 * named against no exclusion. Counted for the life of the process (the
 * session) from `since`; nothing in the running binary resets them,
 * not even alerts_clear(). slothweb keeps a total across sloth
 * restarts (web_live.h).
 *
 * Main-loop state only: every hook runs inside alerts_update(). */

#define TWIN_FIELD_EXCL_CARRIER 0x1u
#define TWIN_FIELD_EXCL_FAINT   0x2u
#define TWIN_FIELD_EXCL_SIBLING 0x4u

typedef struct {
    time_t   since;          /* first pass counted, 0 = none yet */
    uint64_t floods;
    uint64_t floods_chain;
    uint64_t named;
    uint64_t late_laa;
    uint64_t coincide;
    uint64_t excl_carrier;
    uint64_t excl_faint;
    uint64_t excl_sibling;
    uint64_t excl_any;
} twin_field_counts_t;

/* In rules_twin.c, beside the predicates it reads, and read-only: is
 * `copy` a locally administered copy of `orig`'s SSID that arrived
 * late by twin_pair_late_arrival()? Fills the TWIN_FIELD_EXCL_* bits
 * that pair would carry when `excl` is not NULL. Security is not
 * compared here; the chain rule's own filter does that. */
int twin_late_laa_copy(const beacon_ap_t *orig, const beacon_ap_t *copy,
                       unsigned *excl);

/* Hooks, called by rule_evil_twin_attack_chain only. */
void twin_field_begin(const sloth_state_t *s, time_t now);
/* The chain rule examined a flood on `bssid` this pass. `fired` is 1
 * when it named the flood; `shape` 1 when it saw the #193 pair, with
 * its TWIN_FIELD_EXCL_* bits in `excl`. */
void twin_field_flood(const uint8_t bssid[6], int fired, int shape,
                      unsigned excl);

int  twin_field_enabled(void);
/* Off: every hook returns at once. For the test that pins "no alert
 * changes"; the binary never turns it off. */
void twin_field_set_enabled(int on);

void twin_field_counts(twin_field_counts_t *out);

/* Zero the counts and the episode memory and re-enable. Tests only. */
void twin_field_reset(void);

#endif
