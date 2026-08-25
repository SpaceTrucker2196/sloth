#ifndef WIFI_ASSESS_H
#define WIFI_ASSESS_H

#include "sloth.h"

/* Wireless assessment / compliance-evidence synthesis (issue #24).
 *
 * Turns the passive beacon inventory into conservative, evidence-anchored
 * findings an assessor can drop into a report — "MFP not required on
 * SSID X", "WEP still in use", "WPS enabled". Each finding traces to a
 * specific observed AP; this is not a policy engine, just a readout of
 * what was actually seen. Purely passive — reads existing state. */

typedef struct {
    char severity[8];    /* "HIGH" / "MED" / "LOW" */
    char title[48];
    char evidence[112];  /* "SSID Foo / aa:bb:.. : RSN MFP optional" */
} wifi_finding_t;

/* Populate out[max] with findings derived from s->beacon_aps; return the
 * count (<= max). */
int wifi_assess(const sloth_state_t *s, wifi_finding_t *out, int max);

/* Downgrade lanes this AP advertises about itself — the WPA_DG_* bits.
 *
 * Pure function of one record, which is what makes it testable and what
 * keeps it out of the beacon parser: giving a parser reached by both
 * the monitor and nl80211 paths a side effect on alert state would be
 * the wrong seam (#62).
 *
 * WPA_DG_OWE_TRANSITION is *not* computed here. It needs a paired open
 * BSS, and one record cannot see another; the rule adds that bit. */
uint8_t wifi_downgrade_flags(const beacon_ap_t *a);

/* Human label for a single WPA_DG_* bit. "" for anything else. */
const char *wifi_downgrade_label(uint8_t kind);

/* Fill downgrade_flags on every beacon record, including the OWE
 * transition bit that needs a paired open BSS. Called at the top of
 * alerts_update so the rule and the [b] view read the same field
 * rather than each deriving it — the pairing loop existing twice is
 * how the two would drift apart. Idempotent. */
void wifi_downgrade_update(sloth_state_t *s);

/* Worst downgrade lane on this record, as a compact column label:
 * "WPA1+RSN" > "WPA2+3" > "OWE-tr" > "MFP-opt". Returns NULL when the
 * record advertises no downgrade, so the caller can fall back to
 * whatever it showed before. */
const char *wifi_downgrade_column(uint8_t flags);

#endif /* WIFI_ASSESS_H */
