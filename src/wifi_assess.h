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

#endif /* WIFI_ASSESS_H */
