#ifndef WIFI_BASELINE_H
#define WIFI_BASELINE_H

#include "sloth.h"

/* RF baseline & drift detection (issue #23).
 *
 * Captures an in-memory baseline of the AP inventory once the RF picture
 * settles, then answers the comparative question operators actually ask:
 * "what changed since we got here?" — new APs, disappeared APs, and APs
 * that changed security or channel. Session-scoped and passive; a sibling
 * of the file-based site snapshot (#27) but live, with no operator I/O. */

typedef struct {
    char kind[8];       /* "NEW" / "GONE" / "CHG" */
    char detail[120];
} drift_finding_t;

/* Snapshot the current AP inventory as the session baseline. */
void wifi_baseline_capture(const sloth_state_t *s);

/* 1 once a baseline has been captured. */
int  wifi_baseline_ready(void);

/* Populate out[max] with drift of the current inventory vs the baseline;
 * return the count. 0 (no findings) if no baseline yet. */
int  wifi_baseline_drift(const sloth_state_t *s, drift_finding_t *out, int max);

/* Forget the baseline (tests). */
void wifi_baseline_clear(void);

#endif /* WIFI_BASELINE_H */
