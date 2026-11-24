#ifndef SLOTH_ALERT_QUALITY_CAPTURE_H
#define SLOTH_ALERT_QUALITY_CAPTURE_H

#include "alert_quality.h"

/* sloth-wifi's aq_evidence_fn (src/alert_quality.h): the cited frames'
 * capture times, radios and channels from the evidence ring, and with
 * `window` the dwell and drop history over their span
 * (src/cov_timeline.h). */
int aq_capture_evidence(const uint64_t *ids, int n, int window,
                        aq_evidence_t *out);

#endif /* SLOTH_ALERT_QUALITY_CAPTURE_H */
