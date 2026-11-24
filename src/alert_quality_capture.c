#include <string.h>
#include "alert_quality_capture.h"
#include "evidence_ring.h"
#include "cov_timeline.h"

/* The capture side of a finding's quality (#246): what the frames an
 * incident cites say. Named only by sloth-wifi's rule table
 * (src/alerts/rules_table.c), so sloth-rf links neither this file nor
 * the evidence ring.
 *
 * A cited frame the ring has evicted reads as absent and adds nothing:
 * the window is the span of the frames still held. Channels are the
 * radiotap frequencies the ring recorded; a frame with none (0) places
 * no channel and is left out of the hop question, never counted as
 * covered. */

int aq_capture_evidence(const uint64_t *ids, int n, int window,
                        aq_evidence_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    out->uncovered_ms = -1;
    out->drops = -1;
    if (!ids || n <= 0) return 0;
    if (n > ALERT_EVIDENCE_IDS) n = ALERT_EVIDENCE_IDS;
    int freq[ALERT_EVIDENCE_IDS], nf = 0;
    for (int i = 0; i < n; i++) {
        evidence_rec_t r;
        if (evidence_ring_get(ids[i], &r, NULL, 0) < 0) continue;
        int64_t ms = (int64_t)r.ts_sec * 1000 + (int64_t)(r.ts_usec / 1000);
        if (out->n == 0 || ms < out->first_ms) out->first_ms = ms;
        if (out->n == 0 || ms > out->last_ms)  out->last_ms  = ms;
        out->n++;
        if (r.radio < 8) out->radio_mask |= (uint8_t)(1u << r.radio);
        int seen = 0;
        for (int k = 0; k < nf; k++) if (freq[k] == r.freq_mhz) seen = 1;
        if (!seen && r.freq_mhz) freq[nf++] = r.freq_mhz;
    }
    if (!window || out->n == 0) return out->n;
    /* No channel among them: nothing to show a radio was there. */
    int64_t worst = nf ? 0 : -1;
    for (int k = 0; k < nf; k++) {
        int64_t u = cov_tl_uncovered_ms(freq[k], out->first_ms, out->last_ms);
        if (u < 0) { worst = -1; break; }
        if (u > worst) worst = u;
    }
    out->uncovered_ms = worst;
    out->drops = cov_tl_drops_in(out->first_ms, out->last_ms);
    return out->n;
}
