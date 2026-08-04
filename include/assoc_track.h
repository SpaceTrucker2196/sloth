#ifndef SLOTH_ASSOC_TRACK_H
#define SLOTH_ASSOC_TRACK_H

#include <stdint.h>
#include "sloth.h"

/* Client↔AP association tracker.
 *
 * Each (BSSID, STA) pair we see explicit evidence for becomes a row.
 * Evidence sources, strongest first:
 *
 *   ASSOC_SRC_EAPOL    — completed 4-way handshake (definitive)
 *   ASSOC_SRC_ASSOC    — observed association-response with status=0
 *   ASSOC_SRC_REASSOC  — observed reassociation-response with status=0
 *
 * Disassociation / deauth frames remove the entry. Empty stays out:
 * we only record successful associations, so the view answers
 * "who is on this WiFi network right now?" reliably. */

void assoc_observe(const uint8_t bssid[6], const uint8_t sta[6],
                    const char *ssid, int source,
                    int8_t signal, int channel);

/* Disassoc / deauth fired by either side — drop the entry if present. */
void assoc_forget(const uint8_t bssid[6], const uint8_t sta[6]);

void assoc_snapshot(sloth_state_t *s);
void assoc_clear(void);

/* Parse an association (subtype 0) or reassociation (subtype 2)
 * request into *out. `dot11` starts at the FC byte, post-radiotap.
 *
 * Returns 1 on success, 0 if the frame is not a request of either kind
 * or is too short for its own fixed fields. `out` is zeroed on entry.
 *
 * This is the *ask* half of the association picture; assoc_observe()
 * above records the *grant*. Comparing the two is what surfaces a
 * downgrade — a STA requesting SAE with MFP required that ends up on
 * PSK has been moved, and neither half shows it alone (#60). */
int assoc_request_parse(const uint8_t *dot11, int len, assoc_req_t *out);

/* Record a parsed request. Keyed by (BSSID, STA); the most recent ask
 * replaces any earlier one, since a client that re-requests with new
 * parameters has changed what it wants and the delta must be measured
 * against that. Thread-safe (capture thread). */
void assoc_request_observe(const assoc_req_t *req, int8_t signal, int channel);

/* Look up the last request seen for a (BSSID, STA). Returns 1 and
 * fills *out on hit, 0 on miss. This is the seam the downgrade delta
 * reads once the matching grant arrives. */
int  assoc_request_find(const uint8_t bssid[6], const uint8_t sta[6],
                        assoc_req_t *out);

/* Test introspection. */
int  assoc_count(void);
int  assoc_request_count(void);
void assoc_request_clear(void);

#endif /* SLOTH_ASSOC_TRACK_H */
