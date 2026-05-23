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

/* Test introspection. */
int  assoc_count(void);

#endif /* SLOTH_ASSOC_TRACK_H */
