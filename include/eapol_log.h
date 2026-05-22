#ifndef SLOTH_EAPOL_LOG_H
#define SLOTH_EAPOL_LOG_H

#include <stdint.h>
#include "sloth.h"

/* EAPOL-Key / WPA 4-way handshake capture.
 *
 * Sloth observes EAPOL-Key frames in monitor-mode 802.11 captures, and
 * for each (BSSID, STA) pair tracks the M1..M4 state machine. Two
 * SIGINT-relevant artefacts come out:
 *
 *   - PMKID (modern offline-crackable). The AP's M1 sometimes embeds
 *     a PMKID KDE in its Key Data field. One frame is enough to crack
 *     the PSK offline (hashcat -m 22000).
 *
 *   - Full 4-way handshake. M1's ANonce + M2's SNonce + M2's MIC are
 *     sufficient to derive a PMK candidate. Saved as message_pair 02
 *     in the hashcat 22000 format.
 *
 * Events land in a small ring buffer + the per-pair state machine.
 * If sloth was launched with --eapol-dir DIR, each successfully
 * captured PMKID or handshake is appended to <DIR>/eapol.22000 in
 * hashcat-mixed format. */

/* eapol_event_t + MAX_EAPOL_EVENTS live in sloth.h alongside the
 * other data types embedded in sloth_state_t. */

/* Feed a raw 802.11 frame that may contain an EAPOL payload.
 * dot11 points at the FC byte; len is the length from FC through end
 * of frame (excluding radiotap). signal/channel come from radiotap.
 * Returns 1 if the frame was an EAPOL-Key frame (handled), 0 otherwise. */
int  eapol_observe_dot11(const uint8_t *dot11, int len,
                          int8_t signal, int channel);

/* Snapshot the ring into the state vector for the view. */
void eapol_snapshot(sloth_state_t *s);

/* Clear all events + pending handshake state. */
void eapol_clear(void);

/* Configure where eapol.22000 output is written. NULL disables writing. */
void eapol_set_output_dir(const char *dir);

/* Test introspection. */
int  eapol_event_count(void);

#endif /* SLOTH_EAPOL_LOG_H */
