#ifndef EAP_TRACK_H
#define EAP_TRACK_H

#include "sloth.h"

/* Per-BSSID accumulation of observed 802.1X EAP methods (issue #31),
 * feeding the ROGUE_RADIUS alert. Thread-safe: eap_track_observe runs on
 * the capture thread; eap_track_snapshot copies into sloth_state_t from
 * the poll loop. Passive — it only records what eap_parse decoded. */

/* Decode an EAP packet (starting at its Code byte) and fold what it
 * reveals into the BSSID's record: the method type offered, whether it's
 * weak (MD5/GTC), and any leaked Response/Identity username. */
/* `sta` is the client half of the conversation and `from_ap` says which
 * way the frame travelled. Both are needed by the CVE-2023-52160 rule
 * (#65): the signal is whether the *AP* ever presented a server
 * certificate, so a Certificate seen travelling the other way proves
 * nothing, and sessions are keyed per client. Both values are already
 * derived at the one call site in eapol_log.c — this only passes them
 * through. `sta` may be NULL for callers that have no client address;
 * the no-server-cert tracking is then skipped rather than guessed. */
void eap_track_observe(const uint8_t *bssid, const uint8_t *sta,
                       int from_ap, const uint8_t *eap_pkt,
                       int eap_len, time_t now);

/* Copy the tracked table into s->rogue_radius[]. */
void eap_track_snapshot(sloth_state_t *s);

/* Erase all tracked state (tests). */
void eap_track_clear(void);

#endif /* EAP_TRACK_H */
