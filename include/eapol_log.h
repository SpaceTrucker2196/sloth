#ifndef SLOTH_EAPOL_LOG_H
#define SLOTH_EAPOL_LOG_H

#include <stdint.h>
#include <time.h>
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
 *     sufficient to derive a PMK candidate. Exported as hashcat's
 *     M1+M2/EAPOL-from-M2 message pair — see eapol_message_pair().
 *
 * The two are only ever built from ONE handshake attempt: an M1 and an
 * M2 pair when they carry the same Key Replay Counter and the M2 lands
 * inside EAPOL_PAIR_WINDOW_S of the M1. A new M1 starts a new attempt
 * and discards everything that depended on the old one (#97 / T12).
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

/* Same, with the observation time supplied by the caller rather than
 * read from the clock. The pairing window below is a time bound, and a
 * test that cannot say when a frame arrived cannot exercise it; this is
 * the same seam eap_track_observe() already uses. eapol_observe_dot11()
 * is this with now = time(NULL). */
int  eapol_observe_dot11_at(const uint8_t *dot11, int len,
                             int8_t signal, int channel, time_t now);

/* How long after its M1 a handshake attempt may still be paired with an
 * M2 (#97 / T12).
 *
 * IEEE 802.11-2020 §12.7.6.6 has the authenticator retry M1
 * dot11RSNAConfigPairwiseUpdateCount times at
 * dot11RSNAConfigPairwiseUpdateTimeOut intervals and then give up —
 * defaults 3 × 100 ms; hostapd's more generous defaults are 4 × 1 s. A
 * real M1 and the M2 answering it are therefore a second or two apart at
 * the outside. Ten seconds clears that with room for a capture backlog
 * and is still far below anything that could bridge two separate
 * association attempts. Unbounded, a cached M1 pairs with an unrelated
 * M2 minutes later and yields a 22000 record that can never crack. */
#define EAPOL_PAIR_WINDOW_S 10

/* hashcat 22000 message-pair byte (#97 / T13).
 *
 * Bits 2..0 name which two messages the record was built from and which
 * one supplied the EAPOL blob; the high bits are flags. Values are
 * hashcat's own, from "Explanation of the MESSAGEPAIR fields" in
 * <https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2>:
 *
 *     000  M1+M2, EAPOL from M2 (challenge)
 *     001  M1+M4, EAPOL from M4 (authorized)
 *     010  M2+M3, EAPOL from M2 (authorized)
 *     011  M2+M3, EAPOL from M3 (authorized)
 *     100  M3+M4, EAPOL from M3 (authorized)
 *     101  M3+M4, EAPOL from M4 (authorized)
 *     bit 3  reserved
 *     bit 4  ap-less attack
 *     bit 5  LE router detected
 *     bit 6  BE router detected
 *     bit 7  not replaycount checked — nonce-error-corrections mandatory
 *
 * sloth builds its EAPOL record from M1's ANonce plus M2's SNonce and
 * MIC, so the only kind it can emit is M1M2_E2. It used to write the
 * literal 02, which is a different pair category (M2+M3) — hashcat was
 * told the record was something it is not. The rest of the table is
 * named so that a future pair kind is a value here, not a new literal. */
typedef enum {
    EAPOL_MP_M1M2_E2 = 0,
    EAPOL_MP_M1M4_E4 = 1,
    EAPOL_MP_M2M3_E2 = 2,
    EAPOL_MP_M2M3_E3 = 3,
    EAPOL_MP_M3M4_E3 = 4,
    EAPOL_MP_M3M4_E4 = 5
} eapol_msg_pair_t;

#define EAPOL_MP_NOT_REPLAYCOUNT_CHECKED 0x80

/* Build the byte. replaycount_checked is what sloth actually did, not
 * what it hopes: bit 7 is *set* when the two messages' Key Replay
 * Counters were never compared, telling hashcat it must apply
 * nonce-error-corrections. */
uint8_t eapol_message_pair(eapol_msg_pair_t kind, int replaycount_checked);

/* Snapshot the ring into the state vector for the view. */
void eapol_snapshot(sloth_state_t *s);

/* Clear all events + pending handshake state. */
void eapol_clear(void);

/* Configure where eapol.22000 and the per-handshake pcaps are written.
 * NULL or "" disables writing. The directory is created 0700 if absent;
 * an existing one must be a real directory owned by the effective uid
 * with no group/other bits, and is refused otherwise — never chmod'ed
 * (#87). Returns 0 on success, -1 on refusal/failure with export
 * disabled and the reason in eapol_export_error(). */
int  eapol_set_output_dir(const char *dir);

/* Export failures since the last eapol_set_output_dir(): a refused or
 * unopenable file, a short write, a failed rename. The first is also
 * printed to stderr; the count and latest reason are snapshotted into
 * the EAPOL view. eapol_export_error() also carries the reason a
 * refused eapol_set_output_dir() returned -1. */
int         eapol_export_failures(void);
const char *eapol_export_error(void);

/* Test introspection. */
int  eapol_event_count(void);

/* EAPOL-Key frames dropped because their lengths don't hold together
 * (#83). Rejected frames produce no event, association or export —
 * only this count, for capture-health stats.
 *   TRUNCATED: the body length (EAPOL header bytes 2..3) claims more
 *              bytes than were captured.
 *   MALFORMED: the declared body is too short for the 95-byte key
 *              descriptor, or Key Data Length overruns the body. */
typedef enum {
    EAPOL_REJECT_TRUNCATED = 0,
    EAPOL_REJECT_MALFORMED,
    EAPOL_REJECT_COUNT
} eapol_reject_t;
int  eapol_reject_count(eapol_reject_t why);

/* PTK generation for (bssid, sta): the number of times sloth has
 * witnessed an M3 (key install) carrying a new ANonce for this pair,
 * distinguishing a rekey from a retransmitted M3 — see the comment at
 * the msg==3 handler. Returns 0 if the pair has never been seen, so a
 * caller cannot mistake "unknown" for "one generation observed".
 * Feeds the FragAttacks mixed-key detector (#75 slice 4,
 * CVE-2020-24587) in src/fragattack.c. */
int  eapol_key_generation(const uint8_t bssid[6], const uint8_t sta[6]);

#endif /* SLOTH_EAPOL_LOG_H */
