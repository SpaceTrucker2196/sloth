#ifndef FRAGATTACK_H
#define FRAGATTACK_H

#include <stdint.h>
#include <time.h>

/* FragAttacks — issue #75, slice 1.
 *
 * Vanhoef, "Fragment and Forge: Breaking Wi-Fi Through Frame
 * Aggregation and Fragmentation", USENIX Security 2021. Twelve CVEs:
 * three design flaws in 802.11 itself and nine implementation bugs.
 * They let an on-path adversary inject frames into an encrypted
 * WPA/WPA2/WPA3 session without holding the key.
 *
 * Slice 1 covers the two that are observable with what sloth already
 * parses, and no more:
 *
 *   CVE-2020-26140  accepting plaintext data frames in a protected net
 *   CVE-2020-26143  ... the fragmented variant of the same
 *   CVE-2020-26145  accepting plaintext broadcast fragments as full
 *                   frames
 *
 * ── What "protected network" means here ──
 *
 * Not "the beacon advertised RSN". Per (BSSID, STA), sloth waits until
 * it has *seen that station send a Protected frame*, and only then
 * treats a subsequent unprotected one as a signal. Three reasons, and
 * the third is the one that matters:
 *
 *   - It works on a BSS whose beacon was missed, which on a hopping
 *     radio is most of them.
 *   - It is per-station, so one client still associating cannot make
 *     another client's traffic look like an attack.
 *   - It is what the CVE actually says. "Accepting plaintext after key
 *     install" needs evidence the key was installed, and a station's
 *     own encrypted traffic is that evidence. A beacon says only what
 *     the AP offers.
 *
 * The ordering is therefore load-bearing: protection must be observed
 * *before* the plaintext frame, never merely somewhere in the capture.
 *
 * ── What is deliberately not here ──
 *
 * ── CVE-2020-24588, and why it is detected sideways ──
 *
 * Not implementable as the issue specifies. The A-MSDU subframe headers
 * live inside the ciphertext, so the proposed signals — subframe DA vs
 * Address 3, subframe length, subframe LLC prefix — are not passively
 * observable, and sloth does not crack (MISSION §2). Only the A-MSDU
 * Present bit is visible, sitting in the plaintext MAC header, and on
 * its own it fires on any hardware that aggregates.
 *
 * The attack is a *replay*: the adversary captures a frame the victim
 * already sent and retransmits it with that one bit flipped, so the
 * receiver reparses the same ciphertext as aggregated subframes.
 *
 * So the signal is the replay, identified by the CCMP packet number.
 * A PN is never legitimately reused under one key — that is the whole
 * basis of CCMP replay protection (§12.5.3.4.4) — so the same
 * transmitter emitting the same PN twice is already an anomaly, and
 * the same PN twice with the A-MSDU bit differing is this attack
 * specifically.
 *
 * That is strictly stronger than the sequence-number version proposed
 * in the #75 triage. Sequence numbers are 12 bits and wrap every 4096
 * frames, which at any real rate is under a second, so a seqnum-keyed
 * detector needs a window short enough to be evaded and long enough to
 * false-positive. The PN is 48 bits and monotonic. It also has no
 * meaning on unprotected frames, which is correct: -24588 is an attack
 * on encrypted MPDUs, and a plaintext A-MSDU is CVE-2020-26144.
 *
 * CVE-2020-24587 (mixed key) needs PTK-rotation visibility — the
 * current M1-M4 EAPOL parser does not distinguish a GTK rekey from the
 * initial handshake, so it stays out.
 *
 * ── Slice 4 ──
 *
 * Adds one more detector, unrelated in mechanism to the mixed-key gap
 * above (that one is still out — see the note it left behind):
 *
 *   CVE-2020-26144  plaintext A-MSDU whose first subframe claims to
 *                   carry EAPOL
 *
 * Unlike -24588, this is readable in the clear: the frame is plaintext,
 * so the A-MSDU subframe header (DA/SA/Length) and its LLC/SNAP are not
 * behind any cipher. Real EAPOL is never aggregated — it is always its
 * own MPDU, never a subframe — so a subframe claiming EtherType 0x888E
 * has no benign reading. This is the plaintext half of the same design
 * flaw -24588 detects the encrypted half of: an unauthenticated A-MSDU
 * bit that lets a receiver be tricked about what it is parsing.
 *
 * ── Slice 2 ──
 *
 * Adds a fragment-session table keyed on (BSSID, SA, DA, TID) and two
 * more detectors that ride it:
 *
 *   CVE-2020-24586  fragment cache poisoned across a (re)association
 *   CVE-2020-26147  reassembly mixes an encrypted fragment with a
 *                   plaintext one
 *
 * CVE-2020-26146 (non-consecutive packet numbers) is NOT here despite
 * `docs/wiki/fragattacks.md` having called it "slice 2" before this
 * code existed. The CCMP PN is transmitted in the clear, so reading it
 * is not the obstacle — the obstacle is that PN is a single counter
 * shared by every frame sent under one key on one TID, not a
 * per-reassembly sequence. Two fragments of one MSDU only get
 * consecutive PNs if nothing else on that TID was transmitted between
 * them, which the 802.11 spec expects but does not enforce, and any
 * frame from another exchange, or a retried fragment (a retry gets a
 * fresh PN even though the fragment number and sequence number do
 * not change), opens a gap that is not an attack. A same-session
 * detector with that failure mode would be noisy on exactly the
 * ordinary multi-station traffic this issue is meant to be quiet
 * against. Left for a slice that can test the retry case honestly.
 *
 * Lives outside src/capture/probe.c for the reason ctrl_frames.c and
 * dot11_data.c do: probe.c is compiled only under WITH_PCAP and is
 * absent from TEST_SRCS, so logic placed there cannot be tested. */

#define FRAG_MAX_BSS      64
#define FRAG_MAX_STATIONS 128
#define FRAG_MAX_SESSIONS 128
#define FRAG_MAX_ASSOC_EVT 128
#define FRAG_MAX_MPDUS     256

/* How long a recorded MPDU stays comparable. The attacker replays
 * promptly — the victim's fragment cache and replay window are what
 * the attack rides, and both are short-lived. Bounding it also keeps
 * the table from holding evidence long enough to be matched against
 * an unrelated key rotation, after which PNs legitimately restart. */
#define FRAG_MPDU_WINDOW_S  10

typedef struct {
    uint8_t  bssid[6];
    time_t   first_seen;
    time_t   last_seen;

    /* Stations on this BSS seen sending at least one Protected frame.
     * The gate for everything below. */
    uint32_t protected_frames;

    /* CVE-2020-26140 / -26143: a unicast data frame with Protected
     * clear, carrying something other than EAPOL, from a station whose
     * key install was already witnessed. */
    uint32_t plaintext_unicast;

    /* CVE-2020-26145: a group-addressed data frame with Protected
     * clear that is fragmented. Broadcast reassembly is not permitted
     * in a protected network at all, so one is already wrong. */
    uint32_t plaintext_bcast_frag;

    /* CVE-2020-24586: a continuation fragment completed a reassembly
     * that started before a (re)association response we witnessed for
     * one of the two endpoints. The fragment cache should have been
     * cleared at that boundary. */
    uint32_t cache_poison;

    /* CVE-2020-26147: a reassembly whose fragments do not agree on the
     * Protected bit — some encrypted, some not. */
    uint32_t mixed_protect;

    /* CVE-2020-24588: the same protected MPDU — same transmitter, same
     * CCMP packet number — seen twice with the A-MSDU Present bit
     * differing between the two. See the note below on why this is the
     * signal and the one the issue proposed is not. */
    uint32_t amsdu_flip;

    /* CVE-2020-26144: a plaintext A-MSDU whose first subframe's
     * LLC/SNAP claims EtherType EAPOL (0x888E). Real EAPOL is never
     * aggregated, so this has no benign reading. The plaintext
     * counterpart to amsdu_flip above — that one needs the CCMP PN
     * because its evidence is encrypted; this one needs nothing but
     * the subframe header because its evidence is not. */
    uint32_t amsdu_eapol_spoof;

    /* The most recent offender, for the alert line. Kept rather than a
     * list because the alert names one example and the JSONL row and
     * per-alert pcap carry the rest. */
    uint8_t  last_sa[6];
    uint8_t  last_da[6];
    time_t   last_hit;
} frag_bss_t;

/* Feed one 802.11 frame, radiotap already stripped. Ignores everything
 * that is not a data frame. `now` is passed rather than read so the
 * ordering rule above is testable. */
void frag_observe(const uint8_t *dot11, int len, time_t now);

/* Record that (bssid, sta) completed a (re)association — issue #75
 * slice 2. Called from the same probe.c site that already feeds
 * assoc_observe() on a status-0 assoc/reassoc response, so the two
 * trackers see identical evidence. `now` is passed rather than read
 * for the same testability reason as frag_observe. */
void frag_note_association(const uint8_t bssid[6], const uint8_t sta[6],
                           time_t now);

int              frag_bss_count(void);
const frag_bss_t *frag_bss_at(int i);
/* Index of `bssid` in the table, or -1. */
int              frag_find(const uint8_t bssid[6]);

/* Test introspection: number of open (incomplete) fragment sessions. */
int              frag_session_count(void);

/* Test introspection: protected MPDUs currently held for A-MSDU
 * comparison. */
int              frag_mpdu_count(void);

void frag_clear(void);

#endif /* FRAGATTACK_H */
