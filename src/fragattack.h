#ifndef FRAGATTACK_H
#define FRAGATTACK_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"
#include "dot11_frame.h"

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
 * ── Slice 4 ──
 *
 * Adds two more detectors:
 *
 *   CVE-2020-26144  plaintext A-MSDU whose first subframe claims to
 *                   carry EAPOL
 *   CVE-2020-24587  fragment reassembly spans a completed PTK rotation
 *                   ("mixed key")
 *
 * Unlike -24588, -26144 is readable in the clear: the frame is
 * plaintext, so the A-MSDU subframe header (DA/SA/Length) and its
 * LLC/SNAP are not behind any cipher. Real EAPOL is never aggregated —
 * it is always its own MPDU, never a subframe — so a subframe claiming
 * EtherType 0x888E has no benign reading. This is the plaintext half of
 * the same design flaw -24588 detects the encrypted half of: an
 * unauthenticated A-MSDU bit that lets a receiver be tricked about what
 * it is parsing.
 *
 * -24587 was the one item the #75 triage flagged as needing state that
 * did not exist: eapol_log.c's M1-M4 parser could not tell a PTK rekey
 * apart from the initial handshake, so a fragment session had nothing
 * to compare against a later fragment of the same reassembly. It now
 * tracks a per-(BSSID, STA) generation counter, bumped when an M3
 * carries a new ANonce (`eapol_key_generation()`); a session records
 * that counter when it opens (fragment number 0), and a completing
 * fragment whose current generation has moved past it spans a
 * mid-reassembly rekey — the mixed-key bug. Keyed on ANonce rather than
 * "an M3 arrived" because an AP retries M3 verbatim (same ANonce) when
 * M4 is lost, and counting retries would fire on ordinary handshake
 * loss. Gated on both fragments being encrypted (an unencrypted one is
 * FRAG_MIXED's territory) and on a nonzero generation at session open
 * (0 means sloth never witnessed an install for this pair — reporting a
 * rekey without that evidence would be a guess, not a finding).
 *
 * CVE-2020-26139 (an AP forwarding an EAPOL frame from a station that
 * has not completed authentication out to another client) still stays
 * out, but for a different reason than earlier notes on this issue
 * claimed. It is not a wired-side-only bug: read literally, "forwards to
 * connected clients" means the re-addressed frame *is* transmitted
 * wirelessly — an uplink EAPOL from station A naming station B as its
 * destination, followed by a downlink EAPOL from the AP to B carrying
 * A as the source, would both be on-air and in principle visible to a
 * detector that tracks per-station authentication state, which
 * eapol_log.c already does. What is not yet verified is the precise
 * wire-level shape of "destination" in the attack — whether it rides
 * the 802.11 addressing, an 802.1X PAE group address, or something the
 * paper specifies that a title alone does not — and shipping a rule on
 * a guessed shape risks a detector that never fires or fires on the
 * wrong thing. Left for a slice that starts from the paper's own frame
 * trace rather than its one-line advisory description.
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
/* BSSIDs whose beacon told this module who the AP is (#180). Larger
 * than FRAG_MAX_BSS because every beaconing AP in range lands here, not
 * only the ones carrying data on a channel sloth dwelt on. */
#define FRAG_MAX_AP_IDENT  128

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

    /* CVE-2020-24587: a fragment reassembly completed after eapol_log.c
     * witnessed a PTK rotation (a new-ANonce M3) for the pair — the
     * reassembly spans two different keys. Only counted when both
     * fragments are encrypted (an unencrypted one is mixed_protect's
     * territory) and when a generation was actually observed at session
     * open (0 means no evidence, not "no rekey"). */
    uint32_t mixed_key;

    /* CVE-2020-26146: two encrypted fragments of one reassembly whose
     * CCMP packet numbers are not consecutive. §12.5.3.4.4 requires the
     * fragments of one MSDU to carry consecutive PNs, so a gap means
     * the reassembly is combining fragments from different bursts —
     * which is the whole point of the attack. Compared against the
     * *fragment-number* delta rather than expecting +1, so a fragment
     * sloth simply did not hear is not reported as an attack. */
    uint32_t pn_gap;

    /* CVE-2020-26139: an EAPOL frame the AP forwarded between two
     * stations. On an infrastructure BSS, EAPOL only ever travels
     * between a station and the authenticator, so a frame where
     * neither address is the BSSID is one the AP relayed on behalf of
     * a sender it should not have — no association history needed to
     * say so. */
    uint32_t eapol_relay;

    /* #180: EAPOL frames that would have counted as eapol_relay above
     * but for the mld-sibling heuristic — the AP-side address was not
     * the BSSID and no beacon from this BSSID had been decoded, but it
     * has the shape vendors derive an AP MLD MAC with (see
     * frag_ap_identity()). Not a finding; kept so a reader can see the
     * detector withheld something on a guess, and named in the
     * FRAG_EAPOL_RELAY detail when that alert fires. */
    uint32_t eapol_mld_sibling;

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
/* The same, on a frame on_probe_frame() has already decoded (#130). */
void frag_observe_frame(const dot11_frame_t *f, time_t now);

/* Record that (bssid, sta) completed a (re)association — issue #75
 * slice 2. Called from the same probe.c site that already feeds
 * assoc_observe() on a status-0 assoc/reassoc response, so the two
 * trackers see identical evidence. `now` is passed rather than read
 * for the same testability reason as frag_observe. */
void frag_note_association(const uint8_t bssid[6], const uint8_t sta[6],
                           time_t now);

/* ── Who the AP is (#180) ──
 *
 * FRAG_EAPOL_RELAY asked "is this address the AP?" as "is it the
 * BSSID?", and the plaintext rules' key-install gate filed the AP under
 * whichever source address a frame carried. On an 802.11be AP MLD both
 * go wrong: the authenticator's EAPOL address is the AP MLD MAC, the
 * over-the-air BSSID (addr2 downlink, addr1 uplink) the per-link
 * address. On the reference host every M1/M3 an Arcadyan Wi-Fi 7 AP
 * sent its own client read as CVE-2020-26139.
 *
 * Record what one decoded Beacon says about its BSS: `mld_mac` is the
 * MLD MAC Address of the Basic Multi-Link element mle_parse() read from
 * it, or NULL when the beacon carried none. A BSSID beaconing WITHOUT an
 * MLE is recorded too, because that is evidence as well (the caller
 * passes NULL only for a beacon that could have shown one: captured
 * whole, and carrying no Basic MLE at all, not one mle_parse()
 * refused): an AP
 * affiliated with an AP MLD carries a Basic MLE in every Beacon
 * (hostapd's ieee802_11_build_ap_params() appends
 * hostapd_eid_eht_ml_beacon() to every beacon tail whenever mld_ap is
 * set; src/ap/beacon.c, read 2026-11-03 through the AOSP mirror), so
 * one that did not is not an MLD, and the fallback heuristic is not
 * allowed to guess otherwise for it. Called from the beacon branch of
 * on_probe_frame(); `now` passed for the same testability reason as
 * frag_observe(). */
void frag_note_beacon(const uint8_t bssid[6], const uint8_t *mld_mac,
                      time_t now);

/* Is `addr` the AP of `bssid`? Exposed for the tests; the rules use the
 * same function under the module lock.
 *
 *   FRAG_AP_BSSID        it is the BSSID.
 *   FRAG_AP_MLD          a beacon from this BSSID advertised it as the
 *                        AP MLD MAC.
 *   FRAG_AP_MLD_SIBLING  no beacon from this BSSID has been decoded,
 *                        and the address is unicast, locally
 *                        administered, equal to the BSSID in octets 1-4
 *                        and within +/-1 of it in octet 5: the usual
 *                        vendor derivation of an AP MLD MAC from its
 *                        first link address (the reference host's
 *                        Arcadyan AP: octet 0 gained bits 1 and 5,
 *                        octet 5 lost one). A guess, so it may only
 *                        ever withhold a finding, never create one.
 *   FRAG_AP_NO           none of these. */
typedef enum {
    FRAG_AP_NO = 0,
    FRAG_AP_BSSID,
    FRAG_AP_MLD,
    FRAG_AP_MLD_SIBLING
} frag_ap_ident_t;
frag_ap_ident_t frag_ap_identity(const uint8_t bssid[6], const uint8_t addr[6]);

/* The FRAG_EAPOL_RELAY detail's suffix: "" when the sibling heuristic
 * withheld nothing on this BSS, else "; N more withheld as the AP MLD
 * (mld-sibling heuristic)", so a reader of a real relay on an AP MLD
 * whose beacon sloth never decoded sees that a guess was made. Written
 * into `buf` and returned. */
const char      *frag_sibling_note(const frag_bss_t *b, char *buf, size_t n);

/* Test introspection: BSSIDs with a recorded beacon. */
int              frag_ap_ident_count(void);

/* ── Threading (#111) ──
 *
 * frag_observe() and frag_note_association() run on the monitor-capture
 * thread; everything else here runs on main. Every entry point takes
 * the module's one mutex, so each call is atomic with respect to the
 * others. Two readers need a word about *what* that atomicity covers:
 *
 *   frag_bss_at()   returns a pointer into the live table. The lookup
 *                   is locked; the caller's reads through the pointer
 *                   are not. It exists for single-threaded test
 *                   introspection, where nothing writes concurrently.
 *   frag_bss_copy() copies the row out under the lock. This is what a
 *                   reader on main uses while the capture thread is
 *                   live (rule_fragattack in src/alerts/rules_twin.c). */
int              frag_bss_count(void);
const frag_bss_t *frag_bss_at(int i);
/* Copy row i into *out under the lock. Returns 1 on success, 0 when i
 * is out of range (the row count can shrink underneath a caller that
 * read frag_bss_count() a moment ago -- frag_clear() on the other
 * thread -- so the index is re-checked here, not trusted). */
int              frag_bss_copy(int i, frag_bss_t *out);
/* Index of `bssid` in the table, or -1. */
int              frag_find(const uint8_t bssid[6]);

/* Test introspection: number of open (incomplete) fragment sessions. */
int              frag_session_count(void);

/* Test introspection: protected MPDUs currently held for A-MSDU
 * comparison. */
int              frag_mpdu_count(void);

/* Copy the per-BSS table into s->frag_rows for VIEW_FRAGATTACK (#75
 * slice 5), sorted by last_hit descending — the BSS that just fired
 * belongs at the top, not wherever bss_get() happened to insert it.
 * Mirrors frag_bss_t into frag_bss_row_t rather than exposing the
 * internal table to the view directly. */
void frag_snapshot(sloth_state_t *s);

void frag_clear(void);

#endif /* FRAGATTACK_H */
