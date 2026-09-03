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
 * CVE-2020-24588 (A-MSDU flip) is not implementable as the issue
 * specifies it: the A-MSDU subframe headers live inside the ciphertext,
 * so the proposed signals — subframe DA vs Address 3, subframe length,
 * subframe LLC prefix — are not passively observable and sloth does not
 * crack (MISSION §2). Only the A-MSDU Present bit itself is visible,
 * being in the plaintext MAC header. See the triage comment on #75 for
 * the replacement signal (a duplicate sequence number whose A-MSDU bit
 * differs), which is slice 3.
 *
 * CVE-2020-24586/-24587 (fragment-cache poison, mixed key) need a
 * fragment session table and PTK-rotation visibility respectively.
 * Slices 2 and 4.
 *
 * Lives outside src/capture/probe.c for the reason ctrl_frames.c and
 * dot11_data.c do: probe.c is compiled only under WITH_PCAP and is
 * absent from TEST_SRCS, so logic placed there cannot be tested. */

#define FRAG_MAX_BSS      64
#define FRAG_MAX_STATIONS 128

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

int              frag_bss_count(void);
const frag_bss_t *frag_bss_at(int i);
/* Index of `bssid` in the table, or -1. */
int              frag_find(const uint8_t bssid[6]);

void frag_clear(void);

#endif /* FRAGATTACK_H */
