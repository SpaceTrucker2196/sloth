#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "eapol_log.h"

/* libFuzzer smoke target for the EAPOL-Key path in eapol_observe_dot11()
 * (#95). "fuzzing through the capture path" named parse_eapol_key as a
 * follow-up to fuzz_deauth_parse, deferred because parse_eapol_key() is
 * `static` and reaching it means going through eapol_observe_dot11()'s
 * full frame shape: an 802.11 data-frame header, an LLC/SNAP + EtherType
 * wrapper (IEEE 802.2, AA AA 03 00 00 00 + 0x888E), then the EAPOL
 * header, before a single byte of the Key body is read.
 *
 * That framing is fixed here rather than left to the fuzzer. A first
 * version passed the fuzzer's bytes straight through as the whole
 * frame, like fuzz_deauth_parse does for its much shallower parser —
 * and found nothing in over a million runs, because getting past eight
 * exact LLC/SNAP + EtherType bytes from an empty corpus is the classic
 * "magic number defeats coverage-guided fuzzing" case: every wrong byte
 * in that sequence returns from the same early `if`, so there is no
 * finer-grained coverage edge for the fuzzer to climb on one byte at a
 * time. Verified directly (not inferred): a temporary stderr probe
 * placed right after the LLC/EtherType match in eapol_observe_dot11()
 * never fired once across 1,076,641 runs in 20 seconds.
 *
 * So the skeleton below is built the same way every hand-built test
 * frame in this repo is built — not a captured fixture, a byte array
 * from the spec — and only the part actually under test, the Key body
 * parse_eapol_key() walks, is the fuzzer's own bytes. This is what lets
 * a 20-second smoke run exercise parse_eapol_key's length and offset
 * arithmetic instead of spending its whole budget failing an LLC check.
 *
 * No libpcap in this path (unlike the monitor-decode seam), so the
 * fuzzer's own tightly-redzoned buffer is what parse_eapol_key reads —
 * nothing masks a modest overread the way libpcap's offline-read buffer
 * would (that buffer is sized well past any one record's caplen;
 * verified separately, which is why this slice does not add a fuzz
 * target over the monitor-decode seam).
 *
 * eapol_observe_dot11() reaches real module-static tables (eap_track,
 * wps_track, assoc_track, alerts.c) — all bounded, all zero-initialised,
 * no sloth_state_t needed. Nothing is ever written to disk:
 * crackable-material export is gated behind --collect-handshakes
 * (src/eapol_log.c's g_collect), which defaults off and nothing here
 * turns on.
 *
 * Smoke, not a campaign: no corpus is kept in-tree and there is no
 * crash-triage process, same as every other target in this file. */

#define SKEL_80211_HDR 24   /* FC+Dur+Addr1+Addr2+Addr3+SeqCtl, to_ds=1 */
#define SKEL_LLC_SNAP   8   /* AA AA 03 00 00 00 + EtherType 0x888E    */
#define SKEL_EAPOL_HDR  4   /* version, type=3 (EAPOL-Key), body len   */
#define SKEL_LEN (SKEL_80211_HDR + SKEL_LLC_SNAP + SKEL_EAPOL_HDR)
#define BODY_MAX 1024       /* generous over EAPOL_KEY_FIXED_LEN (99)  */

/* runner.h expects these at file scope somewhere (#114); this target
 * links the test build's core archive for symbol availability (see
 * FUZZ_CORE_SRCS in the Makefile, #115) but never runs any RUN_TEST
 * itself, so no default setUp is needed here either. */
int g_pass      = 0;
int g_fail      = 0;
int g_test_fail = 0;
int g_test_total = 0;
void (*g_test_setup)(void) = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > BODY_MAX) return 0;

    uint8_t frame[SKEL_LEN + BODY_MAX];
    memset(frame, 0, SKEL_LEN);

    /* 802.11 data frame, to_ds=1/from_ds=0 (STA -> AP), non-QoS, no HT
     * Order bit — the plainest shape that reaches hdr == 24 exactly. */
    frame[0] = 0x08;   /* type=2 (Data), subtype=0 */
    frame[1] = 0x01;   /* ToDS=1 */

    uint8_t *llc = frame + SKEL_80211_HDR;
    memcpy(llc, "\xAA\xAA\x03\x00\x00\x00\x88\x8E", 8);

    uint8_t *eapol = llc + SKEL_LLC_SNAP;
    eapol[0] = 1;                       /* EAPOL version   */
    eapol[1] = 3;                       /* type: EAPOL-Key */
    eapol[2] = (uint8_t)(size >> 8);    /* body length, hi */
    eapol[3] = (uint8_t)(size & 0xff);  /* body length, lo */

    memcpy(eapol + SKEL_EAPOL_HDR, data, size);

    eapol_observe_dot11(frame, (int)(SKEL_LEN + size),
                        /*signal=*/-50, /*channel=*/6,
                        /*ts_sec=*/1700000000, /*ts_usec=*/0);
    return 0;
}
