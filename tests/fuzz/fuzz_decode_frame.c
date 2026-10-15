#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "sloth.h"
#include "capture/capture.h"

/* libFuzzer smoke target for decode_frame() (#125).
 *
 * decode_frame() is where every wired and monitor-radio frame enters
 * the IP decoders: the datalink switch, the 802.1Q strip, then IPv4 /
 * IPv6 and from there every protocol snooper in capture.c's dispatch —
 * DNS, TLS SNI, HTTP, the cleartext-credential parsers, SMB, Kerberos,
 * LDAP, DHCP, NDP and the rest. The 2026-10 review rewrites that
 * dispatch ("decode each frame once"); this is its baseline.
 *
 * It is static inside capture.c's WITH_PCAP guard, so it is reached
 * through capture_test_decode_frame() and built by the WITH_PCAP fuzz
 * rule (FUZZ_PCAP_TARGETS in the Makefile). It is NOT reached through
 * capture_test_dispatch(): that seam goes through libpcap's offline
 * reader, whose buffer runs well past each record's caplen, so ASan has
 * no redzone where the frame ends and a modest overread passes. Here
 * the bytes decode_frame() reads are the fuzzer's own buffer.
 *
 * Two leading bytes are arguments rather than frame:
 *   byte 0  the DLT, one of the four decode_frame() accepts — the low
 *           two bits, so every value selects a real branch instead of
 *           most of them hitting the unknown-DLT return;
 *   byte 1  how many octets the wire frame was longer than the capture
 *           (origlen - caplen). On the radiotap DLT that difference is
 *           what dot11_fcs_strip_len() decides on, so pinning it would
 *           leave the FCS-strip arithmetic unfuzzed.
 *
 * The snoopers it reaches keep bounded module-static tables; nothing is
 * written to disk. */

/* pcap-linktype(7) values, spelled out because the two cooked-capture
 * ones are not defined by every libpcap this builds against — capture.c
 * carries its own copies for the same reason. */
static const int k_dlts[4] = {
    1,     /* DLT_EN10MB           */
    113,   /* DLT_LINUX_SLL        */
    276,   /* DLT_LINUX_SLL2       */
    127,   /* DLT_IEEE802_11_RADIO */
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > 65535 + 2) return 0;

    const int dlt     = k_dlts[data[0] & 3];
    const int caplen  = (int)size - 2;
    const int origlen = caplen + data[1];

    packet_info_t pkt;
    capture_test_decode_frame(data + 2, caplen, origlen, dlt, &pkt);

    /* Read the string output so a missing terminator faults here. */
    size_t n = strnlen(pkt.info, sizeof(pkt.info));
    return (int)(n & 0);
}
