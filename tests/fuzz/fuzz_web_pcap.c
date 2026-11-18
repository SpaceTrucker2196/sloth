#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libFuzzer smoke target for slothweb's pcap reader and frame decoders
 * (web/src/web_pcap.c) and its manifest line parser
 * (web/src/web_pcapdir.c): the alert page's packet capture.
 *
 * Every byte of a capture file came off a network, and the --pcap-dir
 * reader is the one place slothweb walks a buffer whose strides it
 * reads from that buffer: the record lengths, then per frame radiotap's
 * self-describing header, the 802.11 MAC header, the element walk, the
 * IP header lengths, TCP's data offset, DNS names with compression
 * pointers, a TLS ClientHello's nested lengths. The unit tests
 * (web/tests/test_evidence.c) build the truncated and malformed cases
 * a reader picks; this searches for the ones nobody picked.
 *
 * As fuzz_web_query.c does, the web translation units are included
 * here directly (libsloth_core.a carries no web/ file); sloth's own
 * parsers they call (radiotap.c, dot11_frame.c, dot11_ie.c,
 * wifi_freq.c, dns_wire.c, netstr.c) come from the archive, as they
 * come from src/ in slothweb's link. All are pure: no clock, no lock,
 * no file.
 *
 * The input is used three ways: as a whole pcap file, paged through
 * web_pcap_frames_json() at two offsets into a buffer the size of a
 * connection's (whose overflow flag must stay clear: the page stops
 * early instead); as one frame under each link type the decoder knows;
 * and as one manifest line. */
#include "../../web/src/web_json.c"
#include "../../web/src/web_dot11_names.c"
#include "../../web/src/web_pcap.c"
#include "../../web/tools/sha256.c"
#include "../../web/src/web_pcapdir.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (1u << 20)) return 0;
    static char out[65536 - 1024];
    web_jw_t w;
    const char *why;
    for (long long off = 0; off < 48; off += 24) {
        web_jw_init(&w, out, sizeof(out));
        if (web_pcap_frames_json(data, size, off, &w, &why) == 0 && w.overflow) abort();
    }
    static const unsigned DLT[] = { 1, 105, 113, 127, 254, 276 };
    unsigned cap = size > WEB_PCAP_REC_MAX ? WEB_PCAP_REC_MAX : (unsigned)size;
    for (size_t i = 0; i < sizeof(DLT) / sizeof(DLT[0]); i++) {
        web_pcap_dec_t d;
        web_pcap_decode(DLT[i], data, cap, cap + (unsigned)(size & 0xff), &d);
        if (strlen(d.summary) >= sizeof(d.summary) || d.nkv > WEB_PCAP_KV_MAX) abort();
    }
    web_pcap_entry_t e;
    if (web_pcapdir_parse_line((const char *)data, size, &e) == 1 && !web_pcapdir_name_ok(e.file))
        abort();
    return 0;
}
