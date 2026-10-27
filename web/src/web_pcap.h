/* A libpcap-free pcap reader and bounded frame decoders for the alert
 * page's "packet capture" section (owner request 2026-10-27: "show the
 * full packet capture in alerts at the bottom as well").
 *
 * The file format is the classic pcap savefile, IETF
 * draft-ietf-opsawg-pcap-09 "PCAP Capture File Format": §4 the file
 * header (magic 0xA1B2C3D4 for microsecond stamps, 0xA1B23C4D for
 * nanosecond ones, each in either byte order, the reader telling them
 * apart by the first four octets; major 2, minor 4; SnapLen; LinkType
 * in the low 16 bits of the last word), §5 the packet record (seconds,
 * fraction in the magic's unit, captured length, original length, the
 * data unpadded). sloth writes the microsecond form little-endian and
 * never pcapng (src/pcap_format.c); both byte orders and both
 * resolutions are read because the draft requires it and a file the
 * operator dropped beside sloth's could be either, and pcapng (a
 * Section Header Block, 0A 0D 0D 0A) is refused with its own word.
 *
 * Link types are tcpdump.org's "Link-layer header types": ETHERNET 1,
 * IEEE802_11 105, LINUX_SLL 113, IEEE802_11_RADIOTAP 127,
 * BLUETOOTH_LINUX_MONITOR 254, LINUX_SLL2 276.
 *
 * Decoding is in two tiers. 802.11 frames (105, 127) go through
 * sloth's own parsers, linked from src/ (radiotap.c, dot11_frame.c,
 * dot11_ie.c, wifi_freq.c, netstr.c; WEB_CORE_SRCS in the Makefile),
 * so the page reads a frame's header exactly as the sensor did. The
 * IP tiers (Ethernet, SLL, SLL2, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP,
 * TLS) are a summary decoder of this file's own, because sloth's live
 * ones are static inside src/capture/capture.c, src/tls_log.c and
 * src/http_log.c and cannot be linked without the sensor's state; the
 * DNS name walk is sloth's (src/dns_wire.c). The page says which.
 *
 * Every byte here came off a network and is treated as hostile: every
 * read is bounded by caplen, a structure that runs past it marks the
 * frame "truncated" (the --pcap-dir files are 64 bytes a packet, so
 * this is the common case, not an error), and every string that
 * leaves is cut, printable-ASCII filtered and written through
 * web_jw_str(). The record walk stops at WEB_PCAP_RECORDS; a record
 * header that does not fit, or claims more than its file holds, ends
 * the walk with "truncated_file". tests/fuzz/fuzz_web_pcap.c
 * fuzzes the reader and the decoders together. */
#ifndef SLOTHWEB_PCAP_H
#define SLOTHWEB_PCAP_H

#include <stddef.h>
#include <stdint.h>

#include "web_json.h"

/* Records indexed per file; past it the answer says "more" and the
 * download link has the rest. */
#define WEB_PCAP_RECORDS   4096
/* A record longer than this is a malformed file, not a frame: the
 * largest snaplen sloth's writers declare (src/evidence_export.c). */
#define WEB_PCAP_REC_MAX   262144
/* Frames per page of /api/pcap/frames, and the bytes of each frame's
 * hex dump sent inline: 24 x (a 256-byte dump as 16 rows of 16, plus
 * the decode) stays under the connection's 64 KiB buffer
 * (web/tests/test_pcap.c :: test_worst_case_page_fits). */
#define WEB_PCAP_PAGE      24
#define WEB_PCAP_HEX       256
/* The most one frame's JSON can take: every string at its cut, escaped
 * six-fold where a byte could need it, and the 256-byte dump. A page
 * stops early (and says "more") rather than overrun its buffer. */
#define WEB_PCAP_FRAME_JSON 27648

#define WEB_PCAP_FILE_HDR  24
#define WEB_PCAP_REC_HDR   16

typedef struct {
    int      swapped;         /* the file's byte order is not the host's */
    int      nanos;           /* fraction is nanoseconds */
    unsigned major, minor;
    unsigned snaplen;
    unsigned linktype;        /* the low 16 bits of the LinkType word */
} web_pcap_hdr_t;

/* Read the file header. 0, or -1 with *why one of "short_file",
 * "pcapng_not_supported", "not_pcap". */
int web_pcap_header(const uint8_t *buf, size_t n, web_pcap_hdr_t *h,
                    const char **why);

typedef struct {
    size_t    off;            /* of the data */
    unsigned  caplen, origlen;
    long long ts_sec;
    unsigned  ts_frac;        /* in the file's unit */
} web_pcap_rec_t;

/* The record at *off (the first is at WEB_PCAP_FILE_HDR). 1 and *off
 * moved past it; 0 at a clean end of file; -1 when a header does not
 * fit, caplen is past the snaplen or WEB_PCAP_REC_MAX, or the data runs
 * past the file (a file cut short: the walk ends there). origlen is
 * raised to caplen when it is smaller, as sloth's writer does. */
int web_pcap_next(const uint8_t *buf, size_t n, const web_pcap_hdr_t *h,
                  size_t *off, web_pcap_rec_t *r);

/* The link type's name, or "dlt N" for one this file does not know. */
const char *web_pcap_linktype_name(unsigned linktype, char *buf, size_t cap);

/* ── one frame, decoded ───────────────────────────────────────────── */

#define WEB_PCAP_KV_MAX 20
#define WEB_PCAP_STR    96

typedef struct {
    char  link[32];           /* "802.11 radiotap", "ethernet", ... */
    char  kind[48];           /* "Deauthentication", "IPv4 TCP", ... */
    char  from[WEB_PCAP_STR], to[WEB_PCAP_STR];
    char  summary[360];
    int   truncated;          /* caplen ended inside a structure */
    int   nkv;                /* the fields, in order */
    char  k[WEB_PCAP_KV_MAX][24];
    char  v[WEB_PCAP_KV_MAX][WEB_PCAP_STR];
} web_pcap_dec_t;

/* Decode caplen bytes at p (the frame's captured bytes) of a record
 * whose original length was origlen, under the file's link type. */
void web_pcap_decode(unsigned linktype, const uint8_t *p, unsigned caplen,
                     unsigned origlen, web_pcap_dec_t *out);

/* The hex dump of the first min(n, WEB_PCAP_HEX) bytes: rows of
 * "oooo  xx xx ... xx  |ascii|", '.' for a byte outside 0x20..0x7e,
 * newline-separated, into out (cap bytes). Returns the bytes dumped. */
size_t web_pcap_hexdump(const uint8_t *p, size_t n, char *out, size_t cap);

/* The JSON members of one page: "file" (the header), "frames" (from
 * offset, at most WEB_PCAP_PAGE), "frames_total", "truncated_file",
 * "more", "next_offset". Written at w's current position, no braces;
 * the caller opens the object and adds the hash line. Returns 0, or
 * -1 for a file whose header is refused (*why set, nothing written). */
int web_pcap_frames_json(const uint8_t *buf, size_t n, long long offset,
                         web_jw_t *w, const char **why);

#endif
