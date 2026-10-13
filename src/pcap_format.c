#include <string.h>

#include "pcap_format.h"

/* pcap-savefile magic, in its natural reading order. Written
 * little-endian like every other field, so the first four bytes on disk
 * are d4 c3 b2 a1 — which is what libpcap's "swapped" magic check
 * matches on a little-endian reader. */
#define PCAP_MAGIC      0xa1b2c3d4u
#define PCAP_VER_MAJOR  2
#define PCAP_VER_MINOR  4

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v       & 0xff);
    p[1] = (uint8_t)((v>>8)  & 0xff);
    p[2] = (uint8_t)((v>>16) & 0xff);
    p[3] = (uint8_t)((v>>24) & 0xff);
}

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v      & 0xff);
    p[1] = (uint8_t)((v>>8) & 0xff);
}

void pcap_fmt_file_hdr(uint8_t out[PCAP_FILE_HDR_LEN],
                       uint32_t dlt, uint32_t snaplen) {
    if (!out) return;
    put32(out +  0, PCAP_MAGIC);
    put16(out +  4, PCAP_VER_MAJOR);
    put16(out +  6, PCAP_VER_MINOR);
    put32(out +  8, 0);          /* thiszone: timestamps are UTC */
    put32(out + 12, 0);          /* sigfigs: unused by every reader */
    put32(out + 16, snaplen);
    put32(out + 20, dlt);
}

void pcap_fmt_rec_hdr(uint8_t out[PCAP_REC_HDR_LEN],
                      uint32_t ts_sec, uint32_t ts_usec,
                      uint32_t caplen, uint32_t origlen) {
    if (!out) return;
    /* See the header: a record claiming fewer original than captured
     * bytes misparses every record that follows it, so this is clamped
     * rather than trusted. */
    if (origlen < caplen) origlen = caplen;
    put32(out +  0, ts_sec);
    put32(out +  4, ts_usec);
    put32(out +  8, caplen);
    put32(out + 12, origlen);
}

void pcap_fmt_put_file_hdr(FILE *f, uint32_t dlt, uint32_t snaplen) {
    if (!f) return;
    uint8_t h[PCAP_FILE_HDR_LEN];
    pcap_fmt_file_hdr(h, dlt, snaplen);
    fwrite(h, 1, sizeof(h), f);
}

void pcap_fmt_put_rec(FILE *f, uint32_t ts_sec, uint32_t ts_usec,
                      const void *data, uint32_t caplen, uint32_t origlen) {
    if (!f) return;
    /* No payload means no record. Writing a header for bytes that do not
     * follow is the corruption described in the header comment, reached
     * from the other direction. */
    if (!data || caplen == 0) return;
    uint8_t h[PCAP_REC_HDR_LEN];
    pcap_fmt_rec_hdr(h, ts_sec, ts_usec, caplen, origlen);
    fwrite(h, 1, sizeof(h), f);
    fwrite(data, 1, caplen, f);
}

uint32_t pcap_fmt_dlt_or_default(int linktype) {
    return linktype ? (uint32_t)linktype : (uint32_t)PCAP_DLT_EN10MB;
}
