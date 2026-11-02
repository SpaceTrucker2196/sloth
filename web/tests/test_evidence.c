/* The alert page's proof (web_evidence.h): the pcap reader and frame
 * decoders (web_pcap.h), the pcap directory's gate and manifest index
 * (web_pcapdir.h), the assessment generator (web/tools/alertasm.c), and
 * the routes that serve them.
 *
 * No capture file is checked in (agents/AGENTS.md "No pcap fixtures"):
 * every frame below is a byte array built per the clause that defines
 * it, and every pcap file is written at run time, under the run's own
 * temporary directory, from those arrays. A manifest line is written in
 * the exact shape src/evidence_manifest.c's snprintf() produces
 * (evidence_manifest_record_pinned()), with its SHA-256 computed here. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sha256.h"
#include "web_alertasm.h"
#include "web_alerts.h"
#include "web_assets.h"
#include "web_dot11_names.h"
#include "web_evidence.h"
#include "web_ingest.h"
#include "web_live.h"
#include "web_pcap.h"
#include "web_pcapdir.h"
#include "web_routes.h"
#include "wt_tmp.h"
#include "wtest.h"

/* ── building files ───────────────────────────────────────────────── */

typedef struct {
    uint8_t b[1 << 16];
    size_t  n;
    int     swapped;
} pf_t;

static void put32(pf_t *f, uint32_t v) {
    if (f->swapped)
        v = (v >> 24) | ((v >> 8) & 0xff00u) | ((v << 8) & 0xff0000u) | (v << 24);
    f->b[f->n++] = (uint8_t)v; f->b[f->n++] = (uint8_t)(v >> 8);
    f->b[f->n++] = (uint8_t)(v >> 16); f->b[f->n++] = (uint8_t)(v >> 24);
}
static void put16(pf_t *f, uint16_t v) {
    if (f->swapped) v = (uint16_t)((v >> 8) | (v << 8));
    f->b[f->n++] = (uint8_t)v; f->b[f->n++] = (uint8_t)(v >> 8);
}

/* draft-ietf-opsawg-pcap §4: magic, 2.4, reserved 0 0, snaplen, link. */
static void pf_hdr(pf_t *f, int swapped, int ns, unsigned snaplen, unsigned dlt) {
    memset(f, 0, sizeof(*f));
    f->swapped = swapped;
    put32(f, ns ? 0xa1b23c4du : 0xa1b2c3d4u);
    put16(f, 2); put16(f, 4);
    put32(f, 0); put32(f, 0);
    put32(f, snaplen); put32(f, dlt);
}

/* §5: seconds, fraction, captured length, original length, data. */
static void pf_rec(pf_t *f, uint32_t sec, uint32_t frac, const uint8_t *p, unsigned caplen,
                   unsigned origlen) {
    put32(f, sec); put32(f, frac); put32(f, caplen); put32(f, origlen);
    memcpy(f->b + f->n, p, caplen);
    f->n += caplen;
}

/* ── frames, each per its clause ──────────────────────────────────── */

/* Ethernet II (IEEE 802.3 §3.2.6 type field) + IPv4 (RFC 791 §3.1,
 * IHL 5, total length 256: the packet was longer than its 64 captured
 * bytes) + TCP (RFC 9293 §3.1, data offset 5, PSH|ACK) + the first ten
 * bytes of a TLS 1.2 record carrying a ClientHello (RFC 8446 §5.1,
 * §4.1.2): what one record of a --pcap-dir file holds. */
static const uint8_t ETH_TLS[64] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
    0x45, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
    192, 168, 1, 10, 93, 184, 216, 34,
    0xc3, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x18, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x16, 0x03, 0x01, 0x00, 0xf0, 0x01, 0x00, 0x00, 0xec, 0x03,
};

/* Ethernet + IPv4 (total 57) + UDP (RFC 768, 40000 -> 53, length 37) +
 * a DNS query (RFC 1035 §4.1: id 0x1234, RD, one question,
 * example.com A IN). 71 bytes. */
static const uint8_t ETH_DNS[71] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
    0x45, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
    10, 0, 0, 5, 10, 0, 0, 1,
    0x9c, 0x40, 0x00, 0x35, 0x00, 0x25, 0x00, 0x00,
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
    0x00, 0x01, 0x00, 0x01,
};

/* The same query whose name is a compression pointer to itself
 * (RFC 1035 §4.1.4: 0xC00C points at offset 12, which is the pointer). */
static const uint8_t ETH_DNS_LOOP[56] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00,
    0x45, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
    10, 0, 0, 5, 10, 0, 0, 1,
    0x9c, 0x40, 0x00, 0x35, 0x00, 0x16, 0x00, 0x00,
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x0c,
};

/* LINKTYPE_LINUX_SLL2 (tcpdump.org): protocol 0x0800, reserved,
 * ifindex 2, ARPHRD_ETHER 1, packet type 4 (sent by this host), address
 * length 6, address padded to 8; then IPv4 (proto 1, total 28) and an
 * ICMP echo request (RFC 792: type 8 code 0, id 1, seq 2). */
static const uint8_t SLL2_ICMP[48] = {
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x04, 0x06,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00,
    10, 0, 0, 1, 10, 0, 0, 2,
    0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,
};

/* LINKTYPE_LINUX_SLL: packet type 0 (to us), ARPHRD 1, address length
 * 6, address padded to 8, protocol 0x0806; then an ARP request
 * (RFC 826: Ethernet/IPv4, op 1, who has 10.0.0.1 tell 10.0.0.9). */
static const uint8_t SLL_ARP[44] = {
    0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
    0x08, 0x06,
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x09, 10, 0, 0, 9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 10, 0, 0, 1,
};

/* Radiotap (radiotap.org: version 0, length 13, present bits 3 Channel
 * and 5 dBm Antenna Signal; Channel aligned to 2 at offset 8: 2437 MHz,
 * flags 0x00a0 (2 GHz, CCK); signal -60 dBm) + a Deauthentication frame
 * (IEEE Std 802.11-2020 §9.3.3.12: FC type 0 subtype 12, addr1 the STA,
 * addr2 and addr3 the AP, sequence 1, Reason Code 7, Table 9-49). */
#define RT13 0x00, 0x00, 0x0d, 0x00, 0x28, 0x00, 0x00, 0x00, 0x85, 0x09, 0xa0, 0x00, 0xc4
static const uint8_t RT_DEAUTH[39] = {
    RT13,
    0xc0, 0x00, 0x00, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x00,
    0x07, 0x00,
};

/* A Beacon (§9.3.3.2): timestamp, interval 100 TU, capability ESS +
 * Privacy, then SSID "home" (§9.4.2.2), DSSS Parameter Set channel 6
 * (§9.4.2.4) and an RSN element (§9.4.2.24, version 1 only). */
static const uint8_t RT_BEACON[66] = {
    RT13,
    0x80, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x20, 0x00,
    0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00, 0x11, 0x00,
    0x00, 0x04, 'h', 'o', 'm', 'e',
    0x03, 0x01, 0x06,
    0x30, 0x02, 0x01, 0x00,
};

/* An Authentication frame (§9.3.3.11): algorithm 0 Open System,
 * transaction 1, Status Code 0 (Table 9-50). */
static const uint8_t RT_AUTH[43] = {
    RT13,
    0xb0, 0x00, 0x00, 0x00,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x30, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
};

static int has_kv(const web_pcap_dec_t *d, const char *k, const char *v) {
    for (int i = 0; i < d->nkv; i++)
        if (!strcmp(d->k[i], k) && (!v || strstr(d->v[i], v))) return 1;
    return 0;
}

/* ── the file ─────────────────────────────────────────────────────── */

static void test_header_forms(void) {
    static pf_t f;
    web_pcap_hdr_t h;
    const char *why;
    /* sloth's own: little-endian microseconds. */
    pf_hdr(&f, 0, 0, 64, 1);
    WT_EQ(web_pcap_header(f.b, f.n, &h, &why), 0);
    WT_EQ(h.swapped, 0); WT_EQ(h.nanos, 0); WT_EQ(h.snaplen, 64); WT_EQ(h.linktype, 1);
    WT_EQ(h.major, 2); WT_EQ(h.minor, 4);
    /* The other byte order and the nanosecond magic. */
    pf_hdr(&f, 1, 1, 262144, 127);
    WT_EQ(web_pcap_header(f.b, f.n, &h, &why), 0);
    WT_EQ(h.swapped, 1); WT_EQ(h.nanos, 1); WT_EQ(h.snaplen, 262144); WT_EQ(h.linktype, 127);
    /* The LinkType word's high bits (FCS length) are not the link type. */
    pf_hdr(&f, 0, 0, 64, 0x10000001u);
    WT_EQ(web_pcap_header(f.b, f.n, &h, &why), 0);
    WT_EQ(h.linktype, 1);
    /* pcapng's Section Header Block is refused by name, even short. */
    static const uint8_t ng[28] = { 0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a };
    WT_EQ(web_pcap_header(ng, sizeof(ng), &h, &why), -1);
    WT_ASSERT(why && !strcmp(why, "pcapng_not_supported"));
    WT_EQ(web_pcap_header(ng, 4, &h, &why), -1);
    WT_ASSERT(why && !strcmp(why, "pcapng_not_supported"));
    WT_EQ(web_pcap_header(f.b, 10, &h, &why), -1);
    WT_ASSERT(why && !strcmp(why, "short_file"));
    static const uint8_t junk[24] = "GIF89a not a capture..";
    WT_EQ(web_pcap_header(junk, sizeof(junk), &h, &why), -1);
    WT_ASSERT(why && !strcmp(why, "not_pcap"));
    char nb[24];
    WT_ASSERT(!strcmp(web_pcap_linktype_name(276, nb, sizeof(nb)), "linux sll2"));
    WT_ASSERT(!strcmp(web_pcap_linktype_name(4242, nb, sizeof(nb)), "dlt 4242"));
}

static void test_record_walk(void) {
    static pf_t f;
    web_pcap_hdr_t h;
    web_pcap_rec_t r;
    const char *why;
    for (int sw = 0; sw < 2; sw++) {
        pf_hdr(&f, sw, sw, 64, 1);
        pf_rec(&f, 1000, 5, ETH_TLS, 64, 270);
        /* orig_len below incl_len is raised, as sloth's writer does. */
        pf_rec(&f, 1001, 6, ETH_TLS, 60, 10);
        WT_EQ(web_pcap_header(f.b, f.n, &h, &why), 0);
        size_t off = WEB_PCAP_FILE_HDR;
        WT_EQ(web_pcap_next(f.b, f.n, &h, &off, &r), 1);
        WT_EQ(r.ts_sec, 1000); WT_EQ(r.ts_frac, 5); WT_EQ(r.caplen, 64); WT_EQ(r.origlen, 270);
        WT_EQ(web_pcap_next(f.b, f.n, &h, &off, &r), 1);
        WT_EQ(r.caplen, 60); WT_EQ(r.origlen, 60);
        WT_EQ(web_pcap_next(f.b, f.n, &h, &off, &r), 0);
        /* A file cut inside the last record ends the walk with -1. */
        off = WEB_PCAP_FILE_HDR;
        WT_EQ(web_pcap_next(f.b, f.n - 1, &h, &off, &r), 1);
        WT_EQ(web_pcap_next(f.b, f.n - 1, &h, &off, &r), -1);
    }
    /* caplen past the snaplen is a malformed record. */
    pf_hdr(&f, 0, 0, 32, 1);
    pf_rec(&f, 1, 0, ETH_TLS, 64, 64);
    WT_EQ(web_pcap_header(f.b, f.n, &h, &why), 0);
    size_t off = WEB_PCAP_FILE_HDR;
    WT_EQ(web_pcap_next(f.b, f.n, &h, &off, &r), -1);
}

/* ── the decoders ─────────────────────────────────────────────────── */

static void test_decode_ip_tiers(void) {
    web_pcap_dec_t d;
    web_pcap_decode(1, ETH_TLS, sizeof(ETH_TLS), 270, &d);
    WT_ASSERT(!strcmp(d.link, "ethernet"));
    WT_ASSERT(!strcmp(d.kind, "TLS"));
    WT_ASSERT(!strcmp(d.from, "192.168.1.10:50000"));
    WT_ASSERT(!strcmp(d.to, "93.184.216.34:443"));
    WT_ASSERT(d.truncated);
    WT_ASSERT(has_kv(&d, "tcp flags", "PSH"));
    WT_ASSERT(has_kv(&d, "handshake", "ClientHello"));
    WT_HAS(d.summary, "ClientHello (cut by snaplen)");
    /* No SNI is claimed for a hello the snaplen cut. Seen red with an
     * empty "sni" recorded for a cut hello. */
    WT_ASSERT(!has_kv(&d, "sni", NULL));

    web_pcap_decode(1, ETH_DNS, sizeof(ETH_DNS), sizeof(ETH_DNS), &d);
    WT_ASSERT(!strcmp(d.kind, "DNS"));
    WT_ASSERT(!d.truncated);
    WT_ASSERT(has_kv(&d, "qname", "example.com"));
    WT_ASSERT(has_kv(&d, "qtype", "A"));
    WT_ASSERT(has_kv(&d, "dns id", "0x1234"));
    WT_HAS(d.summary, "DNS query A example.com");
    /* Cut at sloth's 64 bytes, the name runs past the capture. */
    web_pcap_decode(1, ETH_DNS, 64, sizeof(ETH_DNS), &d);
    WT_ASSERT(d.truncated);
    WT_HAS(d.summary, "name cut or malformed");
    /* A pointer to itself is refused, not followed. */
    web_pcap_decode(1, ETH_DNS_LOOP, sizeof(ETH_DNS_LOOP), sizeof(ETH_DNS_LOOP), &d);
    WT_ASSERT(d.truncated);
    WT_HAS(d.summary, "name cut or malformed");

    web_pcap_decode(276, SLL2_ICMP, sizeof(SLL2_ICMP), sizeof(SLL2_ICMP), &d);
    WT_ASSERT(!strcmp(d.link, "linux sll2"));
    WT_ASSERT(!strcmp(d.kind, "ICMP"));
    WT_ASSERT(has_kv(&d, "direction", "sent by host"));
    WT_ASSERT(has_kv(&d, "icmp type", "echo request"));
    WT_ASSERT(has_kv(&d, "seq", "2"));
    WT_ASSERT(!strcmp(d.from, "10.0.0.1") && !strcmp(d.to, "10.0.0.2"));
    /* The SLL2 header itself cut short. */
    web_pcap_decode(276, SLL2_ICMP, 12, sizeof(SLL2_ICMP), &d);
    WT_ASSERT(d.truncated);

    web_pcap_decode(113, SLL_ARP, sizeof(SLL_ARP), sizeof(SLL_ARP), &d);
    WT_ASSERT(!strcmp(d.link, "linux sll"));
    WT_ASSERT(!strcmp(d.kind, "ARP"));
    WT_HAS(d.summary, "ARP who has 10.0.0.1, tell 10.0.0.9");

    /* A link type with no decoder is shown as hex only, by its number. */
    web_pcap_decode(254, SLL_ARP, sizeof(SLL_ARP), sizeof(SLL_ARP), &d);
    WT_ASSERT(!strcmp(d.kind, "hex only"));
    WT_ASSERT(!strcmp(d.link, "bluetooth hci monitor"));
}

static void test_decode_dot11(void) {
    web_pcap_dec_t d;
    web_pcap_decode(127, RT_DEAUTH, sizeof(RT_DEAUTH), sizeof(RT_DEAUTH), &d);
    WT_ASSERT(!strcmp(d.link, "802.11 radiotap"));
    WT_ASSERT(!strcmp(d.kind, "Deauthentication"));
    WT_ASSERT(has_kv(&d, "reason", "7: Class 3 frame received from nonassociated STA"));
    WT_ASSERT(has_kv(&d, "channel", "2437 MHz (ch 6, 2.4 GHz)"));
    WT_ASSERT(has_kv(&d, "rssi", "-60 dBm"));
    /* Table 9-26's roles for a management frame: addr1 RA/DA, addr2
     * TA/SA, addr3 the BSSID. */
    WT_ASSERT(has_kv(&d, "addr1", "11:22:33:44:55:66 = RA DA"));
    WT_ASSERT(has_kv(&d, "addr2", "aa:bb:cc:dd:ee:ff = TA SA"));
    WT_ASSERT(has_kv(&d, "addr3", "BSSID"));
    WT_ASSERT(has_kv(&d, "seq / frag", "1 / 0"));
    WT_ASSERT(!strcmp(d.from, "aa:bb:cc:dd:ee:ff") && !strcmp(d.to, "11:22:33:44:55:66"));
    WT_ASSERT(!d.truncated);
    /* The reason code cut off: no reason read from half of it. Seen red
     * with the length check lowered to one byte. */
    web_pcap_decode(127, RT_DEAUTH, sizeof(RT_DEAUTH) - 1, sizeof(RT_DEAUTH), &d);
    WT_ASSERT(d.truncated);
    WT_ASSERT(!has_kv(&d, "reason", NULL));
    /* The radiotap header claiming more than the capture. */
    uint8_t bad[sizeof(RT_DEAUTH)];
    memcpy(bad, RT_DEAUTH, sizeof(bad));
    bad[2] = 0xff;
    web_pcap_decode(127, bad, sizeof(bad), sizeof(bad), &d);
    WT_ASSERT(d.truncated);
    WT_HAS(d.kind, "radiotap");

    web_pcap_decode(127, RT_BEACON, sizeof(RT_BEACON), sizeof(RT_BEACON), &d);
    WT_ASSERT(!strcmp(d.kind, "Beacon"));
    WT_ASSERT(has_kv(&d, "ssid", "home"));
    WT_ASSERT(has_kv(&d, "ds channel", "6"));
    WT_ASSERT(has_kv(&d, "rsn", "present"));
    WT_ASSERT(has_kv(&d, "capability", "ESS, privacy"));
    /* Seen red with the element's verdict written for every SSID. */
    WT_ASSERT(!has_kv(&d, "ssid element", NULL));
    /* An SSID element of 33 octets is invalid (§9.4.2.2), and said so. */
    uint8_t big[sizeof(RT_BEACON) + 29];
    memcpy(big, RT_BEACON, 13 + 24 + 12);
    size_t o = 13 + 24 + 12;
    big[o++] = 0x00; big[o++] = 33;
    memset(big + o, 'A', 33);
    o += 33;
    web_pcap_decode(127, big, (unsigned)o, (unsigned)o, &d);
    WT_ASSERT(has_kv(&d, "ssid element", "over 32 octets"));

    web_pcap_decode(127, RT_AUTH, sizeof(RT_AUTH), sizeof(RT_AUTH), &d);
    WT_ASSERT(!strcmp(d.kind, "Authentication"));
    WT_ASSERT(has_kv(&d, "algorithm", "0: Open System"));
    WT_ASSERT(has_kv(&d, "status", "0: Successful"));
    WT_ASSERT(has_kv(&d, "auth seq", "1"));

    /* The tables answer every code, never NULL. */
    WT_ASSERT(!strcmp(web_dot11_reason_name(3),
                      "Deauthenticated because sending STA is leaving (or has left) IBSS or ESS"));
    WT_ASSERT(web_dot11_reason_name(60000) != NULL);
    WT_ASSERT(web_dot11_status_name(60000) != NULL);
    WT_ASSERT(!strcmp(web_dot11_subtype_name(0, 8), "Beacon"));
    WT_ASSERT(!strcmp(web_dot11_subtype_name(9, 99), "reserved"));
}

static void test_hexdump(void) {
    char out[WEB_PCAP_HEX / 16 * 78 + 8];
    static const uint8_t b[18] = { 'G', 'E', 'T', ' ', '/', 0x00, 0x01, 0x7f, 'a', 'b', 'c', 'd',
                                   'e', 'f', 'g', 'h', 'i', 'j' };
    WT_EQ(web_pcap_hexdump(b, sizeof(b), out, sizeof(out)), 18);
    WT_HAS(out, "0000  47 45 54 20 2f 00 01 7f  61 62 63 64 65 66 67 68  |GET /...abcdefgh|");
    WT_HAS(out, "\n0010  69 6a ");
    WT_HAS(out, "|ij|");
    /* At most WEB_PCAP_HEX bytes, and the caller is told how many. */
    static uint8_t long_[300];
    WT_EQ(web_pcap_hexdump(long_, sizeof(long_), out, sizeof(out)), WEB_PCAP_HEX);
}

/* A page's JSON, at the worst the decoders allow: every frame a full
 * 256-byte dump of bytes that escape six-fold, through a 64 KiB
 * connection buffer less the header reserve. The page stops early and
 * says "more" rather than overflow. */
static void test_frames_page(void) {
    static pf_t f;
    static char buf[65536 - WEB_LIVE_HDR_RESERVE];
    pf_hdr(&f, 0, 0, 64, 1);
    for (int i = 0; i < 30; i++) pf_rec(&f, 1000 + (uint32_t)i, (uint32_t)i * 1000, ETH_TLS, 64, 270);
    web_jw_t w;
    const char *why;
    web_jw_init(&w, buf, sizeof(buf));
    web_jw_raw(&w, "{");
    WT_EQ(web_pcap_frames_json(f.b, f.n, 0, &w, &why), 0);
    web_jw_raw(&w, "}");
    WT_ASSERT(!w.overflow);
    WT_HAS(buf, "\"frames_total\":30");
    WT_HAS(buf, "\"shown\":24");
    WT_HAS(buf, "\"more\":true,\"next_offset\":24");
    WT_HAS(buf, "\"cut\":\"truncated at snaplen 64\"");
    WT_HAS(buf, "\"t_rel_ns\":1001000000");
    WT_HAS(buf, "\"linktype_name\":\"ethernet\"");
    web_jw_init(&w, buf, sizeof(buf));
    WT_EQ(web_pcap_frames_json(f.b, f.n, 24, &w, &why), 0);
    WT_ASSERT(!w.overflow);
    WT_HAS(buf, "\"shown\":6");
    WT_HAS(buf, "\"more\":false,\"next_offset\":null");
    /* The worst case: 262144-snaplen radiotap frames of '<' bytes. */
    static pf_t g;
    pf_hdr(&g, 0, 0, 262144, 127);
    static uint8_t lt[2000];
    memset(lt, '<', sizeof(lt));
    for (int i = 0; i < 30; i++) pf_rec(&g, 1, 0, lt, sizeof(lt), sizeof(lt));
    web_jw_init(&w, buf, sizeof(buf));
    WT_EQ(web_pcap_frames_json(g.b, g.n, 0, &w, &why), 0);
    WT_ASSERT(!w.overflow);
    WT_HAS(buf, "\"more\":true");
    WT_HAS(buf, "\"hex_more\":1744");
    /* A file cut short says so. */
    web_jw_init(&w, buf, sizeof(buf));
    WT_EQ(web_pcap_frames_json(f.b, f.n - 3, 0, &w, &why), 0);
    WT_HAS(buf, "\"truncated_file\":true");
    WT_HAS(buf, "\"frames_total\":29");
    /* A record cut below the header's snaplen was not cut by it: the
     * counts, not a cause the file does not support. The absence seen
     * red with the snaplen sentence written for every short record. */
    static pf_t c;
    pf_hdr(&c, 0, 0, 0xffffffffu, 1);
    pf_rec(&c, 1, 0, ETH_TLS, 40, 270);
    web_jw_init(&w, buf, sizeof(buf));
    WT_EQ(web_pcap_frames_json(c.b, c.n, 0, &w, &why), 0);
    WT_ASSERT(!w.overflow);
    WT_HAS(buf, "\"cut\":\"40 of 270 bytes captured\"");
    WT_LACKS(buf, "truncated at snaplen");
}

/* ── the directory ────────────────────────────────────────────────── */

static void test_name_gate(void) {
    static const char *const ok[] = {
        "alert_20261027_120000_Port_scan_from_10_0.pcap",
        "alert_20261027_120000_.pcap",
        "alert_20261027_120000_x_2.pcap",
        "0123456789abcdef-42-DEAUTH_FLOOD.pcap",
        "0123456789abcdef-42-DEAUTH_FLOOD-3.pcap",
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) WT_ASSERT(web_pcapdir_name_ok(ok[i]));
    /* What shares an --eapol-dir and must never be served: the
     * per-handshake pcap (src/eapol_log.c names it <bssid>_<sta>.pcap)
     * and the hashcat file. Seen red with web_pcapdir_name_ok()
     * reduced to "ends in .pcap" (the handshake name passed). */
    static const char *const no[] = {
        "aabbccddeeff_112233445566.pcap", "eapol.22000", "", ".", "..",
        "../alert_20261027_120000_x.pcap", "x/alert_20261027_120000_x.pcap",
        "alert_20261027_120000_x.pcapng", "alert_2026102_120000_x.pcap",
        "alert_20261027_120000_x-y.pcap", "alert_20261027_120000_x.pcap.tmp",
        "0123456789ABCDEF-42-DEAUTH_FLOOD.pcap", "0123456789abcdef--DEAUTH_FLOOD.pcap",
        "0123456789abcdef-42-.pcap", "0123456789abcdef-42-DEAUTH_FLOOD-123.pcap",
        "sloth-manifest-20261027T120000Z-0123456789abcdef.jsonl",
        "alert_20261027_120000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.pcap",
    };
    for (size_t i = 0; i < sizeof(no) / sizeof(no[0]); i++) {
        if (web_pcapdir_name_ok(no[i])) fprintf(stderr, "    passed: %s\n", no[i]);
        WT_ASSERT(!web_pcapdir_name_ok(no[i]));
    }
    char b[WEB_PCAP_NAME_MAX + 1];
    web_pcapdir_basename("/var/lib/sloth/pcap/alert_20261027_120000_x.pcap", b);
    WT_ASSERT(!strcmp(b, "alert_20261027_120000_x.pcap"));
    web_pcapdir_basename("/var/lib/sloth/eapol/aabbccddeeff_112233445566.pcap", b);
    WT_ASSERT(!strcmp(b, ""));
}

static void hex64(const uint8_t *p, size_t n, char out[65]) {
    uint8_t d[32];
    web_sha256(p, n, d);
    for (int i = 0; i < 32; i++) snprintf(out + 2 * i, 3, "%02x", d[i]);
}

/* One manifest line exactly as src/evidence_manifest.c writes it. */
static int manifest_line(char *out, size_t cap, int seq, const char *file, size_t size,
                         const char *sha, const char *sink, const char *inc, const char *rule,
                         long long epoch) {
    int n = snprintf(out, cap,
        "{\"v\":1,\"session\":\"%s\",\"seq\":%d,\"file\":\"%s\","
        "\"size\":%zu,\"sha256\":\"%s\",\"sink\":\"%s\"",
        "20261027T120000Z-00ff00ff00ff00ff", seq, file, size, sha, sink);
    if (inc && inc[0]) n += snprintf(out + n, cap - (size_t)n, ",\"incident_id\":\"%s\"", inc);
    if (rule && rule[0]) n += snprintf(out + n, cap - (size_t)n, ",\"rule\":\"%s\"", rule);
    n += snprintf(out + n, cap - (size_t)n,
                  ",\"reconstructed\":false,\"written_at\":\"2026-10-27T12:00:00Z\","
                  "\"written_at_epoch\":%lld}\n", epoch);
    return n;
}

static void test_manifest_line(void) {
    char l[1024];
    web_pcap_entry_t e;
    char sha[65];
    hex64((const uint8_t *)"x", 1, sha);
    int n = manifest_line(l, sizeof(l), 1, "alert_20261027_120000_x.pcap", 300, sha, "alert_pcap",
                          "0123456789abcdef", "PORT_SCAN", 1793102400);
    WT_EQ(web_pcapdir_parse_line(l, (size_t)n - 1, &e), 1);
    WT_ASSERT(!strcmp(e.file, "alert_20261027_120000_x.pcap"));
    WT_ASSERT(!strcmp(e.sink, "alert_pcap"));
    WT_ASSERT(!strcmp(e.rule, "PORT_SCAN"));
    WT_ASSERT(!strcmp(e.incident_id, "0123456789abcdef"));
    WT_ASSERT(!strcmp(e.sha256, sha));
    WT_EQ(e.size, 300);
    WT_EQ(e.written_at_epoch, 1793102400);
    WT_ASSERT(!strcmp(e.written_at, "2026-10-27T12:00:00Z"));
    /* Never indexed: the handshake sinks, whatever the name; a name
     * off the gate; a sink whose name is the other's shape. Seen red
     * with handshake_pcap admitted as a sink (the evidence-shaped
     * line's 0 went to 1). */
    n = manifest_line(l, sizeof(l), 2, "aabbccddeeff_112233445566.pcap", 3, sha, "handshake_pcap",
                      NULL, NULL, 1);
    WT_EQ(web_pcapdir_parse_line(l, (size_t)n - 1, &e), 0);
    n = manifest_line(l, sizeof(l), 3, "eapol.22000", 3, sha, "hashcat_22000", NULL, NULL, 1);
    WT_EQ(web_pcapdir_parse_line(l, (size_t)n - 1, &e), 0);
    n = manifest_line(l, sizeof(l), 4, "0123456789abcdef-1-PM_FORGE.pcap", 3, sha, "handshake_pcap",
                      "0123456789abcdef", "PM_FORGE", 1);
    WT_EQ(web_pcapdir_parse_line(l, (size_t)n - 1, &e), 0);
    n = manifest_line(l, sizeof(l), 5, "0123456789abcdef-1-PM_FORGE.pcap", 3, sha, "alert_pcap",
                      "0123456789abcdef", "PM_FORGE", 1);
    WT_EQ(web_pcapdir_parse_line(l, (size_t)n - 1, &e), 0);
    n = manifest_line(l, sizeof(l), 6, "0123456789abcdef-1-PM_FORGE.pcap", 3, sha, "evidence_pcap",
                      "0123456789abcdef", "PM_FORGE", 1);
    WT_EQ(web_pcapdir_parse_line(l, (size_t)n - 1, &e), 1);
    /* Malformed: a line cut anywhere. */
    n = manifest_line(l, sizeof(l), 7, "alert_20261027_120000_x.pcap", 300, sha, "alert_pcap",
                      NULL, NULL, 1);
    for (int cut = 1; cut < n - 1; cut += 7) WT_EQ(web_pcapdir_parse_line(l, (size_t)cut, &e), 0);
}

static char g_dir[TEST_TMP_MAX];

static int write_file(const char *name, const void *p, size_t n) {
    char path[TEST_TMP_MAX + 200];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(p, 1, n, f);
    return fclose(f) == 0 && w == n ? 0 : -1;
}

static int append_file(const char *name, const char *s) {
    char path[TEST_TMP_MAX + 200];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    FILE *f = fopen(path, "ab");
    if (!f) return -1;
    fputs(s, f);
    return fclose(f);
}

#define INC_A "0123456789abcdef"
#define NAME_A "alert_20261027_120000_Port_scan.pcap"
#define NAME_B "alert_20261027_120500_Port_scan.pcap"
#define NAME_C "alert_20261027_121000_Port_scan.pcap"
#define MANI "sloth-manifest-20261027T120000Z-00ff00ff00ff00ff.jsonl"

static pf_t g_pa;

/* The directory: file A listed by its incident, B listed with no
 * incident (a rule+time match), C on disk with no line (the record's
 * own name), a manifest whose tail is cut, a handshake pcap and the
 * hashcat file beside them. */
static int make_dir(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-ev-XXXXXX", test_tmpdir());
    if (!mkdtemp(g_dir)) return -1;
    pf_hdr(&g_pa, 0, 0, 64, 1);
    pf_rec(&g_pa, 1793102400, 0, ETH_TLS, 64, 270);
    pf_rec(&g_pa, 1793102401, 0, ETH_DNS, 64, sizeof(ETH_DNS));
    char sha[65], l[1024];
    hex64(g_pa.b, g_pa.n, sha);
    if (write_file(NAME_A, g_pa.b, g_pa.n) || write_file(NAME_B, g_pa.b, g_pa.n) ||
        write_file(NAME_C, g_pa.b, g_pa.n) ||
        write_file("aabbccddeeff_112233445566.pcap", g_pa.b, g_pa.n) ||
        write_file("eapol.22000", "WPA*02*x\n", 9))
        return -1;
    manifest_line(l, sizeof(l), 1, NAME_A, g_pa.n, sha, "alert_pcap", INC_A, "PORT_SCAN",
                  1793102400);
    append_file(MANI, l);
    manifest_line(l, sizeof(l), 2, NAME_B, g_pa.n, sha, "alert_pcap", NULL, "PORT_SCAN", 1793102700);
    append_file(MANI, l);
    manifest_line(l, sizeof(l), 3, "aabbccddeeff_112233445566.pcap", g_pa.n, sha, "handshake_pcap",
                  NULL, NULL, 1793102800);
    append_file(MANI, l);
    /* A crash's tail: the writer truncates a failed append, so an
     * unterminated line is never one sloth committed. */
    int n = manifest_line(l, sizeof(l), 4, NAME_C, g_pa.n, sha, "alert_pcap", INC_A, "PORT_SCAN",
                          1793102900);
    l[n - 1] = '\0';
    append_file(MANI, l);
    return 0;
}

static void test_dir_index(void) {
    WT_EQ(make_dir(), 0);
    const char *dirs[1] = { g_dir };
    web_pcapdir_t p;
    WT_EQ(web_pcapdir_init(&p, dirs, 1), 0);
    web_pcapdir_scan(&p, 1000);
    /* A and B, the handshake line and the cut tail not indexed. Seen
     * red with read_manifest() taking an unterminated tail (3). */
    WT_EQ(p.n, 2);
    WT_ASSERT(!strcmp(p.e[0].file, NAME_B));     /* newest first */
    WT_ASSERT(p.d[0].err == 0);
    char nb[96];
    WT_ASSERT(web_pcapdir_note(&p, nb, sizeof(nb)) == NULL);

    web_pcap_hit_t h[WEB_PCAPDIR_HITS];
    /* By incident; the record's own name adds C, with no line. */
    int n = web_pcapdir_for_alert(&p, 1000, INC_A, NAME_C, "PORT_SCAN", 1793102300,
                                  1793102500, h, WEB_PCAPDIR_HITS);
    WT_EQ(n, 2);
    WT_ASSERT(!strcmp(h[0].file, NAME_A) && !strcmp(h[0].matched_by, "incident"));
    WT_ASSERT(!strcmp(h[1].file, NAME_C) && !strcmp(h[1].matched_by, "record") && !h[1].e);
    /* B is another incident's: the rule+time fallback only runs when
     * the id and the record found nothing. */
    n = web_pcapdir_for_alert(&p, 1000, "ffffffffffffffff", "", "PORT_SCAN", 1793102300,
                              1793102500, h, WEB_PCAPDIR_HITS);
    WT_EQ(n, 2);
    WT_ASSERT(!strcmp(h[0].matched_by, "rule_time"));
    n = web_pcapdir_for_alert(&p, 1000, "ffffffffffffffff", "", "DEAUTH_FLOOD", 1793102300,
                              1793102500, h, WEB_PCAPDIR_HITS);
    WT_EQ(n, 0);
    /* The handshake pcap is on disk and passes no gate, by name or by
     * record. */
    n = web_pcapdir_for_alert(&p, 1000, "", "aabbccddeeff_112233445566.pcap", "", 0, 0, h,
                              WEB_PCAPDIR_HITS);
    WT_EQ(n, 0);

    /* Hash verification over the bytes read. */
    int err = 0;
    int dfd = web_pcapdir_open_dir(&p, 0, &err);
    WT_ASSERT(dfd >= 0);
    long long size = 0;
    const char *why = NULL;
    int fd = web_pcapdir_open_file(dfd, NAME_A, &size, &why);
    WT_ASSERT(fd >= 0);
    unsigned char *b = fd >= 0 ? web_pcapdir_slurp(fd, size) : NULL;
    if (fd >= 0) close(fd);
    WT_ASSERT(b != NULL);
    if (b) {
        WT_ASSERT(!strcmp(web_pcapdir_verify(b, (size_t)size, &p.e[1]), "verified"));
        b[30] ^= 1;
        WT_ASSERT(!strcmp(web_pcapdir_verify(b, (size_t)size, &p.e[1]), "MISMATCH"));
        WT_ASSERT(!strcmp(web_pcapdir_verify(b, (size_t)size - 1, &p.e[1]), "MISMATCH"));
        WT_ASSERT(!strcmp(web_pcapdir_verify(b, (size_t)size, NULL), "no_manifest_entry"));
        free(b);
    }
    /* Through the directory's descriptor only, following nothing: a
     * symlink at an artifact name, a FIFO, a name off the gate, a file
     * over the cap. */
    char path[TEST_TMP_MAX + 200], tgt[TEST_TMP_MAX + 200];
    snprintf(path, sizeof(path), "%s/alert_20261027_130000_link.pcap", g_dir);
    snprintf(tgt, sizeof(tgt), "%s/%s", g_dir, NAME_A);
    WT_EQ(symlink(tgt, path), 0);
    WT_EQ(web_pcapdir_open_file(dfd, "alert_20261027_130000_link.pcap", &size, &why), -1);
    WT_ASSERT(!strcmp(why, "not_regular"));
    snprintf(path, sizeof(path), "%s/alert_20261027_130000_fifo.pcap", g_dir);
    WT_EQ(mkfifo(path, 0600), 0);
    WT_EQ(web_pcapdir_open_file(dfd, "alert_20261027_130000_fifo.pcap", &size, &why), -1);
    WT_ASSERT(!strcmp(why, "not_regular"));
    WT_EQ(web_pcapdir_open_file(dfd, "aabbccddeeff_112233445566.pcap", &size, &why), -1);
    WT_ASSERT(!strcmp(why, "bad_name"));
    WT_EQ(web_pcapdir_open_file(dfd, "eapol.22000", &size, &why), -1);
    WT_ASSERT(!strcmp(why, "bad_name"));
    snprintf(path, sizeof(path), "%s/alert_20261027_130000_big.pcap", g_dir);
    int bfd = open(path, O_WRONLY | O_CREAT, 0600);
    WT_ASSERT(bfd >= 0);
    WT_EQ(ftruncate(bfd, (off_t)WEB_PCAP_FILE_MAX + 1), 0);
    close(bfd);
    WT_EQ(web_pcapdir_open_file(dfd, "alert_20261027_130000_big.pcap", &size, &why), -1);
    WT_ASSERT(!strcmp(why, "too_large"));
    WT_EQ(web_pcapdir_open_file(dfd, "alert_20261027_130000_none.pcap", &size, &why), -1);
    WT_ASSERT(!strcmp(why, "not_found"));
    close(dfd);
    web_pcapdir_destroy(&p);

    /* A directory that is not there says so, and holds nothing. */
    const char *gone[1] = { "/nonexistent/slothweb/pcap" };
    WT_EQ(web_pcapdir_init(&p, gone, 1), 0);
    web_pcapdir_scan(&p, 1000);
    WT_EQ(p.n, 0);
    const char *note = web_pcapdir_note(&p, nb, sizeof(nb));
    WT_ASSERT(note && !strcmp(note, "directory unreadable: ENOENT"));
    web_pcapdir_destroy(&p);
    WT_EQ(web_pcapdir_init(&p, NULL, 0), 0);
    WT_ASSERT(!strcmp(web_pcapdir_note(&p, nb, sizeof(nb)), "no --pcap-dir"));
    web_pcapdir_destroy(&p);
}

/* The sort: newest stamp first, read order within one stamp. A stamp
 * is whatever ll_of() admits (18 digits), so nothing may be computed
 * from it that can overflow. Seen red with the old key put back (the
 * stamp scaled by 65536 with the read index folded in): the 18-digit
 * line came back with another stamp in the plain build, and the
 * sanitized build stopped on the signed overflow. The tie order seen
 * red with the tie-break reversed (C before A). */
static void test_dir_order(void) {
    char dir[TEST_TMP_MAX];
    snprintf(dir, sizeof(dir), "%s/slothweb-evo-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(dir) != NULL);
    char sha[65], l[1024], path[TEST_TMP_MAX + 200];
    hex64((const uint8_t *)"x", 1, sha);
    snprintf(path, sizeof(path), "%s/%s", dir, MANI);
    FILE *f = fopen(path, "wb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    manifest_line(l, sizeof(l), 1, "alert_20261027_120000_a.pcap", 1, sha, "alert_pcap", NULL,
                  "PORT_SCAN", 1793102400);
    fputs(l, f);
    manifest_line(l, sizeof(l), 2, "alert_20261027_120000_b.pcap", 1, sha, "alert_pcap", NULL,
                  "PORT_SCAN", 999999999999999999LL);
    fputs(l, f);
    manifest_line(l, sizeof(l), 3, "alert_20261027_120000_c.pcap", 1, sha, "alert_pcap", NULL,
                  "PORT_SCAN", 1793102400);
    fputs(l, f);
    fclose(f);
    const char *dirs[1] = { dir };
    web_pcapdir_t p;
    WT_EQ(web_pcapdir_init(&p, dirs, 1), 0);
    web_pcapdir_scan(&p, 1000);
    WT_EQ(p.n, 3);
    if (p.n == 3) {
        WT_ASSERT(!strcmp(p.e[0].file, "alert_20261027_120000_b.pcap"));
        WT_EQ(p.e[0].written_at_epoch, 999999999999999999LL);
        WT_ASSERT(!strcmp(p.e[1].file, "alert_20261027_120000_a.pcap"));
        WT_ASSERT(!strcmp(p.e[2].file, "alert_20261027_120000_c.pcap"));
        WT_EQ(p.e[1].written_at_epoch, 1793102400);
    }
    web_pcapdir_destroy(&p);
    test_rm_tree(dir);
}

/* ── the routes ───────────────────────────────────────────────────── */

static char g_out[65536];

static int route(const web_health_t *h, const char *path, const char *query, int head,
                 web_resp_t *r) {
    web_req_t rq;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "%s", path);
    snprintf(rq.query, sizeof(rq.query), "%s", query);
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    rq.is_head = head;
    if (web_route(&rq, h, 1, g_out, sizeof(g_out), r) != 0) return -1;
    g_out[r->out_len < sizeof(g_out) ? r->out_len : sizeof(g_out) - 1] = '\0';
    return r->status;
}

static const char *body_of(const char *out) {
    const char *sep = strstr(out, "\r\n\r\n");
    return sep ? sep + 4 : "";
}

static void test_routes(void) {
    const char *dirs[1] = { g_dir };
    web_pcapdir_t *p = calloc(1, sizeof(*p));
    web_live_t *l = calloc(1, sizeof(*l));
    WT_ASSERT(p && l);
    if (!p || !l) { free(p); free(l); return; }
    WT_EQ(web_pcapdir_init(p, dirs, 1), 0);
    web_live_init(l, "unix:/t/s.sock");
    web_live_sock_connected(l, 0);
    web_feed_t f;
    memset(&f, 0, sizeof(f));
    web_feed_reset(&f);
    /* A CRIT port scan with its pcap, as src/jsonl.c writes the
     * lifecycle record (incident_id 16 hex, pcap_path the full path). */
    char rec[1024];
    snprintf(rec, sizeof(rec),
             "{\"type\":\"alert.create\",\"ts\":1793102400,\"incident_id\":\"" INC_A "\","
             "\"ty\":0,\"sev\":2,\"title\":\"Port scan\",\"key\":\"scan:10.0.0.5\","
             "\"match_ip\":\"10.0.0.5\",\"first_detected\":1793102390,"
             "\"pcap_path\":\"%s/" NAME_C "\"}\n", g_dir);
    web_feed_bytes(&f, l, rec, strlen(rec), 1000);
    /* And a WARN one with neither. */
    const char rec2[] = "{\"type\":\"alert.create\",\"ts\":1793102400,\"incident_id\":"
                        "\"fedcba9876543210\",\"ty\":1,\"sev\":1,\"title\":\"Deauth\","
                        "\"key\":\"deauth:x\"}\n";
    web_feed_bytes(&f, l, rec2, strlen(rec2), 1000);
    char id[48] = "", id2[48] = "";
    for (int i = 0; i < l->ninc; i++) {
        if (l->inc[i].type == 0) snprintf(id, sizeof(id), "s%s", l->inc[i].hid);
        if (l->inc[i].type == 1) snprintf(id2, sizeof(id2), "s%s", l->inc[i].hid);
    }
    WT_ASSERT(id[0] && id2[0]);
    web_m4_t m;
    memset(&m, 0, sizeof(m));
    m.pcap = p;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = 1793103000;
    h.live = l;
    h.m4 = &m;
    web_resp_t r;
    char q[128];

    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(route(&h, "/api/alert", q, 0, &r), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "\"captures\":[{\"n\":0,\"file\":\"" NAME_A "\",\"matched_by\":\"incident\"");
    WT_HAS(b, "{\"n\":1,\"file\":\"" NAME_C "\",\"matched_by\":\"record\",\"withheld\":null,"
              "\"unreadable\":null,\"manifest_lines\":0,\"conflict\":null,\"sink\":null");
    WT_HAS(b, "\"captures_note\":null");
    WT_HAS(b, "\"why_no_capture\":null");
    WT_HAS(b, "\"assessment\":");
    /* The real docs/wiki/alert-assessments/PORT_SCAN.md, built in: its
     * count semantics and noise verdict shown as written, next to the
     * engine's own caveat on the two counters. */
    WT_HAS(b, "\"assessment\":{\"path\":\"docs/wiki/alert-assessments/PORT_SCAN.md\"");
    WT_HAS(b, "[\"count_semantics\",");
    WT_HAS(b, "[\"noise_verdict\",");
    WT_HAS(b, "[\"count_semantics (assessment)\",");
    WT_HAS(b, "[\"count (evaluations)\",");
    WT_HAS(b, "observations follows evaluations");
    WT_HAS(b, "\"thresholds\":[[\"tuning\",");
    /* Never sloth's incident_id, the manifest's session or the
     * directory. Seen red with "incident_id" emitted per capture, and
     * with the directory's path emitted. The session is never parsed
     * out of a line (web_pcapdir_parse_line() keeps no field for it),
     * so its absence here is by construction, not a mutation seen. */
    WT_LACKS(b, INC_A);
    WT_LACKS(b, "00ff00ff00ff00ff");
    WT_LACKS(b, g_dir);

    /* The frames, hash-checked. */
    snprintf(q, sizeof(q), "id=%s&n=0", id);
    WT_EQ(route(&h, "/api/pcap/frames", q, 0, &r), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"hash\":{\"status\":\"verified\",\"says\":\"hash verified\"");
    WT_HAS(b, "\"frames_total\":2");
    WT_HAS(b, "\"kind\":\"TLS\"");
    WT_HAS(b, "\"cut\":\"truncated at snaplen 64\"");
    WT_LACKS(b, g_dir);
    snprintf(q, sizeof(q), "id=%s&n=1&offset=1", id);
    WT_EQ(route(&h, "/api/pcap/frames", q, 0, &r), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"says\":\"no manifest entry\"");
    WT_HAS(b, "\"shown\":1");
    /* n names only the alert's own files; a name is never taken. */
    snprintf(q, sizeof(q), "id=%s&n=2", id);
    WT_EQ(route(&h, "/api/pcap/frames", q, 0, &r), 404);
    WT_HAS(body_of(g_out), "\"error\":\"no_such_capture\"");
    snprintf(q, sizeof(q), "id=%s&n=0&file=eapol.22000", id);
    WT_EQ(route(&h, "/api/pcap/frames", q, 0, &r), 400);
    snprintf(q, sizeof(q), "id=%s&n=x", id);
    WT_EQ(route(&h, "/api/pcap/frames", q, 0, &r), 400);
    WT_EQ(route(&h, "/api/pcap/frames", "id=s0zz&n=0", 0, &r), 404);
    snprintf(q, sizeof(q), "id=%s&n=0", id);
    WT_EQ(route(&h, "/api/pcap/frames", q, 1, &r), 405);
    WT_EQ(route(&h, "/api/pcap", q, 1, &r), 405);

    /* The download: the bytes, an attachment, owned by the response. */
    WT_EQ(route(&h, "/api/pcap", q, 0, &r), 200);
    WT_HAS(g_out, "Content-Type: application/vnd.tcpdump.pcap\r\n");
    WT_HAS(g_out, "Content-Disposition: attachment; filename=\"" NAME_A "\"\r\n");
    WT_HAS(g_out, "X-Content-Type-Options: nosniff\r\n");
    /* The bytes served are hashed themselves, not vouched for by the
     * frames read before them. The mismatch and no_manifest_entry
     * answers below seen red with the download's check replaced by a
     * constant "verified" (this first one cannot tell, by design). */
    WT_HAS(g_out, "X-Sloth-SHA256: verified\r\n");
    WT_ASSERT(r.body_owned != NULL && r.body == r.body_owned);
    WT_EQ(r.body_len, g_pa.n);
    WT_ASSERT(r.body_owned && !memcmp(r.body_owned, g_pa.b, g_pa.n));
    free(r.body_owned);

    /* A file changed after sloth hashed it. */
    char path[TEST_TMP_MAX + 200];
    snprintf(path, sizeof(path), "%s/%s", g_dir, NAME_A);
    FILE *fp = fopen(path, "r+b");
    WT_ASSERT(fp != NULL);
    if (fp) { fseek(fp, 40, SEEK_SET); fputc(0x55, fp); fclose(fp); }
    WT_EQ(route(&h, "/api/pcap/frames", q, 0, &r), 200);
    WT_HAS(body_of(g_out), "\"says\":\"HASH MISMATCH\"");
    /* Downloaded after the page said "verified": the download says not. */
    WT_EQ(route(&h, "/api/pcap", q, 0, &r), 200);
    WT_HAS(g_out, "X-Sloth-SHA256: mismatch\r\n");
    free(r.body_owned);
    /* A pcapng file where a pcap was. */
    static const uint8_t ng[28] = { 0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a };
    WT_EQ(write_file(NAME_C, ng, sizeof(ng)), 0);
    snprintf(q, sizeof(q), "id=%s&n=1", id);
    WT_EQ(route(&h, "/api/pcap/frames", q, 0, &r), 415);
    WT_HAS(body_of(g_out), "\"error\":\"pcapng_not_supported\"");
    WT_HAS(body_of(g_out), "editcap -F pcap");
    WT_EQ(route(&h, "/api/pcap", q, 0, &r), 200);
    WT_HAS(g_out, "X-Sloth-SHA256: no_manifest_entry\r\n");
    free(r.body_owned);

    /* No capture: said why, in sloth's terms. */
    snprintf(q, sizeof(q), "id=%s", id2);
    WT_EQ(route(&h, "/api/alert", q, 0, &r), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"captures\":[]");
    WT_HAS(b, "\"why_no_capture\":\"this rule names no target address");
    m.pcap = NULL;
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(route(&h, "/api/alert", q, 0, &r), 200);
    WT_HAS(body_of(g_out), "\"captures_note\":\"no --pcap-dir\"");
    WT_HAS(body_of(g_out), "\"why_no_capture\":\"slothweb was not given --pcap-dir");
    snprintf(q, sizeof(q), "id=%s&n=0", id);
    WT_EQ(route(&h, "/api/pcap", q, 0, &r), 404);
    WT_HAS(body_of(g_out), "\"error\":\"no_pcap_dir\"");

    web_live_destroy(l);
    web_pcapdir_destroy(p);
    free(l);
    free(p);
    test_rm_tree(g_dir);
}

/* ── what the list holds back, and lines that disagree ────────────── */

#define INC_W  "00112233aabbccdd"
#define NAME_W "alert_20261027_140000_Port_scan.pcap"       /* genuine + forged line */
#define NAME_F "alert_20261027_140500_Port_scan.pcap"       /* forged line only */
#define NAME_E INC_W "-7-FRAG_EAPOL_RELAY.pcap"           /* an evidence pcap */
#define NAME_L "alert_20261027_141000_link.pcap"            /* a symlink */
#define NAME_Q "alert_20261027_141500_fifo.pcap"            /* a FIFO */

static char g_wdir[TEST_TMP_MAX];
static pf_t g_pe;

static int put_in(const char *dir, const char *name, const void *b, size_t n, int append) {
    char path[TEST_TMP_MAX + 200];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, append ? "ab" : "wb");
    if (!f) return -1;
    size_t w = fwrite(b, 1, n, f);
    return fclose(f) == 0 && w == n ? 0 : -1;
}

/* W listed twice: sloth's line, then a later-stamped one with another
 * hash, as anyone who can write the directory could append. F listed
 * only by such a line. E an evidence pcap of radiotap frames. L and Q
 * a symlink and a FIFO under names the gate passes, each with a line.
 * Every one is the incident's. */
static int make_wdir(void) {
    snprintf(g_wdir, sizeof(g_wdir), "%s/slothweb-evw-XXXXXX", test_tmpdir());
    if (!mkdtemp(g_wdir)) return -1;
    pf_hdr(&g_pe, 0, 0, 65535, 127);
    pf_rec(&g_pe, 1793102400, 0, RT_DEAUTH, sizeof(RT_DEAUTH), sizeof(RT_DEAUTH));
    char sha[65], esha[65], bad[65], l[1024];
    hex64(g_pa.b, g_pa.n, sha);
    hex64(g_pe.b, g_pe.n, esha);
    hex64((const uint8_t *)"forged", 6, bad);
    if (put_in(g_wdir, NAME_W, g_pa.b, g_pa.n, 0) || put_in(g_wdir, NAME_F, g_pa.b, g_pa.n, 0) ||
        put_in(g_wdir, NAME_E, g_pe.b, g_pe.n, 0))
        return -1;
    char path[TEST_TMP_MAX + 200], tgt[TEST_TMP_MAX + 200];
    snprintf(path, sizeof(path), "%s/%s", g_wdir, NAME_L);
    snprintf(tgt, sizeof(tgt), "%s/%s", g_wdir, NAME_W);
    if (symlink(tgt, path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/%s", g_wdir, NAME_Q);
    if (mkfifo(path, 0600) != 0) return -1;
    struct { const char *file, *sha, *sink; long long at; size_t size; } L[] = {
        { NAME_W, sha,  "alert_pcap",    1793102400, g_pa.n },
        { NAME_W, bad,  "alert_pcap",    999999999999999999LL, g_pa.n },
        { NAME_F, bad,  "alert_pcap",    1793102390, g_pa.n },
        { NAME_E, esha, "evidence_pcap", 1793102380, g_pe.n },
        { NAME_L, sha,  "alert_pcap",    1793102370, g_pa.n },
        { NAME_Q, sha,  "alert_pcap",    1793102360, g_pa.n },
    };
    for (size_t i = 0; i < sizeof(L) / sizeof(L[0]); i++) {
        int n = manifest_line(l, sizeof(l), (int)i + 1, L[i].file, L[i].size, L[i].sha, L[i].sink,
                              INC_W, "PORT_SCAN", L[i].at);
        if (put_in(g_wdir, MANI, l, (size_t)n, 1)) return -1;
    }
    return 0;
}

static const web_pcap_hit_t *hit_of(const web_pcap_hit_t *h, int n, const char *file) {
    for (int i = 0; i < n; i++)
        if (!strcmp(h[i].file, file)) return &h[i];
    return NULL;
}

static unsigned char *read_hit(web_pcapdir_t *p, const web_pcap_hit_t *h, long long *size) {
    int err = 0;
    int dfd = web_pcapdir_open_dir(p, h->dir, &err);
    if (dfd < 0) return NULL;
    const char *why = NULL;
    int fd = web_pcapdir_open_file(dfd, h->file, size, &why);
    close(dfd);
    if (fd < 0) return NULL;
    unsigned char *b = web_pcapdir_slurp(fd, *size);
    close(fd);
    return b;
}

/* Each absence below was seen red under its own mutation: the withheld
 * mark with annotate()'s evidence test removed; the not-regular mark
 * with its fstatat() test removed; "verified" for W with
 * web_pcapdir_verify_hit() checking only the hit's own (newest) line. */
static void test_withheld_and_lines(void) {
    WT_EQ(make_wdir(), 0);
    const char *dirs[1] = { g_wdir };
    web_pcapdir_t p;
    WT_EQ(web_pcapdir_init(&p, dirs, 1), 0);
    web_pcap_hit_t h[WEB_PCAPDIR_HITS];
    int n = web_pcapdir_for_alert(&p, 1000, INC_W, "", "PORT_SCAN", 0, 0, h, WEB_PCAPDIR_HITS);
    WT_EQ(n, 5);
    const web_pcap_hit_t *w = hit_of(h, n, NAME_W), *f = hit_of(h, n, NAME_F),
                         *e = hit_of(h, n, NAME_E), *sl = hit_of(h, n, NAME_L),
                         *q = hit_of(h, n, NAME_Q);
    WT_ASSERT(w && f && e && sl && q);
    if (!(w && f && e && sl && q)) { web_pcapdir_destroy(&p); return; }
    /* Withheld by default, listed all the same; served when asked. */
    WT_ASSERT(e->withheld && !strcmp(e->withheld, WEB_PCAP_WITHHELD));
    WT_ASSERT(w->withheld == NULL && f->withheld == NULL);
    /* Not a regular file: said in the list, not only on opening. */
    WT_ASSERT(sl->unreadable && !strcmp(sl->unreadable, WEB_PCAP_NOT_REG));
    WT_ASSERT(q->unreadable && !strcmp(q->unreadable, WEB_PCAP_NOT_REG));
    WT_ASSERT(w->unreadable == NULL && e->unreadable == NULL);
    /* Two lines for W that disagree; one for F. */
    WT_EQ(w->lines, 2);
    WT_EQ(w->conflict, 1);
    WT_EQ(f->lines, 1);
    WT_EQ(f->conflict, 0);
    /* The forged line is W's newest, so it is the hit's own line, and
     * the genuine one still vouches for the bytes. */
    WT_EQ(w->e->written_at_epoch, 999999999999999999LL);
    long long size = 0;
    unsigned char *b = read_hit(&p, w, &size);
    WT_ASSERT(b != NULL);
    if (b) {
        const web_pcap_entry_t *me = NULL;
        WT_ASSERT(!strcmp(web_pcapdir_verify_hit(&p, b, (size_t)size, w, &me), "verified"));
        WT_ASSERT(me && me->written_at_epoch == 1793102400);
        b[30] ^= 1;
        WT_ASSERT(!strcmp(web_pcapdir_verify_hit(&p, b, (size_t)size, w, &me), "MISMATCH"));
        WT_ASSERT(me == w->e);
        free(b);
    }
    b = read_hit(&p, f, &size);
    WT_ASSERT(b != NULL);
    if (b) {
        WT_ASSERT(!strcmp(web_pcapdir_verify_hit(&p, b, (size_t)size, f, NULL), "MISMATCH"));
        free(b);
    }
    p.serve_evidence = 1;
    n = web_pcapdir_for_alert(&p, 1000, INC_W, "", "PORT_SCAN", 0, 0, h, WEB_PCAPDIR_HITS);
    e = hit_of(h, n, NAME_E);
    WT_ASSERT(e && e->withheld == NULL);
    web_pcapdir_destroy(&p);
}

/* The same through the routes: a withheld evidence pcap is listed with
 * its reason and neither decoded nor downloaded. The 403s seen red with
 * open_capture()'s withheld check removed (frames and bytes served). */
static void test_routes_withheld(void) {
    const char *dirs[1] = { g_wdir };
    web_pcapdir_t *p = calloc(1, sizeof(*p));
    web_live_t *l = calloc(1, sizeof(*l));
    WT_ASSERT(p && l);
    if (!p || !l) { free(p); free(l); return; }
    WT_EQ(web_pcapdir_init(p, dirs, 1), 0);
    web_live_init(l, "unix:/t/s.sock");
    web_live_sock_connected(l, 0);
    web_feed_t fd;
    memset(&fd, 0, sizeof(fd));
    web_feed_reset(&fd);
    const char rec[] = "{\"type\":\"alert.create\",\"ts\":1793102400,\"incident_id\":\"" INC_W "\","
                       "\"ty\":0,\"sev\":2,\"title\":\"Port scan\",\"key\":\"scan:10.0.0.9\","
                       "\"match_ip\":\"10.0.0.9\",\"first_detected\":1793102390}\n";
    web_feed_bytes(&fd, l, rec, strlen(rec), 1000);
    char id[48] = "";
    for (int i = 0; i < l->ninc; i++)
        if (l->inc[i].type == 0) snprintf(id, sizeof(id), "s%s", l->inc[i].hid);
    WT_ASSERT(id[0]);
    web_m4_t m;
    memset(&m, 0, sizeof(m));
    m.pcap = p;
    web_health_t hh;
    memset(&hh, 0, sizeof(hh));
    hh.wall_s = 1793103000;
    hh.live = l;
    hh.m4 = &m;
    web_resp_t r;
    char q[128];

    /* Newest first: W (by its forged stamp), F, E, L, Q. */
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(route(&hh, "/api/alert", q, 0, &r), 200);
    const char *b = body_of(g_out);
    WT_HAS(b, "{\"n\":0,\"file\":\"" NAME_W "\",\"matched_by\":\"incident\",\"withheld\":null,"
              "\"unreadable\":null,\"manifest_lines\":2,"
              "\"conflict\":\"conflicting manifest lines (2)\"");
    WT_HAS(b, "{\"n\":2,\"file\":\"" NAME_E "\",\"matched_by\":\"incident\","
              "\"withheld\":\"" WEB_PCAP_WITHHELD "\",\"unreadable\":null");
    WT_HAS(b, "{\"n\":3,\"file\":\"" NAME_L "\",\"matched_by\":\"incident\",\"withheld\":null,"
              "\"unreadable\":\"" WEB_PCAP_NOT_REG "\"");
    WT_HAS(b, "{\"n\":4,\"file\":\"" NAME_Q "\",\"matched_by\":\"incident\",\"withheld\":null,"
              "\"unreadable\":\"" WEB_PCAP_NOT_REG "\"");

    /* W: verified by sloth's line, the forged newer one notwithstanding,
     * with the disagreement said. Seen red with the frames and download
     * routes checking the hit's own line only. */
    char sha[65];
    hex64(g_pa.b, g_pa.n, sha);
    snprintf(q, sizeof(q), "id=%s&n=0", id);
    WT_EQ(route(&hh, "/api/pcap/frames", q, 0, &r), 200);
    b = body_of(g_out);
    WT_HAS(b, "\"hash\":{\"status\":\"verified\",\"says\":\"hash verified\"");
    WT_HAS(b, sha);
    WT_HAS(b, "\"manifest_lines\":2,\"conflict\":\"conflicting manifest lines (2)\"");
    WT_EQ(route(&hh, "/api/pcap", q, 0, &r), 200);
    WT_HAS(g_out, "X-Sloth-SHA256: verified\r\n");
    free(r.body_owned);
    /* F: only a line that does not match. */
    snprintf(q, sizeof(q), "id=%s&n=1", id);
    WT_EQ(route(&hh, "/api/pcap/frames", q, 0, &r), 200);
    WT_HAS(body_of(g_out), "\"says\":\"HASH MISMATCH\"");
    WT_HAS(body_of(g_out), "\"conflict\":null");

    /* E: withheld, from both routes, no frame and no byte. */
    snprintf(q, sizeof(q), "id=%s&n=2", id);
    WT_EQ(route(&hh, "/api/pcap/frames", q, 0, &r), 403);
    WT_HAS(body_of(g_out), "\"error\":\"withheld_evidence_pcap\"");
    WT_LACKS(body_of(g_out), "frames_total");
    r.body_owned = NULL;
    WT_EQ(route(&hh, "/api/pcap", q, 0, &r), 403);
    WT_HAS(body_of(g_out), "\"error\":\"withheld_evidence_pcap\"");
    WT_ASSERT(r.body_owned == NULL);
    WT_LACKS(g_out, "application/vnd.tcpdump.pcap");
    free(r.body_owned);
    /* L, Q: listed as unreadable, refused the same way. */
    snprintf(q, sizeof(q), "id=%s&n=3", id);
    WT_EQ(route(&hh, "/api/pcap/frames", q, 0, &r), 403);
    WT_HAS(body_of(g_out), "\"error\":\"not_regular\"");
    snprintf(q, sizeof(q), "id=%s&n=4", id);
    WT_EQ(route(&hh, "/api/pcap", q, 0, &r), 403);
    WT_HAS(body_of(g_out), "\"error\":\"not_regular\"");

    /* --web-serve-evidence-pcap: the same file decoded and served. */
    p->serve_evidence = 1;
    snprintf(q, sizeof(q), "id=%s", id);
    WT_EQ(route(&hh, "/api/alert", q, 0, &r), 200);
    WT_HAS(body_of(g_out), "{\"n\":2,\"file\":\"" NAME_E "\",\"matched_by\":\"incident\","
                           "\"withheld\":null");
    snprintf(q, sizeof(q), "id=%s&n=2", id);
    WT_EQ(route(&hh, "/api/pcap/frames", q, 0, &r), 200);
    WT_HAS(body_of(g_out), "\"hash\":{\"status\":\"verified\"");
    WT_HAS(body_of(g_out), "\"frames_total\":1");
    WT_EQ(route(&hh, "/api/pcap", q, 0, &r), 200);
    WT_EQ(r.body_len, g_pe.n);
    free(r.body_owned);

    web_live_destroy(l);
    web_pcapdir_destroy(p);
    free(l);
    free(p);
    test_rm_tree(g_wdir);
}

/* ── the assessment generator ─────────────────────────────────────── */

#ifndef WEB_ASMGEN
#define WEB_ASMGEN "build/web/alertasm"
#endif

static int gen(const char *dir, const char *out) {
    char cmd[3 * TEST_TMP_MAX];
    snprintf(cmd, sizeof(cmd), "%s %s include/sloth_alerts.def %s 2>/dev/null", WEB_ASMGEN, out, dir);
    int rc = system(cmd);
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

static int put_doc(const char *dir, const char *name, const char *text) {
    char path[TEST_TMP_MAX + 200];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(text, f);
    return fclose(f);
}

static int remove_doc(const char *dir, const char *name) {
    char path[TEST_TMP_MAX + 200];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    return unlink(path);
}

static const char DOC[] =
    "**Summary**: how far the rule can be trusted.\n"
    "**Sources**: IEEE Std 802.11-2020\n"
    "**Last updated**: 2026-10-27\n"
    "\n---\nfalse_positive_risk: low\nthreshold: 30 frames\nwindow: 10 s\n---\n\n"
    "# DEAUTH_FLOOD\n\n"
    "## What the rule checks\n\nIt counts **deauthentication** frames [1], `n [9]` kept.\n\n"
    "## Bibliography\n\n1. IEEE Std 802.11-2020, 9.4.1.7\n\n"
    "## Related pages\n\n- alerts\n";

static void test_assessment_generator(void) {
    char dir[TEST_TMP_MAX], out[TEST_TMP_MAX + 32];
    snprintf(dir, sizeof(dir), "%s/slothweb-asm-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(dir) != NULL);
    snprintf(out, sizeof(out), "%s/t.c", dir);
    char sub[TEST_TMP_MAX + 16];
    snprintf(sub, sizeof(sub), "%s/docs", dir);
    WT_EQ(mkdir(sub, 0700), 0);
    /* No documents: an empty table, the build goes on. */
    WT_EQ(gen(sub, out), 0);
    WT_EQ(put_doc(sub, "DEAUTH_FLOOD.md", DOC), 0);
    WT_EQ(gen(sub, out), 0);
    char *t = NULL;
    FILE *f = fopen(out, "r");
    if (f) {
        t = calloc(1, 65536);
        if (t) { size_t n = fread(t, 1, 65535, f); t[n] = '\0'; }
        fclose(f);
    }
    WT_ASSERT(t != NULL);
    WT_HAS(t, "\"threshold\", \"window\"");
    WT_HAS(t, "\"30 frames\", \"10 s\"");
    WT_HAS(t, "{ \"What the rule checks\", \"It counts deauthentication frames [1], `n [9]` kept.\" }");
    WT_HAS(t, "\"[1] IEEE Std 802.11-2020, 9.4.1.7\"");   /* "1. " kept as [1] */
    WT_HAS(t, "\"2026-10-27\"");
    WT_LACKS(t, "Related pages");
    WT_HAS(t, "-1, 0, -1");                 /* DEAUTH_FLOOD is the .def's second row */
    free(t);
    /* A dangling [2], and a stem that is no alert type: the build
     * stops. Seen red: each passed (exit 0) with check_cites() and the
     * type_of() check removed from the generator in turn. */
    WT_EQ(put_doc(sub, "DEAUTH_FLOOD.md",
                  "# x\n\n## The attack\n\nSee [2].\n\n## Bibliography\n\n1. one\n"), 0);
    WT_EQ(gen(sub, out), 1);
    WT_EQ(put_doc(sub, "DEAUTH_FLOOD.md", DOC), 0);
    WT_EQ(put_doc(sub, "DEAUTH_FLOD.md", DOC), 0);
    WT_EQ(gen(sub, out), 1);
    WT_EQ(remove_doc(sub, "DEAUTH_FLOD.md"), 0);

    /* Gapped list numbers are the entries' own: [7] is the item written
     * "7. ", and [5] is no entry. Seen red: with the "[n] " prefix
     * dropped from a numbered item, the [7] document failed (exit 1). */
    WT_EQ(put_doc(sub, "DEAUTH_FLOOD.md",
                  "# x\n\n## The attack\n\nSee [7].\n\n## Bibliography\n\n1. one\n7. seven\n"), 0);
    WT_EQ(gen(sub, out), 0);
    WT_EQ(put_doc(sub, "DEAUTH_FLOOD.md",
                  "# x\n\n## The attack\n\nSee [5].\n\n## Bibliography\n\n1. one\n7. seven\n"), 0);
    WT_EQ(gen(sub, out), 1);
    /* The verification notes name the sources' own reference numbers
     * (CSA_ABUSE.md's "[70]"). Seen red: with that section checked,
     * exit 1. */
    WT_EQ(put_doc(sub, "DEAUTH_FLOOD.md",
                  "# x\n\n## The attack\n\nSee [1].\n\n## Bibliography\n\n1. one\n\n"
                  "## Verification notes\n\nThe paper's own [70] is theirs.\n"), 0);
    WT_EQ(gen(sub, out), 0);
    /* Prose among the entries is the Bibliography's note, not the words
     * of the source above it: an unindented line under an entry
     * (MY_NETWORK_RECON.md's "(5. and 6. intentionally unused ...)")
     * and a paragraph after a blank line. An indented line straight
     * under an entry is still its continuation. The two absences seen
     * red with every unnumbered line taken as a continuation again. */
    WT_EQ(put_doc(sub, "DEAUTH_FLOOD.md",
                  "# x\n\n## The attack\n\nSee [1] and [3].\n\n## Bibliography\n\n"
                  "1. one\n   still one\n(2. intentionally unused)\n3. three\n\n"
                  "No public advisory was found.\n"), 0);
    WT_EQ(gen(sub, out), 0);
    f = fopen(out, "r");
    t = NULL;
    if (f) {
        t = calloc(1, 65536);
        if (t) { size_t n = fread(t, 1, 65535, f); t[n] = '\0'; }
        fclose(f);
    }
    WT_ASSERT(t != NULL);
    if (t) {
        WT_HAS(t, "\"[1] one still one\"");
        WT_HAS(t, "\"[3] three\"");
        WT_HAS(t, "\"(2. intentionally unused)\\012\\012No public advisory was found.\"");
        WT_LACKS(t, "still one (2.");
        WT_LACKS(t, "[3] three No public");
        free(t);
    }
    test_rm_tree(dir);

    /* The real MY_NETWORK_RECON.md: its note kept apart from [4]. */
    int recon = 0;
    for (int i = 0; i < web_asm_n; i++) {
        if (strcmp(web_asm[i].name, "MY_NETWORK_RECON")) continue;
        recon = 1;
        WT_ASSERT(!strncmp(web_asm[i].bib_note, "(5. and 6. intentionally unused", 31));
        for (int k = 0; k < web_asm[i].nbib; k++)
            WT_ASSERT(strstr(web_asm[i].bib[k], "intentionally unused") == NULL);
    }
    WT_ASSERT(recon);

    /* The built-in table is docs/wiki/alert-assessments/ as written:
     * every entry with its count semantics, noise verdict, sections and
     * a bibliography (tests/test_alert_assessments.c owns which types
     * are pending; a missing file is "no assessment yet"). */
    WT_ASSERT(web_asm_n > 0);
    for (int i = 0; i < web_asm_n; i++) {
        int cs = 0, nv = 0;
        for (int k = 0; k < web_asm[i].nfm; k++) {
            if (!strcmp(web_asm[i].fm_k[k], "count_semantics")) cs = 1;
            if (!strcmp(web_asm[i].fm_k[k], "noise_verdict")) nv = 1;
        }
        WT_ASSERT(cs && nv);
        WT_ASSERT(web_asm[i].nsec >= 4);
        WT_ASSERT(web_asm[i].nbib >= 1);
    }

    /* A document past what the answer has left is named whole, not
     * cut: PORT_SCAN (type 0) in 64 KiB, then in 16 KiB. Seen red with
     * the roll-back removed (the 16 KiB answer overflowed, no
     * too_large and no closing brace). */
    {
        static char jb[65536];
        web_jw_t w;
        web_alert_tgt_t t;
        memset(&t, 0, sizeof(t));
        t.type = 0;
        snprintf(t.rule, sizeof(t.rule), "PORT_SCAN");
        web_jw_init(&w, jb, sizeof(jb));
        web_evidence_alert_json(&w, NULL, &t);
        WT_ASSERT(!w.overflow);
        WT_HAS(jb, "\"bibliography\":[\"[1] ");
        WT_LACKS(jb, "\"too_large\"");
        web_jw_init(&w, jb, 16384);
        web_evidence_alert_json(&w, NULL, &t);
        WT_ASSERT(!w.overflow);
        WT_HAS(jb, "\"assessment\":{\"path\":\"docs/wiki/alert-assessments/PORT_SCAN.md\","
                   "\"too_large\":true}");
    }

    /* The built-in table answers by type, and nothing past the .def. */
    WT_ASSERT(web_asm_get(-1) == NULL);
    WT_ASSERT(web_asm_get(web_asm_ntypes) == NULL);
    for (int i = 0; i < web_asm_n; i++) {
        WT_ASSERT(web_asm[i].name != NULL);
        for (int s = 0; s < web_asm[i].nsec; s++) WT_ASSERT(web_asm[i].sec[s].text != NULL);
    }
}

/* ── the page ─────────────────────────────────────────────────────── */

static void test_page_hooks(void) {
    const char *p = (const char *)web_page;
    /* The module, its two containers, and one hook per view in app.js. */
    WT_HAS(p, "window.SlothEvidence = ");
    WT_HAS(p, "id=\"ev-alert\"");
    WT_HAS(p, "if (window.SlothEvidence) window.SlothEvidence.alert(j);");
    WT_HAS(p, "if (window.SlothEvidence) window.SlothEvidence.drawer(box);");
    /* The drawer's alert list found by app.js's mark on that list, not
     * by its label's wording: rewording the label cannot silently drop
     * the tap mark, the 44 px rows and the drawer closing. The absence
     * seen red with the label-text search put back in drawer(). */
    WT_HAS(p, "var alw = itemList(box, \"alerts naming it\", j.alerts, ");
    WT_HAS(p, "alw.dataset.ev = \"drawer-alerts\";\n");
    WT_HAS(p, "var wrap = box.querySelector(\"[data-ev=\\\"drawer-alerts\\\"]\");");
    WT_LACKS(p, "indexOf(\"alerts naming it\")");
    /* The frame index is a data table like the page's others: through
     * DataTable, its tools and its kept filter. The absence seen red
     * with the old <details> rows put back in frameRow(). */
    WT_HAS(p, "window.SlothTables = { make: DataTable };");
    WT_HAS(p, "S.t = window.SlothTables.make({ id: \"evframes\", ");
    WT_HAS(p, "head: $(\"ev-frames-head\"), reset: $(\"ev-frames-tools\"), redraw: drawFrames, cols: COLS });");
    WT_HAS(p, "var r = el(\"div\", \"evfrow dt-row\");");
    WT_HAS(p, "id=\"ev-frames-tools\"");
    WT_LACKS(p, "el(\"details\", \"ev-frame\")");
    /* A withheld or unreadable capture is listed with its reason and
     * never opened: no click, no key, and open() refuses it. */
    WT_HAS(p, "var shut = c.withheld || c.unreadable;");
    WT_HAS(p, "if (!c || c.withheld || c.unreadable) return;");
    WT_HAS(p, "if (first >= 0) open(first, 0);");
    /* The one way the page starts a download: the same origin's
     * /api/pcap, every value encoded, no .href sink. */
    WT_HAS(p, "window.location.assign(\"/api/pcap?id=\" + encodeURIComponent(");
    WT_HAS(p, "getJSON(\"/api/pcap/frames?id=\" + encodeURIComponent(");
    /* The ev-alert section is the alert page's last. */
    const char *ev = strstr(p, "id=\"ev-alert\"");
    const char *dev = strstr(p, "id=\"ad-device\"");
    const char *rec = strstr(p, "id=\"v-records\"");
    WT_ASSERT(ev && dev && rec && dev < ev && ev < rec);
}

void run_evidence_tests(void) {
    WT_RUN(test_header_forms);
    WT_RUN(test_record_walk);
    WT_RUN(test_decode_ip_tiers);
    WT_RUN(test_decode_dot11);
    WT_RUN(test_hexdump);
    WT_RUN(test_frames_page);
    WT_RUN(test_name_gate);
    WT_RUN(test_manifest_line);
    WT_RUN(test_dir_index);
    WT_RUN(test_dir_order);
    WT_RUN(test_routes);
    WT_RUN(test_withheld_and_lines);
    WT_RUN(test_routes_withheld);
    WT_RUN(test_assessment_generator);
    WT_RUN(test_page_hooks);
}
