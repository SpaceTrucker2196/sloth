#ifndef SLOTH_FRAME_BUILD_H
#define SLOTH_FRAME_BUILD_H

#include <stdint.h>
#include <string.h>

/* Spec-derived 802.11 frame builder for tests — issue #122.
 *
 * Every field is appended in clause order and every optional field is
 * appended because the TEST SAID SO, never because the builder worked
 * it out from the flags. `fb_dot11_hdr()` emits HT Control when
 * `htc_present` is set and not otherwise, whatever the Order bit says;
 * a test that wants the StrictlyOrdered case sets Order and leaves
 * `htc_present` clear. This is the difference between a builder that
 * checks the parser and one that is a copy of it: the old
 * `tests/test_dot11_data.c :: build_data` computed the header length
 * with the production formula, so it agreed with the production bug
 * for as long as the bug lived there.
 *
 * Conventions:
 *   - HT Control bytes are DE AD BE EF. Read as the start of an IE list
 *     they look like tag 0xDE claiming length 0xAD, which overruns and
 *     ends the walk, so a parser that forgot the field extracts nothing
 *     rather than something plausible.
 *   - `fb_ciphertext()` never produces bytes that read as a plaintext
 *     category: its first three octets are never AA AA 03.
 *   - Nothing here reads a real site identifier. Callers choose MACs
 *     and SSIDs; the ones in tests are locally-administered or
 *     documentation values.
 *
 * All functions are bounds-checked against the buffer the test gave:
 * an overrun sets `overflow` and drops the bytes instead of writing
 * past the array, and the test asserts `fb_ok()`. */

typedef struct {
    uint8_t *buf;
    int      cap;
    int      len;
    int      overflow;
} fb_t;

static inline void fb_init(fb_t *b, uint8_t *buf, int cap) {
    b->buf = buf; b->cap = cap; b->len = 0; b->overflow = 0;
    if (buf && cap > 0) memset(buf, 0, (size_t)cap);
}

static inline int fb_ok(const fb_t *b) { return !b->overflow; }

static inline void fb_u8(fb_t *b, uint8_t v) {
    if (b->len + 1 > b->cap) { b->overflow = 1; return; }
    b->buf[b->len++] = v;
}

static inline void fb_le16(fb_t *b, uint16_t v) {
    fb_u8(b, (uint8_t)(v & 0xff));
    fb_u8(b, (uint8_t)(v >> 8));
}

static inline void fb_be16(fb_t *b, uint16_t v) {
    fb_u8(b, (uint8_t)(v >> 8));
    fb_u8(b, (uint8_t)(v & 0xff));
}

static inline void fb_le64(fb_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) fb_u8(b, (uint8_t)(v >> (8 * i)));
}

static inline void fb_bytes(fb_t *b, const void *src, int n) {
    const uint8_t *s = (const uint8_t *)src;
    for (int i = 0; i < n; i++) fb_u8(b, s[i]);
}

static inline void fb_mac(fb_t *b, const uint8_t m[6]) { fb_bytes(b, m, 6); }

/* ── MAC header (IEEE 802.11-2020 §9.2.4) ─────────────────────────── */

/* Frame Control flags, byte 1 (§9.2.4.1.1 Figure 9-2). */
#define FB_TODS       0x01
#define FB_FROMDS     0x02
#define FB_MOREFRAG   0x04
#define FB_RETRY      0x08
#define FB_PWRMGT     0x10
#define FB_MOREDATA   0x20
#define FB_PROTECTED  0x40
#define FB_ORDER      0x80

typedef struct {
    uint8_t        type;         /* 0 mgmt, 2 data */
    uint8_t        subtype;
    uint8_t        flags;        /* FB_* OR-ed; FB_ORDER does NOT imply HTC */
    uint16_t       duration;
    const uint8_t *a1, *a2, *a3; /* required */
    uint16_t       seq_ctl;      /* (seq << 4) | frag */
    int            a4_present;   /* append Address 4 */
    const uint8_t *a4;           /* used when a4_present; NULL -> zeros */
    int            qos_present;  /* append QoS Control */
    uint16_t       qos;
    int            htc_present;  /* append HT Control (DE AD BE EF) */
} fb_hdr_t;

/* FC, Duration, A1, A2, A3, SeqCtl, [A4], [QoS], [HTC]: the order of
 * Figure 9-1 for management and data frames. Presence of the optional
 * fields is exactly what the test stated. */
static inline void fb_dot11_hdr(fb_t *b, const fb_hdr_t *h) {
    static const uint8_t zero6[6] = {0, 0, 0, 0, 0, 0};
    fb_u8(b, (uint8_t)(((h->subtype & 0x0f) << 4) | ((h->type & 0x03) << 2)));
    fb_u8(b, h->flags);
    fb_le16(b, h->duration);
    fb_mac(b, h->a1 ? h->a1 : zero6);
    fb_mac(b, h->a2 ? h->a2 : zero6);
    fb_mac(b, h->a3 ? h->a3 : zero6);
    fb_le16(b, h->seq_ctl);
    if (h->a4_present)  fb_mac(b, h->a4 ? h->a4 : zero6);
    if (h->qos_present) fb_le16(b, h->qos);
    if (h->htc_present) {
        fb_u8(b, 0xDE); fb_u8(b, 0xAD); fb_u8(b, 0xBE); fb_u8(b, 0xEF);
    }
}

/* Control frame header (§9.3.1): FC, Duration, RA, and TA for the
 * subtypes that carry one. `ta` NULL emits RA only (CTS, ACK). */
static inline void fb_ctrl_hdr(fb_t *b, uint8_t subtype, uint8_t flags,
                               uint16_t duration,
                               const uint8_t ra[6], const uint8_t ta[6]) {
    fb_u8(b, (uint8_t)(((subtype & 0x0f) << 4) | (1 << 2)));
    fb_u8(b, flags);
    fb_le16(b, duration);
    fb_mac(b, ra);
    if (ta) fb_mac(b, ta);
}

/* Management header (§9.3.3.1): A1 = DA, A2 = SA, A3 = BSSID. */
static inline void fb_mgmt(fb_t *b, uint8_t subtype, uint8_t flags,
                           const uint8_t da[6], const uint8_t sa[6],
                           const uint8_t bssid[6], uint16_t seq_ctl,
                           int htc_present) {
    fb_hdr_t h;
    memset(&h, 0, sizeof(h));
    h.type = 0; h.subtype = subtype; h.flags = flags;
    h.a1 = da; h.a2 = sa; h.a3 = bssid; h.seq_ctl = seq_ctl;
    h.htc_present = htc_present;
    fb_dot11_hdr(b, &h);
}

/* ── Fixed fields ─────────────────────────────────────────────────── */

/* Beacon / probe response fixed part (§9.3.3.3 / §9.3.3.11):
 * Timestamp(8) BeaconInterval(2) Capability(2). */
static inline void fb_beacon_fixed(fb_t *b, uint64_t timestamp,
                                   uint16_t interval, uint16_t caps) {
    fb_le64(b, timestamp);
    fb_le16(b, interval);
    fb_le16(b, caps);
}

/* (Re)association response fixed part (§9.3.3.7 / §9.3.3.9):
 * Capability(2) StatusCode(2) AID(2). */
static inline void fb_assoc_resp_fixed(fb_t *b, uint16_t caps,
                                       uint16_t status, uint16_t aid) {
    fb_le16(b, caps);
    fb_le16(b, status);
    fb_le16(b, aid);
}

/* ── Information elements (§9.4.2) ────────────────────────────────── */

static inline void fb_ie(fb_t *b, uint8_t tag, const void *data, int n) {
    fb_u8(b, tag);
    fb_u8(b, (uint8_t)n);
    fb_bytes(b, data, n);
}

/* Element ID Extension (§9.4.2.1): tag 255, length counts the
 * extension octet, then the extension ID and the body. */
static inline void fb_ie_ext(fb_t *b, uint8_t ext_id, const void *data, int n) {
    fb_u8(b, 255);
    fb_u8(b, (uint8_t)(n + 1));
    fb_u8(b, ext_id);
    fb_bytes(b, data, n);
}

static inline void fb_ssid(fb_t *b, const char *ssid) {
    fb_ie(b, 0, ssid, (int)strlen(ssid));
}

/* RSNE (§9.4.2.24) with one pairwise suite and one AKM, all under the
 * IEEE OUI 00-0F-AC: Version(2) Group(4) PairwiseCount(2) Pairwise(4)
 * AKMCount(2) AKM(4) RSNCapabilities(2). Suite selector types per
 * Table 9-149 (ciphers: 2 TKIP, 4 CCMP-128) and Table 9-151 (AKMs:
 * 2 PSK, 8 SAE). */
static inline void fb_rsn(fb_t *b, uint8_t group, uint8_t pairwise,
                          uint8_t akm, uint16_t rsn_caps) {
    uint8_t body[20];
    int p = 0;
    body[p++] = 0x01; body[p++] = 0x00;                       /* version 1 */
    body[p++] = 0x00; body[p++] = 0x0f; body[p++] = 0xac; body[p++] = group;
    body[p++] = 0x01; body[p++] = 0x00;                       /* 1 pairwise */
    body[p++] = 0x00; body[p++] = 0x0f; body[p++] = 0xac; body[p++] = pairwise;
    body[p++] = 0x01; body[p++] = 0x00;                       /* 1 AKM */
    body[p++] = 0x00; body[p++] = 0x0f; body[p++] = 0xac; body[p++] = akm;
    body[p++] = (uint8_t)(rsn_caps & 0xff);
    body[p++] = (uint8_t)(rsn_caps >> 8);
    fb_ie(b, 48, body, p);
}

/* RSNE (§9.4.2.24) with lists, for the cases fb_rsn() cannot state: a
 * transition-mode AKM pair, several pairwise suites. Same clause order
 * and IEEE OUI; every count written is the number of suites written. */
static inline void fb_rsn_lists(fb_t *b, uint8_t group,
                                const uint8_t *pairwise, int npw,
                                const uint8_t *akm, int nakm,
                                uint16_t rsn_caps) {
    uint8_t body[64];
    fb_t e;
    fb_init(&e, body, (int)sizeof body);
    fb_le16(&e, 1);                                           /* version */
    fb_u8(&e, 0x00); fb_u8(&e, 0x0f); fb_u8(&e, 0xac); fb_u8(&e, group);
    fb_le16(&e, (uint16_t)npw);
    for (int i = 0; i < npw; i++) {
        fb_u8(&e, 0x00); fb_u8(&e, 0x0f); fb_u8(&e, 0xac); fb_u8(&e, pairwise[i]);
    }
    fb_le16(&e, (uint16_t)nakm);
    for (int i = 0; i < nakm; i++) {
        fb_u8(&e, 0x00); fb_u8(&e, 0x0f); fb_u8(&e, 0xac); fb_u8(&e, akm[i]);
    }
    fb_le16(&e, rsn_caps);
    if (e.overflow) { b->overflow = 1; return; }
    fb_ie(b, 48, body, e.len);
}

/* ── Data frame body pieces ───────────────────────────────────────── */

/* LLC/SNAP with the RFC 1042 encapsulation OUI 00-00-00 and a
 * big-endian ethertype. */
static inline void fb_llc_snap(fb_t *b, uint16_t ethertype) {
    fb_u8(b, 0xAA); fb_u8(b, 0xAA); fb_u8(b, 0x03);
    fb_u8(b, 0x00); fb_u8(b, 0x00); fb_u8(b, 0x00);
    fb_be16(b, ethertype);
}

/* CCMP header (§12.5.3.2 Figure 12-17): PN0 PN1 Rsvd KeyID|ExtIV
 * PN2 PN3 PN4 PN5 — low-order octets first, the high four after the
 * KeyID octet. Bit 5 of the KeyID octet is Extended IV. */
static inline void fb_ccmp_hdr(fb_t *b, uint64_t pn, uint8_t key_id) {
    fb_u8(b, (uint8_t)(pn >> 0));
    fb_u8(b, (uint8_t)(pn >> 8));
    fb_u8(b, 0x00);
    fb_u8(b, (uint8_t)(0x20 | ((key_id & 0x03) << 6)));
    fb_u8(b, (uint8_t)(pn >> 16));
    fb_u8(b, (uint8_t)(pn >> 24));
    fb_u8(b, (uint8_t)(pn >> 32));
    fb_u8(b, (uint8_t)(pn >> 40));
}

/* `n` bytes that stand in for ciphertext. The sequence starts 9C C1 E6
 * and never contains AA AA 03 at its head, so a parser that wrongly
 * reads a Protected body cannot find an LLC header in it. */
static inline void fb_ciphertext(fb_t *b, int n) {
    for (int i = 0; i < n; i++) fb_u8(b, (uint8_t)(0x9c + 37 * i));
}

/* One A-MSDU subframe (§9.3.2.2.2): DA(6) SA(6) Length(2, big-endian)
 * MSDU, then padding to a 4-octet boundary (the last subframe is not
 * padded on the air; a test that wants that appends it by hand). */
static inline void fb_amsdu_subframe(fb_t *b, const uint8_t da[6],
                                     const uint8_t sa[6],
                                     const void *msdu, int n) {
    fb_mac(b, da);
    fb_mac(b, sa);
    fb_be16(b, (uint16_t)n);
    fb_bytes(b, msdu, n);
    while ((14 + n) % 4) { fb_u8(b, 0); n++; }
}

/* Radiotap DATAPAD: zero octets until the MAC header ends on a 4-octet
 * boundary measured from the start of the 802.11 frame — `frame_start`
 * is the buffer offset the frame began at (0 with no radiotap header,
 * the value fb_radiotap() returned otherwise; a radiotap header need
 * not itself be a multiple of 4). Called right after the header. */
static inline void fb_datapad_to4(fb_t *b, int frame_start) {
    while ((b->len - frame_start) % 4) fb_u8(b, 0);
}

/* ── Trailer ──────────────────────────────────────────────────────── */

/* The real FCS (§9.2.4.8): CRC-32 as in IEEE 802.3, over everything
 * appended so far, transmitted least-significant octet first. Computed
 * bitwise so the header has no table to keep. */
static inline void fb_fcs(fb_t *b) {
    uint32_t crc = 0xFFFFFFFFu;
    for (int i = 0; i < b->len; i++) {
        crc ^= b->buf[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    crc = ~crc;
    for (int i = 0; i < 4; i++) fb_u8(b, (uint8_t)(crc >> (8 * i)));
}

/* `n` octets of recognisable garbage (BA D0 BA D0 ...) for the tests
 * that need bytes after the frame which must NOT be parsed. */
static inline void fb_bad_bytes(fb_t *b, int n) {
    for (int i = 0; i < n; i++) fb_u8(b, (i & 1) ? 0xD0 : 0xBA);
}

/* ── Radiotap (https://www.radiotap.org) ──────────────────────────── */

typedef struct {
    int     has_flags;   uint8_t  flags;     /* bit 1, 1 octet            */
    int     has_channel; uint16_t freq_mhz;  /* bit 3, 2+2 octets, align 2 */
    int     has_signal;  int8_t   dbm;       /* bit 5, 1 octet            */
} fb_rt_t;

/* An 8-octet radiotap header plus the present fields in bit order with
 * their natural alignment, it_len patched to the total. A NULL `rt`
 * emits the bare header with an empty present bitmap. Returns the
 * header length. */
static inline int fb_radiotap(fb_t *b, const fb_rt_t *rt) {
    int start = b->len;
    uint32_t present = 0;
    if (rt && rt->has_flags)   present |= 1u << 1;
    if (rt && rt->has_channel) present |= 1u << 3;
    if (rt && rt->has_signal)  present |= 1u << 5;
    fb_u8(b, 0);                 /* it_version */
    fb_u8(b, 0);                 /* it_pad     */
    fb_le16(b, 0);               /* it_len, patched below */
    fb_le16(b, (uint16_t)(present & 0xffff));
    fb_le16(b, (uint16_t)(present >> 16));
    if (rt && rt->has_flags) fb_u8(b, rt->flags);
    if (rt && rt->has_channel) {
        while ((b->len - start) % 2) fb_u8(b, 0);
        fb_le16(b, rt->freq_mhz);
        fb_le16(b, 0);           /* channel flags: none claimed */
    }
    if (rt && rt->has_signal) fb_u8(b, (uint8_t)rt->dbm);
    int hlen = b->len - start;
    if (start + 3 < b->cap && !b->overflow) {
        b->buf[start + 2] = (uint8_t)(hlen & 0xff);
        b->buf[start + 3] = (uint8_t)(hlen >> 8);
    }
    return hlen;
}

/* ── Wired: Ethernet II, IPv4, UDP, TCP, ICMP ─────────────────────── */

/* Added for the --replay generator (#119), whose wired savefile needs
 * whole frames rather than the parser-local fragments the capture-path
 * tests build. Same discipline as above: fields in header order, every
 * value one the caller chose, and the checksums computed per their RFC
 * rather than left zero, so a frame here is one a real stack would
 * accept — the replay is an integration input, not a parser probe. */

/* Ethernet II (IEEE 802.3 clause 3.2, DIX framing): DA, SA, EtherType.
 * No FCS — libpcap hands frames over without one on EN10MB. */
static inline void fb_eth(fb_t *b, const uint8_t da[6], const uint8_t sa[6],
                          uint16_t ethertype) {
    fb_mac(b, da);
    fb_mac(b, sa);
    fb_be16(b, ethertype);
}

/* RFC 1071 one's-complement sum over `n` bytes, folded, NOT inverted,
 * starting from `acc` so a pseudo-header can be summed first. */
static inline uint32_t fb_csum_add(uint32_t acc, const uint8_t *p, int n) {
    for (int i = 0; i + 1 < n; i += 2) acc += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (n & 1) acc += (uint32_t)(p[n - 1] << 8);
    return acc;
}
static inline uint16_t fb_csum_fold(uint32_t acc) {
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return (uint16_t)~acc;
}

/* IPv4 header (RFC 791 §3.1), IHL 5, no options, DF clear, TTL 64.
 * `payload_len` is what will follow; the header checksum is computed
 * here because every field it covers is now known. Returns the offset
 * of the header in the buffer, for the transport checksum. */
static inline int fb_ipv4(fb_t *b, uint8_t proto, const uint8_t src[4],
                          const uint8_t dst[4], int payload_len, uint16_t id) {
    int at = b->len;
    fb_u8(b, 0x45);
    fb_u8(b, 0x00);
    fb_be16(b, (uint16_t)(20 + payload_len));
    fb_be16(b, id);
    fb_be16(b, 0x0000);
    fb_u8(b, 64);
    fb_u8(b, proto);
    fb_be16(b, 0x0000);                 /* checksum, patched below */
    fb_bytes(b, src, 4);
    fb_bytes(b, dst, 4);
    if (!b->overflow) {
        uint16_t c = fb_csum_fold(fb_csum_add(0, b->buf + at, 20));
        b->buf[at + 10] = (uint8_t)(c >> 8);
        b->buf[at + 11] = (uint8_t)(c & 0xff);
    }
    return at;
}

/* TCP/UDP checksum over the RFC 793 §3.1 / RFC 768 pseudo-header plus
 * the segment at `seg` (length `n`), written big-endian at `seg + at`. */
static inline void fb_l4_csum(fb_t *b, int ip_at, int seg, int n, int at) {
    if (b->overflow) return;
    uint8_t ph[12];
    memcpy(ph, b->buf + ip_at + 12, 8);           /* src, dst */
    ph[8] = 0; ph[9] = b->buf[ip_at + 9];         /* zero, protocol */
    ph[10] = (uint8_t)(n >> 8); ph[11] = (uint8_t)(n & 0xff);
    uint16_t c = fb_csum_fold(fb_csum_add(fb_csum_add(0, ph, 12),
                                          b->buf + seg, n));
    if (c == 0 && b->buf[ip_at + 9] == 17) c = 0xffff;   /* RFC 768 */
    b->buf[seg + at]     = (uint8_t)(c >> 8);
    b->buf[seg + at + 1] = (uint8_t)(c & 0xff);
}

/* Ethernet + IPv4 + UDP (RFC 768) carrying `payload`. */
static inline void fb_eth_ipv4_udp(fb_t *b, const uint8_t da[6],
                                   const uint8_t sa[6], const uint8_t src[4],
                                   const uint8_t dst[4], uint16_t sport,
                                   uint16_t dport, const void *payload, int n,
                                   uint16_t ip_id) {
    fb_eth(b, da, sa, 0x0800);
    int ip = fb_ipv4(b, 17, src, dst, 8 + n, ip_id);
    int seg = b->len;
    fb_be16(b, sport);
    fb_be16(b, dport);
    fb_be16(b, (uint16_t)(8 + n));
    fb_be16(b, 0x0000);
    fb_bytes(b, payload, n);
    fb_l4_csum(b, ip, seg, 8 + n, 6);
}

/* TCP flag bits (RFC 793 §3.1, RFC 9293 §3.1). */
#define FB_TCP_FIN 0x01
#define FB_TCP_SYN 0x02
#define FB_TCP_PSH 0x08
#define FB_TCP_ACK 0x10

/* Ethernet + IPv4 + TCP, data offset 5 (no options), window 65535. */
static inline void fb_eth_ipv4_tcp(fb_t *b, const uint8_t da[6],
                                   const uint8_t sa[6], const uint8_t src[4],
                                   const uint8_t dst[4], uint16_t sport,
                                   uint16_t dport, uint32_t seq, uint32_t ack,
                                   uint8_t flags, const void *payload, int n,
                                   uint16_t ip_id) {
    fb_eth(b, da, sa, 0x0800);
    int ip = fb_ipv4(b, 6, src, dst, 20 + n, ip_id);
    int seg = b->len;
    fb_be16(b, sport);
    fb_be16(b, dport);
    fb_be16(b, (uint16_t)(seq >> 16)); fb_be16(b, (uint16_t)seq);
    fb_be16(b, (uint16_t)(ack >> 16)); fb_be16(b, (uint16_t)ack);
    fb_u8(b, 5 << 4);
    fb_u8(b, flags);
    fb_be16(b, 65535);
    fb_be16(b, 0x0000);                 /* checksum */
    fb_be16(b, 0x0000);                 /* urgent pointer */
    fb_bytes(b, payload, n);
    fb_l4_csum(b, ip, seg, 20 + n, 16);
}

/* Ethernet + IPv4 + ICMP echo (RFC 792: type 8 request, 0 reply). */
static inline void fb_eth_ipv4_icmp_echo(fb_t *b, const uint8_t da[6],
                                         const uint8_t sa[6],
                                         const uint8_t src[4],
                                         const uint8_t dst[4], uint8_t type,
                                         uint16_t ident, uint16_t seqno,
                                         uint16_t ip_id) {
    fb_eth(b, da, sa, 0x0800);
    (void)fb_ipv4(b, 1, src, dst, 8, ip_id);
    int at = b->len;
    fb_u8(b, type);
    fb_u8(b, 0);
    fb_be16(b, 0x0000);
    fb_be16(b, ident);
    fb_be16(b, seqno);
    if (!b->overflow) {
        uint16_t c = fb_csum_fold(fb_csum_add(0, b->buf + at, 8));
        b->buf[at + 2] = (uint8_t)(c >> 8);
        b->buf[at + 3] = (uint8_t)(c & 0xff);
    }
}

#endif /* SLOTH_FRAME_BUILD_H */
