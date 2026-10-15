/* One bounded reader and one TLV iterator (#126).
 *
 * Before this header sloth walked tag/length lists by hand in at least
 * seventeen places, in six guard styles, with four different behaviours
 * on an element that claimed more bytes than were left: break silently,
 * bump a counter and break, set a flag and break, or reject the whole
 * frame. The same malformed frame could therefore be "fine" to one
 * parser and "fuzzed" to the next, and none of the silent ones left any
 * trace that it had happened. Byte-order helpers were re-declared
 * file-static under five names.
 *
 * This is the one place those live. Header-only `static inline`, C99,
 * no allocation, no globals — the caller decides what an overrun means
 * for its own counters; the iterator only guarantees that it stops and
 * says so.
 *
 * The overrun policy is single and deliberate: **stop and report**. An
 * element whose declared body reaches past the region, or a tail too
 * short to hold an element header, ends the walk with TLV_OVERRUN and
 * yields nothing further. Nothing after a lying length is trustworthy —
 * there is no defined resynchronisation point in an 802.11 element list,
 * so continuing would read attacker-chosen bytes as element headers. */

#ifndef SLOTH_BYTES_H
#define SLOTH_BYTES_H

#include <stdint.h>
#include <stddef.h>

/* ── Fixed-width loads. The caller has already bounds-checked. ─── */

static inline uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static inline uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static inline uint16_t le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t le32(const uint8_t *p) {
    return  (uint32_t)p[0]        | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
/* 48-bit little-endian, for six-octet counters stored contiguously
 * such as the Management MIC element's IPN. (CCMP's PN is split around
 * the Key ID octet and is not one of these.) */
static inline uint64_t le48(const uint8_t *p) {
    return  (uint64_t)p[0]        | ((uint64_t)p[1] << 8)  |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40);
}

/* ── Bounded cursor ─────────────────────────────────────────────
 *
 * A short read returns 0 (or NULL), sets `fault`, and leaves `off`
 * where it was — it never advances past `len`. The fault is sticky:
 * once set, every later read also fails, because a field read after a
 * short one sits at an offset the frame never described, and a value
 * from there is not zero, it is wrong. A caller can therefore read a
 * whole fixed layout and test `fault` once at the end. */
typedef struct {
    const uint8_t *p;
    int            len;
    int            off;
    int            fault;
} rd_t;

static inline void rd_init(rd_t *r, const uint8_t *p, int len) {
    r->p     = p;
    r->len   = (p && len > 0) ? len : 0;
    r->off   = 0;
    r->fault = 0;
}

static inline int rd_rem(const rd_t *r) { return r->len - r->off; }

/* Can `n` more bytes be taken? Sets the fault when not. */
static inline int rd_take_ok(rd_t *r, int n) {
    if (r->fault || n < 0 || n > r->len - r->off) { r->fault = 1; return 0; }
    return 1;
}

static inline uint8_t rd_u8(rd_t *r) {
    if (!rd_take_ok(r, 1)) return 0;
    return r->p[r->off++];
}
static inline uint16_t rd_le16(rd_t *r) {
    if (!rd_take_ok(r, 2)) return 0;
    uint16_t v = le16(r->p + r->off); r->off += 2; return v;
}
static inline uint16_t rd_be16(rd_t *r) {
    if (!rd_take_ok(r, 2)) return 0;
    uint16_t v = be16(r->p + r->off); r->off += 2; return v;
}
static inline uint32_t rd_le32(rd_t *r) {
    if (!rd_take_ok(r, 4)) return 0;
    uint32_t v = le32(r->p + r->off); r->off += 4; return v;
}
static inline uint32_t rd_be32(rd_t *r) {
    if (!rd_take_ok(r, 4)) return 0;
    uint32_t v = be32(r->p + r->off); r->off += 4; return v;
}
/* Borrow `n` bytes in place. *v is NULL on a short read. */
static inline int rd_bytes(rd_t *r, int n, const uint8_t **v) {
    if (!rd_take_ok(r, n)) { if (v) *v = NULL; return 0; }
    if (v) *v = r->p + r->off;
    r->off += n;
    return 1;
}
static inline int rd_skip(rd_t *r, int n) {
    if (!rd_take_ok(r, n)) return 0;
    r->off += n;
    return 1;
}
/* Carve the next `n` bytes off as their own reader — a length-prefixed
 * field parsed with its own bound, so a fault inside it cannot read
 * into the bytes that follow. A short carve leaves `sub` empty. */
static inline int rd_sub(rd_t *r, int n, rd_t *sub) {
    if (!rd_take_ok(r, n)) { if (sub) rd_init(sub, NULL, 0); return 0; }
    if (sub) rd_init(sub, r->p + r->off, n);
    r->off += n;
    return 1;
}

/* ── TLV iterator ───────────────────────────────────────────────
 *
 * tlv_init():   802.11 elements — 1-octet Element ID, 1-octet Length
 *               (IEEE 802.11-2020 §9.4.2.1). Also KDEs and the
 *               subelements of Neighbor Report / Measurement Request /
 *               Multi-Link, which share that framing.
 * tlv_init16(): 2-octet type, 2-octet length — WPS attributes (big
 *               endian) and TLS extensions (big endian); `bigend`
 *               selects byte order so a little-endian 2+2 TLV needs no
 *               second walker.
 *
 * tlv_next() yields only elements that fit entirely in the region.
 * Returns TLV_OK with the tag, length and body outputs filled, TLV_END
 * on a clean end (offset == length), or TLV_OVERRUN when the next
 * element's header or declared body does not fit. END and OVERRUN are terminal: later calls
 * return the same status and yield nothing. On OVERRUN `off` is left at
 * the start of the element that did not fit, so a caller that reports
 * how far the claim overshot (mle.c) can still read its header. */
enum { TLV_OVERRUN = -1, TLV_END = 0, TLV_OK = 1 };

typedef struct {
    const uint8_t *p;
    int            len;
    int            off;
    int            tagsz, lensz, bigend;
    int            status;
} tlv_it_t;

static inline void tlv_init_sz(tlv_it_t *it, const uint8_t *p, int len,
                               int sz, int bigend) {
    it->p      = p;
    it->len    = (p && len > 0) ? len : 0;
    it->off    = 0;
    it->tagsz  = sz;
    it->lensz  = sz;
    it->bigend = bigend;
    it->status = TLV_OK;
}

static inline void tlv_init(tlv_it_t *it, const uint8_t *p, int len) {
    tlv_init_sz(it, p, len, 1, 0);
}

static inline void tlv_init16(tlv_it_t *it, const uint8_t *p, int len,
                              int bigend) {
    tlv_init_sz(it, p, len, 2, bigend);
}

static inline int tlv_next(tlv_it_t *it, uint16_t *tag, int *blen,
                           const uint8_t **body) {
    if (it->status != TLV_OK) return it->status;
    if (it->off == it->len) { it->status = TLV_END; return TLV_END; }
    const int hdr = it->tagsz + it->lensz;
    /* A tail shorter than one header is not padding — no padding is
     * defined between elements — so it is the same fault as a body
     * that overshoots: the previous lengths did not tile the region. */
    if (!(it->off + hdr <= it->len)) {
        it->status = TLV_OVERRUN;
        return TLV_OVERRUN;
    }
    const uint8_t *h = it->p + it->off;
    uint16_t t;
    int      l;
    if (it->tagsz == 1) {
        t = h[0];
        l = h[1];
    } else if (it->bigend) {
        t = be16(h);
        l = be16(h + 2);
    } else {
        t = le16(h);
        l = le16(h + 2);
    }
    if (it->off + hdr + l > it->len) {
        it->status = TLV_OVERRUN;
        return TLV_OVERRUN;
    }
    if (tag)  *tag  = t;
    if (blen) *blen = l;
    if (body) *body = h + hdr;
    it->off += hdr + l;
    return TLV_OK;
}

/* The chain tiled the region exactly: it ended cleanly, with no
 * overrun and nothing left over. The rule mle.c's STA-profile reader
 * holds a chain to, where a non-tiling chain means the fixed prefix in
 * front of it was assumed wrongly. Meaningful only once tlv_next() has
 * returned something other than TLV_OK. */
static inline int tlv_exact(const tlv_it_t *it) {
    return it->status == TLV_END && it->off == it->len;
}

#endif /* SLOTH_BYTES_H */
