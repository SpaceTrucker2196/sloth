#include <string.h>
#include "btle_ll.h"

/* Contract and sources in btle_ll.h. Clause numbers are Bluetooth Core
 * Specification v5.4 Vol 6 Part B unless named otherwise. */

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t le24(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}
static uint32_t le32(const uint8_t *p) {
    return le24(p) | ((uint32_t)p[3] << 24);
}

int btle_rf_to_index(int rf) {
    if (rf < 0 || rf > 39) return -1;
    if (rf == 0)  return 37;
    if (rf == 12) return 38;
    if (rf == 39) return 39;
    return rf < 12 ? rf - 1 : rf - 2;
}

/* The Length range §2.3 gives each legacy advertising PDU type; -1 for
 * a type whose payload is not a fixed legacy shape. */
static int len_ok(uint8_t type, uint8_t len) {
    switch (type) {
    case BTLE_ADV_IND:
    case BTLE_ADV_NONCONN_IND:
    case BTLE_ADV_SCAN_IND:
    case BTLE_SCAN_RSP:       return len >= 6 && len <= 37;   /* AdvA + 0..31 */
    case BTLE_ADV_DIRECT_IND:
    case BTLE_SCAN_REQ:       return len == 12;               /* two addresses */
    case BTLE_CONNECT_IND:    return len == 34;               /* InitA AdvA LLData(22) */
    default:                  return -1;
    }
}

btle_verdict_t btle_ll_parse(const uint8_t *pkt, size_t len, btle_pkt_t *out) {
    if (!out) return BTLE_V_MALFORMED;
    memset(out, 0, sizeof(*out));
    out->channel_index = -1;
    if (!pkt || len < BTLE_AA_LEN + BTLE_PDU_HDR_LEN) return BTLE_V_MALFORMED;
    out->aa = le32(pkt);
    /* A data-channel PDU (follow mode) belongs to a connection: its
     * payload is someone's traffic, and none of it is read. */
    if (out->aa != BTLE_ADV_AA) return BTLE_V_DATA;

    const uint8_t h0 = pkt[4];
    out->pdu_type    = h0 & 0x0F;
    out->chsel       = (h0 >> 5) & 1;
    out->txadd       = (h0 >> 6) & 1;
    out->rxadd       = (h0 >> 7) & 1;
    out->len_claimed = pkt[5];

    /* Trusted: the claim, bounded by what the record holds and by what
     * an Ubertooth can have delivered at all. */
    size_t avail = len - (BTLE_AA_LEN + BTLE_PDU_HDR_LEN);
    size_t trust = out->len_claimed;
    if (trust > avail) trust = avail;
    if (trust > BTLE_PAYLOAD_TRUST_MAX) trust = BTLE_PAYLOAD_TRUST_MAX;
    out->len_trusted = (uint8_t)trust;
    out->truncated   = trust < out->len_claimed;
    const uint8_t *pl = pkt + BTLE_AA_LEN + BTLE_PDU_HDR_LEN;

    int ok = len_ok(out->pdu_type, out->len_claimed);
    if (ok == 0) return BTLE_V_MALFORMED;
    if (ok < 0)
        return out->pdu_type == BTLE_ADV_EXT_IND ? BTLE_V_EXT_ADV : BTLE_V_OTHER;

    switch (out->pdu_type) {
    case BTLE_SCAN_REQ:
        /* ScanA (TxAdd), AdvA (RxAdd), §2.3.2.1. */
        if (trust >= 6)  { out->has_peer = 1; memcpy(out->peer, pl, 6); }
        if (trust >= 12) { out->has_adva = 1; memcpy(out->adva, pl + 6, 6); }
        return BTLE_V_SCAN_REQ;
    case BTLE_CONNECT_IND:
        /* InitA (TxAdd), AdvA (RxAdd), LLData, §2.3.3.1. */
        if (trust >= 6)  { out->has_peer = 1; memcpy(out->peer, pl, 6); }
        if (trust >= 12) { out->has_adva = 1; memcpy(out->adva, pl + 6, 6); }
        if (trust >= 34) {
            const uint8_t *d = pl + 12;
            btle_conn_ind_t *c = &out->conn;
            c->aa         = le32(d);
            c->crc_init   = le24(d + 4);
            c->win_size   = d[7];
            c->win_offset = le16(d + 8);
            c->interval   = le16(d + 10);
            c->latency    = le16(d + 12);
            c->timeout    = le16(d + 14);
            memcpy(c->chm, d + 16, 5);
            c->hop        = d[21] & 0x1F;
            c->sca        = (uint8_t)(d[21] >> 5);
            out->has_conn = 1;
        }
        return BTLE_V_CONNECT_IND;
    case BTLE_ADV_DIRECT_IND:
        /* AdvA (TxAdd), TargetA (RxAdd), §2.3.1.2; no AdvData. */
        if (trust >= 6)  { out->has_adva = 1; memcpy(out->adva, pl, 6); }
        if (trust >= 12) { out->has_peer = 1; memcpy(out->peer, pl + 6, 6); }
        return BTLE_V_ADV;
    default:
        /* ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND, SCAN_RSP: AdvA then
         * AdvData / ScanRspData, §2.3.1.1, §2.3.1.3, §2.3.1.4, §2.3.2.2. */
        if (trust >= 6) {
            out->has_adva = 1;
            memcpy(out->adva, pl, 6);
            out->data     = pl + 6;
            out->data_len = trust - 6;
        }
        return BTLE_V_ADV;
    }
}

btle_verdict_t btle_phdr_record_parse(const uint8_t *rec, size_t len,
                                      btle_pkt_t *out) {
    if (!out) return BTLE_V_MALFORMED;
    if (!rec || len < BTLE_PHDR_LEN) {
        memset(out, 0, sizeof(*out));
        out->channel_index = -1;
        return BTLE_V_MALFORMED;
    }
    btle_verdict_t v = btle_ll_parse(rec + BTLE_PHDR_LEN, len - BTLE_PHDR_LEN, out);
    out->has_phdr      = 1;
    out->rf_channel    = rec[0];
    out->channel_index = (int8_t)btle_rf_to_index(rec[0]);
    out->phdr_flags    = le16(rec + 8);
    out->signal_valid  = (out->phdr_flags & BTLE_PHDR_SIGNAL_VALID) != 0;
    out->signal_dbm    = (int8_t)rec[1];
    out->noise_valid   = (out->phdr_flags & BTLE_PHDR_NOISE_VALID) != 0;
    out->noise_dbm     = (int8_t)rec[2];
    /* An RF channel outside 0..39 is not a channel; the record is not
     * one this link type can carry. */
    if (out->channel_index < 0) return BTLE_V_MALFORMED;
    return v;
}

btle_verdict_t btle_ppi_record_parse(const uint8_t *rec, size_t len,
                                     btle_pkt_t *out) {
    if (!out) return BTLE_V_MALFORMED;
    memset(out, 0, sizeof(*out));
    out->channel_index = -1;
    /* PPI packet header: version (0), flags, length (LE16, the whole
     * header including its fields), DLT (LE32) of what follows. */
    if (!rec || len < BTLE_PPI_HDR_MIN) return BTLE_V_MALFORMED;
    size_t hlen = le16(rec + 2);
    if (rec[0] != 0 || hlen < BTLE_PPI_HDR_MIN || hlen > len)
        return BTLE_V_MALFORMED;
    if (le32(rec + 4) != BTLE_DLT_LL) return BTLE_V_MALFORMED;
    return btle_ll_parse(rec + hlen, len - hlen, out);
}

int btle_adv_report(const btle_pkt_t *p, ble_adv_report_t *r) {
    if (!p || !r || !p->has_adva) return 0;
    memset(r, 0, sizeof(*r));
    switch (p->pdu_type) {
    case BTLE_ADV_IND:         r->event_type = 0x00; break;
    case BTLE_ADV_DIRECT_IND:  r->event_type = 0x01; break;
    case BTLE_ADV_SCAN_IND:    r->event_type = 0x02; break;
    case BTLE_ADV_NONCONN_IND: r->event_type = 0x03; break;
    case BTLE_SCAN_RSP:        r->event_type = 0x04; break;
    default:                   return 0;
    }
    r->addr_type = p->txadd;
    memcpy(r->addr, p->adva, 6);
    if (p->has_phdr && p->signal_valid) {
        r->has_rssi = true;
        r->rssi     = p->signal_dbm;
    }
    /* Only the trusted octets: an AD structure that runs past them is
     * dropped by the walker, never completed from beyond. */
    if (p->data && p->data_len) ble_ad_parse(p->data, p->data_len, r);
    if (p->truncated) r->truncated = true;
    return 1;
}
