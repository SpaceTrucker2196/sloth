#include "ble_snoop.h"
#include <string.h>

#define HCI_EV_LE_META          0x3E
#define HCI_SUBEVT_ADV_REPORT   0x02
#define HCI_SUBEVT_EXT_ADV_REPORT 0x0D
#define BLE_TX_POWER_NOT_AVAILABLE 127
#define BLE_LEGACY_ADV_DATA_MAX 31
#define BLE_RSSI_NOT_AVAILABLE  127

#define BLE_AD_FLAGS            0x01
#define BLE_AD_UUID16_INCOMPLETE 0x02
#define BLE_AD_UUID16_COMPLETE  0x03
#define BLE_AD_NAME_SHORT       0x08
#define BLE_AD_NAME_COMPLETE    0x09
#define BLE_AD_TX_POWER         0x0A
#define BLE_AD_SVC_DATA16       0x16
#define BLE_AD_APPEARANCE       0x19
#define BLE_AD_MFR_DATA         0xFF

void ble_ad_parse(const uint8_t *data, size_t len, ble_adv_report_t *out) {
    if (!out || !data || len == 0) return;

    if (out->ad_shape == 0) out->ad_shape = 2166136261u;   /* FNV-1a 32 offset */
    size_t off = 0;
    while (off < len) {
        uint8_t ad_len = data[off];
        if (ad_len == 0) break; /* zero-length AD struct: end of real data / padding */
        if (off + 1 + (size_t)ad_len > len) {
            out->truncated = true;
            break;
        }

        uint8_t ad_type = data[off + 1];
        const uint8_t *val = data + off + 2;
        out->ad_shape = (out->ad_shape ^ ad_type) * 16777619u;
        out->ad_shape = (out->ad_shape ^ ad_len) * 16777619u;
        size_t val_len = (size_t)ad_len - 1; /* ad_len counts the type octet + value */

        switch (ad_type) {
        case BLE_AD_FLAGS:
            if (val_len >= 1) {
                out->has_flags = true;
                out->flags = val[0];
            }
            break;

        case BLE_AD_UUID16_INCOMPLETE:
        case BLE_AD_UUID16_COMPLETE:
            if (val_len >= 2 && !out->has_service_uuid16) {
                out->has_service_uuid16 = true;
                out->service_uuid16 = (uint16_t)(val[0] | (val[1] << 8));
            }
            /* The list is val_len / 2 UUIDs; an odd trailing octet is
             * not half a UUID and is skipped. */
            for (size_t u = 0; u + 1 < val_len &&
                               out->uuid16_count < BLE_UUID16_LIST_MAX; u += 2)
                out->uuid16_list[out->uuid16_count++] =
                    (uint16_t)(val[u] | (val[u + 1] << 8));
            break;

        case BLE_AD_SVC_DATA16:
            if (val_len >= 2 && !out->has_svc_data16) {
                out->has_svc_data16 = true;
                out->svc_data_uuid16 = (uint16_t)(val[0] | (val[1] << 8));
                size_t dl = val_len - 2;
                size_t copy = dl < BLE_SVC_DATA_MAX ? dl : BLE_SVC_DATA_MAX;
                memcpy(out->svc_data, val + 2, copy);
                out->svc_data_len = (uint8_t)copy;
                out->svc_data_clipped = dl > BLE_SVC_DATA_MAX;
            }
            break;

        case BLE_AD_NAME_SHORT:
        case BLE_AD_NAME_COMPLETE: {
            size_t copy = val_len < BLE_LOCAL_NAME_MAX ? val_len : BLE_LOCAL_NAME_MAX;
            memcpy(out->local_name, val, copy);
            out->local_name[copy] = '\0';
            out->has_local_name = true;
            out->local_name_complete = (ad_type == BLE_AD_NAME_COMPLETE);
            break;
        }

        case BLE_AD_TX_POWER:
            if (val_len >= 1) {
                out->has_tx_power = true;
                out->tx_power = (int8_t)val[0];
            }
            break;

        case BLE_AD_APPEARANCE:
            if (val_len >= 2) {
                out->has_appearance = true;
                out->appearance = (uint16_t)(val[0] | (val[1] << 8));
            }
            break;

        case BLE_AD_MFR_DATA:
            if (val_len >= 2) {
                out->has_mfr_data = true;
                out->mfr_id = (uint16_t)(val[0] | (val[1] << 8));
                size_t mfr_len = val_len - 2;
                size_t copy = mfr_len < BLE_MFR_DATA_MAX ? mfr_len : BLE_MFR_DATA_MAX;
                memcpy(out->mfr_data, val + 2, copy);
                out->mfr_data_len = (uint8_t)copy;
                out->mfr_data_clipped = mfr_len > BLE_MFR_DATA_MAX;
            }
            break;

        default:
            break; /* unrecognised AD type: not an error, just not decoded */
        }

        off += 1 + (size_t)ad_len; /* 1 length octet + (type octet + value) */
    }
}

/* One 0x02 report's octets before its Data: Event_Type Address_Type
 * Address(6) Data_Length. Its RSSI follows the Data. */
#define ADV_REC_FIXED 9

int ble_hci_adv_walk(const uint8_t *evt, size_t len, ble_report_cb_t cb, void *ctx) {
    if (!evt || len < 4) return 0;
    if (evt[0] != HCI_EV_LE_META) return 0;
    if (evt[2] != HCI_SUBEVT_ADV_REPORT) return 0;

    uint8_t num_reports = evt[3];
    if (num_reports == 0) return 0;

    /* Consecutive records (ble_snoop.h), each bounded before an octet
     * of it is read, and together exactly `len`: a short or overlong
     * event decodes nothing rather than a prefix of its reports. */
    size_t off = 4;
    for (uint8_t i = 0; i < num_reports; i++) {
        if (off + ADV_REC_FIXED > len) return 0;
        size_t dl = evt[off + 8];
        if (off + ADV_REC_FIXED + dl + 1 > len) return 0;
        off += ADV_REC_FIXED + dl + 1;
    }
    if (off != len) return 0;

    off = 4;
    for (uint8_t i = 0; i < num_reports; i++) {
        const uint8_t *r = evt + off;
        size_t dl = r[8];
        ble_adv_report_t rep;
        memset(&rep, 0, sizeof(rep));
        rep.event_type = r[0];
        rep.addr_type  = r[1];
        memcpy(rep.addr, r + 2, 6);
        int8_t rssi = (int8_t)r[ADV_REC_FIXED + dl];
        if (rssi != BLE_RSSI_NOT_AVAILABLE) {
            rep.has_rssi = true;
            rep.rssi = rssi;
        }
        ble_ad_parse(r + ADV_REC_FIXED, dl, &rep);
        if (cb) cb(&rep, ctx);
        off += ADV_REC_FIXED + dl + 1;
    }
    return num_reports;
}

/* Event_Type bits of a 0x0D report (§7.7.65.13). */
#define EXT_EVT_CONNECTABLE  0x0001
#define EXT_EVT_SCANNABLE    0x0002
#define EXT_EVT_DIRECTED     0x0004
#define EXT_EVT_SCAN_RSP     0x0008
#define EXT_EVT_LEGACY       0x0010

#define PHY_LE_1M            0x01

/* The 0x02 Event_Type for a Legacy-bit report, -1 for a combination the
 * clause does not list. Compared on bits 0-6, data status (bits 5-6)
 * included, so this is also what refuses a Legacy-bit report claiming
 * to be a fragment: a legacy PDU is never fragmented. Bits 7-15 are
 * reserved for future use. */
static int legacy_code(uint16_t et) {
    switch (et & 0x7F) {
    case 0x13: return 0x00;   /* ADV_IND */
    case 0x15: return 0x01;   /* ADV_DIRECT_IND */
    case 0x12: return 0x02;   /* ADV_SCAN_IND */
    case 0x10: return 0x03;   /* ADV_NONCONN_IND */
    case 0x1B:                /* SCAN_RSP to an ADV_IND */
    case 0x1A: return 0x04;   /* SCAN_RSP to an ADV_SCAN_IND */
    default:   return -1;
    }
}

/* One report record at `r`: BLE_EXT_REPORT_FIXED octets, then the Data
 * the caller has already bounded. Fills `out` (zeroed first); 0 for a
 * record the clause does not allow. */
static int ext_decode(const uint8_t *r, ble_adv_report_t *out) {
    size_t dlen = r[23];
    uint16_t et = (uint16_t)(r[0] | (r[1] << 8));
    uint8_t status = (uint8_t)((et >> 5) & 0x03);
    if (status == 0x03) return 0;   /* reserved */

    int legacy = (et & EXT_EVT_LEGACY) != 0;
    int code;
    if (legacy) {
        /* At most 31 octets of AdvData or ScanRspData (Vol 6 Part B
         * §2.3.1). And §7.7.65.13: "If the Event_Type indicates a legacy
         * PDU (bit 4 = 1), the Primary_PHY parameter shall indicate the
         * LE 1M PHY and the Secondary_PHY parameter shall be set to
         * 0x00." A report breaking that is refused like any other
         * field the clause rules out. */
        code = legacy_code(et);
        if (code < 0 || dlen > BLE_LEGACY_ADV_DATA_MAX) return 0;
        if (r[9] != PHY_LE_1M || r[10] != 0x00) return 0;
    } else {
        code = (et & EXT_EVT_SCAN_RSP) ? BLE_EVT_EXT_SCAN_RSP : BLE_EVT_EXT_ADV;
    }

    memset(out, 0, sizeof(*out));
    out->ext            = true;
    out->ext_event_type = et;
    out->event_type     = (uint8_t)code;
    out->data_status    = status;
    out->addr_type      = r[2];
    if (r[2] != BLE_ADDR_ANONYMOUS) memcpy(out->addr, r + 3, 6);
    out->primary_phy    = r[9];
    out->secondary_phy  = r[10];
    /* A legacy PDU has no ADI (Vol 6 Part B §2.3.4: the ADI field is in
     * the extended header only), so its SID is "no ADI" whatever octet
     * the controller put in the field; the field is ignored. */
    out->sid            = legacy ? 0xFF : r[11];
    int8_t tx = (int8_t)r[12];
    if (tx != BLE_TX_POWER_NOT_AVAILABLE) {
        out->has_adv_tx_power = true;
        out->adv_tx_power     = tx;
    }
    int8_t rssi = (int8_t)r[13];
    if (rssi != BLE_RSSI_NOT_AVAILABLE) {
        out->has_rssi = true;
        out->rssi     = rssi;
    }
    out->periodic_interval = (uint16_t)(r[14] | (r[15] << 8));
    out->directed          = (et & EXT_EVT_DIRECTED) != 0;
    out->direct_addr_type  = r[16];
    memcpy(out->direct_addr, r + 17, 6);
    out->data_len          = (uint8_t)dlen;
    /* For an incomplete or truncated fragment this is a prefix of the
     * advertising data from its first octet: every AD structure it holds
     * whole decodes correctly, and the one the fragment boundary cut
     * sets `truncated` and ends the walk. */
    ble_ad_parse(r + BLE_EXT_REPORT_FIXED, dlen, out);
    return 1;
}

int ble_hci_ext_adv_walk(const uint8_t *evt, size_t len,
                         ble_report_cb_t cb, void *ctx) {
    if (!evt || len < 4) return 0;
    if (evt[0] != HCI_EV_LE_META) return 0;
    size_t plen = evt[1];
    if (2 + plen != len || plen < 2) return 0;
    if (evt[2] != HCI_SUBEVT_EXT_ADV_REPORT) return 0;

    size_t num = evt[3];
    /* 0x01..0x0A is the clause's range. A parameter length of at most
     * 255 cannot hold an eleventh 24-octet header, so the length checks
     * below already refuse a larger count; this bound is what keeps
     * `reps` visibly in range, and no test can tell it from them. */
    if (num == 0 || num > BLE_EXT_REPORTS_MAX) return 0;

    /* Consecutive records (ble_snoop.h). Every one is bounded and
     * decoded before the first callback, so an event with one bad
     * report puts none of its reports in the table. */
    ble_adv_report_t reps[BLE_EXT_REPORTS_MAX];
    const uint8_t *b = evt + 4;
    size_t blen = plen - 2, off = 0;
    for (size_t i = 0; i < num; i++) {
        if (off + BLE_EXT_REPORT_FIXED > blen) return 0;
        size_t dlen = b[off + 23];
        if (off + BLE_EXT_REPORT_FIXED + dlen > blen) return 0;
        if (!ext_decode(b + off, &reps[i])) return 0;
        off += BLE_EXT_REPORT_FIXED + dlen;
    }
    if (off != blen) return 0;

    for (size_t i = 0; i < num; i++)
        if (cb) cb(&reps[i], ctx);
    return (int)num;
}
