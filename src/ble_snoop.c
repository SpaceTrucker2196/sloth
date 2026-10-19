#include "ble_snoop.h"
#include <string.h>

#define HCI_EV_LE_META          0x3E
#define HCI_SUBEVT_ADV_REPORT   0x02
#define BLE_RSSI_NOT_AVAILABLE  127

#define BLE_AD_FLAGS            0x01
#define BLE_AD_UUID16_INCOMPLETE 0x02
#define BLE_AD_UUID16_COMPLETE  0x03
#define BLE_AD_NAME_SHORT       0x08
#define BLE_AD_NAME_COMPLETE    0x09
#define BLE_AD_TX_POWER         0x0A
#define BLE_AD_APPEARANCE       0x19
#define BLE_AD_MFR_DATA         0xFF

void ble_ad_parse(const uint8_t *data, size_t len, ble_adv_report_t *out) {
    if (!out || !data || len == 0) return;

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
            }
            break;

        default:
            break; /* unrecognised AD type: not an error, just not decoded */
        }

        off += 1 + (size_t)ad_len; /* 1 length octet + (type octet + value) */
    }
}

int ble_hci_adv_walk(const uint8_t *evt, size_t len, ble_report_cb_t cb, void *ctx) {
    if (!evt || len < 4) return 0;
    if (evt[0] != HCI_EV_LE_META) return 0;
    if (evt[2] != HCI_SUBEVT_ADV_REPORT) return 0;

    uint8_t num_reports = evt[3];
    if (num_reports == 0) return 0;

    size_t off = 4;
    /* Struct-of-arrays fixed fields: Event_Type[N], Address_Type[N],
     * Address[N*6], Data_Length[N]. Validated as one block before any
     * pointer into it is trusted. */
    size_t fixed_len = (size_t)num_reports * (1 + 1 + 6 + 1);
    if (off + fixed_len > len) return 0;

    const uint8_t *event_type = evt + off;  off += num_reports;
    const uint8_t *addr_type  = evt + off;  off += num_reports;
    const uint8_t *addr       = evt + off;  off += (size_t)num_reports * 6;
    const uint8_t *data_len   = evt + off;  off += num_reports;

    size_t remaining = len - off;
    size_t total_data = 0;
    for (uint8_t i = 0; i < num_reports; i++)
        total_data += data_len[i];

    /* Every report's Data back to back, then one RSSI octet per report.
     * Checked as a single sum so a short buffer rejects the whole event
     * rather than decoding a truncated prefix of reports. */
    if (total_data + (size_t)num_reports > remaining) return 0;

    const uint8_t *data_cursor = evt + off;
    const uint8_t *rssi = data_cursor + total_data;

    int decoded = 0;
    const uint8_t *dp = data_cursor;
    for (uint8_t i = 0; i < num_reports; i++) {
        ble_adv_report_t rep;
        memset(&rep, 0, sizeof(rep));
        rep.event_type = event_type[i];
        rep.addr_type  = addr_type[i];
        memcpy(rep.addr, addr + (size_t)i * 6, 6);

        int8_t r = (int8_t)rssi[i];
        if (r != BLE_RSSI_NOT_AVAILABLE) {
            rep.has_rssi = true;
            rep.rssi = r;
        }

        ble_ad_parse(dp, data_len[i], &rep);
        if (cb) cb(&rep, ctx);

        dp += data_len[i];
        decoded++;
    }

    return decoded;
}
