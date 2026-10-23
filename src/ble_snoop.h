#ifndef BLE_SNOOP_H
#define BLE_SNOOP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* BLE HCI passive advertisement decoder — issue #144 slice 1.
 *
 * Pure, stateless parsing only: no sensor registration, no device table,
 * no alert rule, no view. Proving the decoder correct against the spec
 * before anything is built on top of it, same precedent as #101 slice 1
 * (src/reg_ie.c) and #104 slice 1 (src/mle.c).
 *
 * Covers the legacy LE Advertising Report (HCI_EV_LE_Meta subevent 0x02,
 * Bluetooth Core Spec v5.x Vol 4 Part E §7.7.65.2) and the AD-structure
 * TLVs inside its Data field (Vol 3 Part C §11, types registered in the
 * Bluetooth "Assigned Numbers" supplement), and since the 0x0D slice the
 * LE Extended Advertising Report (subevent 0x0D, §7.7.65.13).
 *
 * ── Multi-report events ──
 *
 * Both events carry Num_Reports reports, drawn in their clauses as
 * arrayed parameters (Event_Type[i], Address_Type[i], ...). Core v5.4
 * Vol 4 Part E §5.2 fixes what that notation means on the wire: "If more
 * than one set of arrayed parameters are specified (e.g. ParameterA[i],
 * ParameterB[i]), then, unless noted otherwise, the order of the
 * parameters are as follows: ParameterA[0], ParameterB[0],
 * ParameterA[1], ParameterB[1] ...". Neither clause notes otherwise, so
 * the reports are consecutive records, one report's every field before
 * the next report's first, which is also how the Linux kernel reads them
 * (struct hci_ev_le_advertising_info, struct hci_ev_le_ext_adv_info).
 * Both walkers decode every report of an event that way. Num_Reports is
 * 0x01..0x19 for 0x02 and 0x01..0x0A for 0x0D; a parameter length of
 * 255 already bounds both.
 */

#define BLE_LOCAL_NAME_MAX 32
#define BLE_MFR_DATA_MAX   27 /* max AD payload (31) minus the 2-byte company ID */
#define BLE_SVC_DATA_MAX   27 /* max AD payload (31) minus the 2-byte UUID */
#define BLE_UUID16_LIST_MAX 8 /* 16-bit service UUIDs kept per report */

typedef struct {
    /* From the HCI event's per-report fixed fields. */
    uint8_t event_type;
    uint8_t addr_type;  /* 0=public 1=random 2=public-identity 3=random-identity */
    uint8_t addr[6];    /* as received over HCI (little-endian octet order) */
    bool    has_rssi;   /* false when the HCI RSSI field reads 127 ("not available") */
    int8_t  rssi;

    /* LE Extended Advertising Report only (subevent 0x0D, §7.7.65.13);
     * all zero for a legacy 0x02 report. `event_type` above is still the
     * legacy 0x02 code for a report with the Legacy bit set (so a legacy
     * PDU heard through an extended scan keys the same rows and flood
     * windows as the same PDU through a legacy scan), and
     * BLE_EVT_EXT_ADV / BLE_EVT_EXT_SCAN_RSP for an extended PDU. */
    bool     ext;              /* decoded from a 0x0D report */
    uint16_t ext_event_type;   /* the raw Event_Type bit field */
    uint8_t  data_status;      /* BLE_EXT_DATA_*, Event_Type bits 5-6 */
    /* PHY values per §7.7.65.13 as of Core v5.4: 0x01 LE 1M, 0x02 LE 2M
     * (secondary only), 0x03 LE Coded (S=8 where Advertising Coding
     * Selection is supported), 0x04 LE Coded S=2 (that feature only);
     * 0x00 secondary = no packets on the secondary channel. Kept as
     * received. */
    uint8_t  primary_phy;
    uint8_t  secondary_phy;
    uint8_t  sid;              /* Advertising_SID 0x00..0x0F, 0xFF no ADI;
                                * 0xFF for every Legacy-bit report */
    bool     has_adv_tx_power; /* false when TX_Power reads 127 */
    int8_t   adv_tx_power;     /* dBm, from the report header, not an AD structure */
    uint16_t periodic_interval;/* x 1.25 ms, 0 = no periodic advertising */
    bool     directed;         /* Event_Type bit 2 */
    uint8_t  direct_addr_type;
    uint8_t  direct_addr[6];   /* HCI order, as received */
    uint8_t  data_len;         /* Data_Length as received */

    /* From the AD-structure walk of that report's Data field. Every
     * has_* field is false (0) until ble_ad_parse() finds that AD type;
     * fields are never invented from absence. */
    bool     has_flags;
    uint8_t  flags;

    bool     has_service_uuid16; /* first 16-bit Service UUID found (type 0x02/0x03) */
    uint16_t service_uuid16;
    /* Every 16-bit Service UUID listed (type 0x02/0x03), in order, up to
     * BLE_UUID16_LIST_MAX (#144 slice 4): the HID service (0x1812) need
     * not be the first one a device lists. */
    uint8_t  uuid16_count;
    uint16_t uuid16_list[BLE_UUID16_LIST_MAX];

    /* Service Data - 16-bit UUID (AD type 0x16, Core Spec Supplement
     * Part A §1.11): a 16-bit UUID, then data that service defines.
     * First such structure only (#144 slice 4). */
    bool     has_svc_data16;
    uint16_t svc_data_uuid16;
    uint8_t  svc_data[BLE_SVC_DATA_MAX];
    uint8_t  svc_data_len;

    bool     has_local_name;
    bool     local_name_complete; /* true = Complete (0x09), false = Shortened (0x08) */
    char     local_name[BLE_LOCAL_NAME_MAX + 1];

    bool    has_tx_power;
    int8_t  tx_power;

    bool     has_appearance;
    uint16_t appearance;

    bool     has_mfr_data;      /* AD type 0xFF */
    uint16_t mfr_id;            /* Company ID, Assigned Numbers §7 */
    uint8_t  mfr_data[BLE_MFR_DATA_MAX];
    uint8_t  mfr_data_len;

    bool truncated; /* an AD structure's declared length ran past the data blob */
} ble_adv_report_t;

/* Legacy-PDU codes are the 0x02 Event_Type values 0x00..0x04
 * (§7.7.65.2). These two are sloth's own, outside that range, for a
 * 0x0D report whose Legacy bit is clear: an extended advertising PDU
 * (AUX_ADV_IND or its chain) and the scan response to one. */
#define BLE_EVT_EXT_ADV        0x05
#define BLE_EVT_EXT_SCAN_RSP   0x06

/* Event_Type bits 5-6 of a 0x0D report. 0x03 is reserved. */
#define BLE_EXT_DATA_COMPLETE   0x00
#define BLE_EXT_DATA_INCOMPLETE 0x01  /* more fragments to come */
#define BLE_EXT_DATA_TRUNCATED  0x02  /* incomplete, no more to come */

/* Address_Type 0xFF in a 0x0D report: an anonymous advertisement, no
 * AdvA. The parser zeroes `addr` for it, so every anonymous advertiser
 * a sensor hears is one row and one flood address, not a row per
 * whatever the Address field happened to hold. */
#define BLE_ADDR_ANONYMOUS     0xFF

/* The fixed fields of one 0x0D report, before its Data: Event_Type(2)
 * Address_Type Address(6) Primary_PHY Secondary_PHY Advertising_SID
 * TX_Power RSSI Periodic_Advertising_Interval(2) Direct_Address_Type
 * Direct_Address(6) Data_Length. */
#define BLE_EXT_REPORT_FIXED   24

/* Walks the AD structures (length, type, value) inside one advertising
 * report's Data field and fills in the AD-derived fields of `out`.
 * Does not touch the HCI-header fields (event_type/addr_type/addr/rssi) —
 * callers fill those separately. Never reads past `len`; a structure
 * whose declared length would overrun `len` sets `out->truncated` and
 * stops the walk, keeping whatever decoded before it. `out` must already
 * be zeroed (ble_hci_adv_walk() does this for its callers). */
void ble_ad_parse(const uint8_t *data, size_t len, ble_adv_report_t *out);

/* Per-report callback for ble_hci_adv_walk(). `report` is valid only for
 * the duration of the call. */
typedef void (*ble_report_cb_t)(const ble_adv_report_t *report, void *ctx);

/* Parses an HCI event buffer whose event code is HCI_EV_LE_Meta (0x3E)
 * and whose subevent code is LE Advertising Report (0x02). The reports
 * are consecutive records (above): Event_Type, Address_Type, Address[6],
 * Data_Length, Data[Data_Length], RSSI, then the next report. Every
 * record is bounds-checked, and together they must fill `len` exactly,
 * before any report is decoded, so a short, overlong or malformed buffer
 * decodes nothing rather than a prefix. `len` is the authority; the
 * parameter-length octet is the caller's to check. Calls `cb` once per
 * report, in order. Returns the number of reports decoded, or 0 for a
 * buffer that is too short or too long, the wrong event/subevent code,
 * or Num_Reports == 0. */
int ble_hci_adv_walk(const uint8_t *evt, size_t len, ble_report_cb_t cb, void *ctx);

/* The most reports one 0x0D event can carry (§7.7.65.13's range). */
#define BLE_EXT_REPORTS_MAX    10

/* Parses an HCI LE Meta event (0x3E) carrying an LE Extended
 * Advertising Report (subevent 0x0D, Core Specification v5.x Vol 4
 * Part E §7.7.65.13). `len` is the event as framed: event code,
 * parameter length, then exactly that many parameter octets.
 *
 * The reports are consecutive records (above), BLE_EXT_REPORT_FIXED
 * octets and then Data_Length octets each, and must fill the parameters
 * exactly: an overlong Data_Length, a header cut short or a trailing
 * octet decodes nothing, never a prefix. Per report, data status 0x03
 * (reserved) is refused, and a Legacy-bit report must be one of the six
 * legacy Event_Type values the clause lists (so data complete), carry
 * at most 31 octets, and say Primary_PHY LE 1M and Secondary_PHY 0x00
 * as the clause requires; its Advertising_SID is ignored and reads 0xFF.
 * One refused report refuses the event.
 *
 * Calls `cb` once per report, in order, only after every report has
 * decoded. Returns the number of reports, or 0 for a refused event,
 * Num_Reports == 0, a wrong event or subevent code, or a short buffer.
 * Never reads past `len`. */
int ble_hci_ext_adv_walk(const uint8_t *evt, size_t len,
                         ble_report_cb_t cb, void *ctx);

#endif /* BLE_SNOOP_H */
