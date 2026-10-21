#ifndef BTLE_LL_H
#define BTLE_LL_H

#include <stddef.h>
#include <stdint.h>
#include "ble_snoop.h"

/* Bluetooth LE Link Layer packets as an Ubertooth captures them
 * (#144 slice 3). Pure decode: no libpcap, no state, no clock. The
 * stream framer in src/bt_stream.c hands records here, and so do the
 * tests and the fuzz target.
 *
 * Two record shapes, both carrying the over-the-air packet from the
 * Access Address on (no preamble):
 *
 *   DLT 256  LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR — a 10-octet
 *            little-endian pseudo-header (RF channel, signal power,
 *            noise power, access-address offenses, reference access
 *            address, flags) and then the LE packet.
 *   DLT 192  LINKTYPE_PPI whose inner link type is 251
 *            (LINKTYPE_BLUETOOTH_LE_LL): the PPI header is skipped by
 *            its own length and the LE packet follows. Its fields are
 *            not decoded, so channel and signal are unknown.
 *
 * The LE packet, Core Specification v5.4 Vol 6 Part B §2.1 and §2.3:
 * Access Address (4, LSO first), PDU header (2: PDU_Type b0-3, ChSel
 * b5, TxAdd b6, RxAdd b7; Length), payload, CRC (3).
 *
 * ── Trusted length ──
 *
 * The PDU header's Length octet is the transmitter's claim. The
 * Ubertooth delivers at most UBT_LE_PACKET_MAX octets of a packet
 * (DMA_SIZE, host/libubertooth/src/ubertooth_interface.h) and drops the
 * rest without saying so, and the record itself may be shorter still.
 * So the payload trusted is the smallest of the three, and a record
 * whose claim runs past it is marked `truncated`. Nothing is read past
 * the trusted length: no field, no AD structure, and no CRC — sloth
 * never checks the CRC and never reports one as valid, and ignores the
 * producer's CRC flags, because the octets a CRC covers past the
 * trusted length are not there to have been checked by anyone. */

#define BTLE_DLT_LL_PHDR   256
#define BTLE_DLT_LL        251
#define BTLE_DLT_PPI       192
#define BTLE_PHDR_LEN      10
#define BTLE_PPI_HDR_MIN   8
#define BTLE_AA_LEN        4
#define BTLE_PDU_HDR_LEN   2
#define BTLE_ADV_AA        0x8E89BED6u   /* Vol 6 Part B §2.1.2 */
/* Octets of an LE packet, from the Access Address, that an Ubertooth
 * delivers per packet: its 50-octet DMA buffer. */
#define UBT_LE_PACKET_MAX  50
#define BTLE_PAYLOAD_TRUST_MAX (UBT_LE_PACKET_MAX - BTLE_AA_LEN - BTLE_PDU_HDR_LEN)

/* PHDR flags (tcpdump.org LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR). Only
 * the two validity bits are read. */
#define BTLE_PHDR_SIGNAL_VALID 0x0002
#define BTLE_PHDR_NOISE_VALID  0x0004

/* Advertising physical channel PDU types, Vol 6 Part B §2.3. */
enum {
    BTLE_ADV_IND = 0, BTLE_ADV_DIRECT_IND = 1, BTLE_ADV_NONCONN_IND = 2,
    BTLE_SCAN_REQ = 3, BTLE_SCAN_RSP = 4, BTLE_CONNECT_IND = 5,
    BTLE_ADV_SCAN_IND = 6, BTLE_ADV_EXT_IND = 7, BTLE_AUX_CONNECT_RSP = 8
};

typedef enum {
    BTLE_V_MALFORMED = 0,  /* short, or a Length outside its PDU type's range */
    BTLE_V_ADV,            /* ADV_IND / DIRECT / NONCONN / SCAN_IND / SCAN_RSP */
    BTLE_V_SCAN_REQ,
    BTLE_V_CONNECT_IND,
    BTLE_V_EXT_ADV,        /* ADV_EXT_IND: counted, not decoded */
    BTLE_V_DATA,           /* not the advertising Access Address: not decoded */
    BTLE_V_OTHER           /* AUX_CONNECT_RSP, reserved types */
} btle_verdict_t;

/* CONNECT_IND LLData, Vol 6 Part B §2.3.3.1. */
typedef struct {
    uint32_t aa;           /* the connection's Access Address */
    uint32_t crc_init;     /* 24 bits */
    uint8_t  win_size;
    uint16_t win_offset, interval, latency, timeout;
    uint8_t  chm[5];       /* channel map, 37 bits used */
    uint8_t  hop;          /* low 5 bits of the last octet */
    uint8_t  sca;          /* high 3 bits of the last octet */
} btle_conn_ind_t;

typedef struct {
    /* Pseudo-header (DLT 256 only; has_phdr 0 for PPI). */
    uint8_t  has_phdr;
    uint8_t  rf_channel;       /* 0..39, (f - 2402 MHz) / 2 */
    int8_t   channel_index;    /* LL channel index, -1 unknown */
    uint8_t  signal_valid;
    int8_t   signal_dbm;
    uint8_t  noise_valid;
    int8_t   noise_dbm;
    uint16_t phdr_flags;
    /* LE packet. */
    uint32_t aa;
    uint8_t  pdu_type, chsel, txadd, rxadd;
    uint8_t  len_claimed;      /* PDU header Length */
    uint8_t  len_trusted;      /* payload octets read: <= claimed */
    uint8_t  truncated;        /* len_trusted < len_claimed */
    uint8_t  has_adva;
    uint8_t  adva[6];          /* as transmitted, LSO first */
    uint8_t  has_peer;         /* TargetA (DIRECT), ScanA (SCAN_REQ), InitA (CONNECT_IND) */
    uint8_t  peer[6];          /* LSO first */
    const uint8_t *data;       /* AdvData / ScanRspData, inside the trusted length */
    size_t   data_len;
    uint8_t  has_conn;
    btle_conn_ind_t conn;
} btle_pkt_t;

/* RF channel 0..39 to Link Layer channel index (Vol 6 Part B §1.4.1):
 * RF 0 → 37, RF 12 → 38, RF 39 → 39, the rest are data channels 0..36
 * in frequency order. -1 outside 0..39. */
int btle_rf_to_index(int rf);

/* Decode an LE packet (from the Access Address) of `len` octets.
 * Fills *out (zeroed first) and returns the verdict. */
btle_verdict_t btle_ll_parse(const uint8_t *pkt, size_t len, btle_pkt_t *out);

/* A DLT 256 record: the pseudo-header, then btle_ll_parse(). */
btle_verdict_t btle_phdr_record_parse(const uint8_t *rec, size_t len,
                                      btle_pkt_t *out);

/* A DLT 192 record: the PPI header, which must declare inner DLT 251
 * and a length inside the record, then btle_ll_parse(). */
btle_verdict_t btle_ppi_record_parse(const uint8_t *rec, size_t len,
                                     btle_pkt_t *out);

/* For a BTLE_V_ADV packet with an AdvA: the HCI-shaped report the
 * device table takes — address and type from AdvA/TxAdd, the HCI
 * Event_Type equivalent of the PDU type (Vol 4 Part E §7.7.65.2), RSSI
 * from the pseudo-header when valid, and the AD structures walked over
 * `data` only. Returns 0 when the packet carries no AdvA. */
int btle_adv_report(const btle_pkt_t *p, ble_adv_report_t *r);

#endif /* BTLE_LL_H */
