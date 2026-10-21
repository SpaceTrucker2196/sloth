#ifndef BREDR_BB_H
#define BREDR_BB_H

#include <stddef.h>
#include <stdint.h>

/* Bluetooth BR/EDR baseband packets as ubertooth-rx writes them
 * (#144 slice 3): LINKTYPE_BLUETOOTH_BREDR_BB, DLT 255. Pure decode, no
 * libpcap, no state.
 *
 * The record is a 22-octet little-endian header (tcpdump.org
 * LINKTYPE_BLUETOOTH_BREDR_BB) and then, when flag 0x0020 says so, the
 * BR/EDR payload, which is never read:
 *
 *   0  RF channel (0..78)          8  LAP (24 bits) + reserved octet
 *   1  signal power (dBm)         12  reference LAP (24 bits)
 *   2  noise power (dBm)          15  reference UAP
 *   3  access code offenses       16  packet header (18 bits)
 *   4  payload transport / rate   20  flags (LE16)
 *   5  corrected header bits
 *   6  corrected payload bits (LE16, signed)
 *
 * ── LAP only ──
 *
 * What a receiver recovers from the air is the LAP: the 24 bits the
 * sync word of the access code is built from (Core Specification v5.4
 * Vol 2 Part B §6.3.3.1). The UAP is not in the access code or the
 * packet header; ubertooth-rx either works it out over many packets or
 * is told it. The NAP is in neither: the full BD_ADDR travels only in an
 * FHS payload (§6.5.1.4), which is never read here. So this decoder reports the LAP and nothing
 * that could be read as a BD_ADDR, and no vendor is looked up from it —
 * an OUI is the NAP and UAP, which a LAP does not contain.
 *
 * The Reference UAP field is what the OPERATOR configured into the
 * capture tool (ubertooth-rx -u). Flag 0x0080 means that configured
 * value was used for HEC and CRC checking — not that it was heard. It
 * is surfaced only as `ref_uap_configured` / `ref_uap`, never as an
 * observed UAP. */

#define BREDR_DLT_BB          255
#define BREDR_BB_HDR_LEN      22
#define BREDR_RF_CHANNELS     79

/* Flags, tcpdump.org LINKTYPE_BLUETOOTH_BREDR_BB. */
#define BREDR_F_SIGNAL_VALID   0x0002
#define BREDR_F_NOISE_VALID    0x0004
#define BREDR_F_REF_LAP_VALID  0x0010
#define BREDR_F_PAYLOAD        0x0020
#define BREDR_F_REF_UAP_VALID  0x0080

/* Reserved LAPs for inquiry access codes, Vol 2 Part B §1.2.1: GIAC
 * 0x9E8B33, LIAC 0x9E8B00, the block 0x9E8B00..0x9E8B3F reserved. */
#define BREDR_IAC_FIRST 0x9E8B00u
#define BREDR_IAC_LAST  0x9E8B3Fu
#define BREDR_GIAC      0x9E8B33u

typedef struct {
    uint8_t  rf_channel;          /* 0..78 */
    uint8_t  signal_valid;
    int8_t   signal_dbm;
    uint8_t  noise_valid;
    int8_t   noise_dbm;
    uint32_t lap;                 /* 24 bits, observed */
    uint8_t  iac;                 /* LAP is an inquiry access code */
    uint8_t  ref_lap_valid;       /* flag 0x0010 */
    uint32_t ref_lap;             /* operator-configured, 24 bits */
    uint8_t  ref_uap_configured;  /* flag 0x0080: the operator's UAP was used */
    uint8_t  ref_uap;             /* operator-configured, NOT observed */
    uint16_t flags;
    uint8_t  payload_present;     /* flag 0x0020; never read */
} bredr_bb_t;

/* 0 and *out filled; -1 for a record shorter than the header or an RF
 * channel outside 0..78 (*out zeroed). */
int bredr_bb_parse(const uint8_t *rec, size_t len, bredr_bb_t *out);

int bredr_lap_is_iac(uint32_t lap);

/* "LAP 9e8b33": the only form a BR/EDR device is ever printed in.
 * Always terminates `buf` when sz > 0. */
void bredr_lap_format(uint32_t lap, char *buf, size_t sz);

#endif /* BREDR_BB_H */
