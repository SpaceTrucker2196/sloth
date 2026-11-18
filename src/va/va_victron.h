#ifndef VA_VICTRON_H
#define VA_VICTRON_H

#include <stddef.h>
#include <stdint.h>

/* sloth-va's pure half: Victron Instant Readout decode, the 6597 GATT
 * characteristics, the reading record and the name-to-serial match. No
 * I/O, no D-Bus; tested from hand-built bytes in tests/test_va.c.
 *
 * Sources (research/victron/README.md has the full list and what each
 * one establishes):
 *  [EMD]  Victron Energy, "Extra manufacturer data", wiki page
 *         rend:ble:extra_manufacturer_data, printed 2022-12-14 (the
 *         record header, the record types, AES-CTR with the 2-byte
 *         nonce, the key-check byte, every per-type bit layout).
 *  [VCS]  Victron staff, community thread "Victron Bluetooth BLE
 *         protocol publication" (mvader 2021-07-01/02; Thiemo van
 *         Engelen 2022-10-06, 2023-11-13): the 65970000 GATT service.
 *  [ADV]  Victron staff (Thiemo van Engelen) in the community thread on
 *         the Orion XS record: "the 3rd byte is 0x10" counting the
 *         company identifier, i.e. the first byte of the manufacturer
 *         data proper.
 *  [VEB]  keshavdv/victron-ble (community, read for its description and
 *         its published test vectors only; nothing copied): the
 *         product-advertisement header before the [EMD] record (two
 *         bytes, the model id, then the record) and the little-endian
 *         nonce in the first counter-block bytes, which an
 *         `openssl enc -aes-128-ctr` run on its vectors confirms. */

#define VA_VICTRON_COMPANY_ID 0x02E1u   /* Bluetooth SIG company identifier */
#define VA_PRODUCT_AD         0x10u     /* [ADV]: product advertisement */

/* [EMD] record types. */
enum {
    VA_REC_TEST = 0x00, VA_REC_SOLAR = 0x01, VA_REC_BATTERY_MONITOR = 0x02,
    VA_REC_INVERTER = 0x03, VA_REC_DCDC = 0x04, VA_REC_SMART_LITHIUM = 0x05,
    VA_REC_INVERTER_RS = 0x06, VA_REC_GX = 0x07, VA_REC_AC_CHARGER = 0x08,
    VA_REC_SMART_BP = 0x09, VA_REC_LYNX_BMS = 0x0A, VA_REC_MULTI_RS = 0x0B,
    VA_REC_VEBUS = 0x0C, VA_REC_DC_ENERGY_METER = 0x0D
};

typedef enum {
    VA_RO_OK = 0,           /* decoded; values[] holds what was present */
    VA_RO_UNDECODED,        /* decrypted, but no layout here for this record type */
    VA_RO_NOT_PRODUCT_AD,   /* first byte is not 0x10: not Instant Readout ([ADV]) */
    VA_RO_TRUNCATED,        /* shorter than the header and one ciphertext byte */
    VA_RO_KEY_MISMATCH      /* key-check byte differs: [EMD] says stop decoding */
} va_ro_status_t;

/* One decoded value. `name` and `unit` are static strings; `name`
 * carries the unit as its suffix too, so a reader of the JSONL never
 * guesses. `text` is a static name for an enumerated value, or NULL. */
typedef struct {
    const char *name;
    const char *unit;
    double      v;
    int         integer;      /* print as an integer */
    const char *text;
} va_value_t;

#define VA_MAX_VALUES 16

typedef struct {
    va_ro_status_t status;
    uint16_t   model_id;
    uint8_t    record_type;
    uint16_t   nonce;
    size_t     plain_len;      /* decrypted bytes, <= 16 used */
    int        nvals;
    va_value_t vals[VA_MAX_VALUES];
} va_readout_t;

/* Decode Instant Readout from the manufacturer-specific data `md` of
 * length `n`, the bytes after the 2-byte company identifier (BlueZ's
 * Device1.ManufacturerData value for key 0x02E1). `key` is the device's
 * 16-byte advertisement key. Every field is length-checked on its own,
 * as [EMD] requires: one past the end is absent, not zero. A value at
 * its NA code, or outside its documented range, is absent. */
va_ro_status_t va_readout_decode(const uint8_t *md, size_t n, const uint8_t key[16],
                                 va_readout_t *out);

/* Stable names, part of the victron JSONL contract. */
const char *va_record_type_name(int rec);     /* "battery_monitor", "dcdc_converter", ... */
const char *va_ro_status_name(va_ro_status_t s);
/* VE.Direct product id to a model name, NULL when not in the table. */
const char *va_model_name(uint16_t model_id);
/* VE_REG_DEVICE_STATE / VE.Direct "CS" to a name, NULL if unlisted. */
const char *va_device_state_name(int state);

/* Bits [start, start+nbits) of `buf` (LSB-first within each byte,
 * bytes in order: [EMD]'s numbering), nbits <= 32. 0 and *out set when
 * every bit is inside `len` bytes; -1 otherwise. */
int va_bits(const uint8_t *buf, size_t len, unsigned start, unsigned nbits, uint32_t *out);

/* ── 65970000 GATT service ([VCS]) ─────────────────────────────────── */

#define VA_GATT_SERVICE_UUID   "65970000-4bda-4c1e-af4b-551c4cf74769"
#define VA_GATT_KEEPALIVE_UUID "6597ffff-4bda-4c1e-af4b-551c4cf74769"

typedef enum { VA_T_U16, VA_T_S16, VA_T_S32 } va_gatt_type_t;

typedef struct {
    const char    *uuid;     /* lower case, full 128-bit */
    const char    *name;     /* value name, unit-suffixed */
    const char    *unit;
    va_gatt_type_t type;
    double         scale;
    int            has_na;
    uint32_t       na;       /* raw NA code, as the type's width */
} va_gatt_char_t;

/* The readable characteristics [VCS] lists, keep-alive excluded. */
extern const va_gatt_char_t va_gatt_chars[];
extern const int va_gatt_nchars;

/* The table row for `uuid` (case-insensitive), or NULL. */
const va_gatt_char_t *va_gatt_find(const char *uuid);

/* Decode one characteristic value. 1 and *v set when present; 0 when
 * the value is the NA code; -1 when `n` is not the type's width. */
int va_gatt_decode(const va_gatt_char_t *c, const uint8_t *b, size_t n, double *v);

/* The keep-alive value to write: [VCS] says 2 bytes, unsigned little
 * endian, milliseconds, write request; 0xFFFF disables the timer and is
 * refused here (staff advise against it). */
int va_gatt_keepalive(unsigned ms, uint8_t out[2]);

/* ── the record ────────────────────────────────────────────────────── */

typedef struct {
    const char  *source;      /* "readout" or "gatt" */
    long long    t;           /* unix seconds */
    uint8_t      mac[6];
    const char  *serial;      /* owner's serial, NULL when not mapped */
    const char  *label;       /* the device's own name (untrusted), or NULL */
    int          has_model;
    uint16_t     model_id;
    int          record_type; /* readout only; -1 otherwise */
    int          has_rssi;
    int          rssi;
    const char  *session;     /* gatt only: "ok", "no_supported_service", ... */
    const char  *services;    /* gatt only: comma-separated UUIDs, or NULL */
    int          nvals;
    const va_value_t *vals;
} va_record_t;

/* One JSONL line (with '\n') into buf. Returns its length, or -1 if
 * it would not fit (nothing partial is ever returned). Strings are
 * JSON-escaped; a label is also cut to 48 bytes. No key, PIN or raw
 * advertisement byte is a field of va_record_t, so none can be
 * written. */
int va_record_jsonl(const va_record_t *r, char *buf, size_t sz);

/* ── device names ──────────────────────────────────────────────────── */

/* 1 when `serial` appears in `name` as a whole token (bounded by the
 * string's ends or a character that is not [A-Za-z0-9]), comparing case
 * insensitively. Victron's default names carry the serial
 * ("SmartShunt HQ2121ABCDE"); a name the owner changed may not, and
 * then the device is not matched by name. */
int va_name_has_serial(const char *name, const char *serial);

/* "c7:fe:23:b1:1c:5f" (lower case) from 6 bytes in display order. */
void va_mac_str(const uint8_t mac[6], char out[18]);
/* Parse "C7:FE:23:B1:1C:5F" or BlueZ's "dev_C7_FE_23_B1_1C_5F" form
 * (any case); 0 on success. */
int va_mac_parse(const char *s, uint8_t mac[6]);

#endif /* VA_VICTRON_H */
