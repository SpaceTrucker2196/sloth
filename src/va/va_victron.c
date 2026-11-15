/* sloth-va's pure half; see va_victron.h for the sources [EMD], [VCS],
 * [ADV], [VEB] and [VED] (Victron, "VE.Direct Protocol" 3.32: the
 * product ids, the CS state and OR off-reason tables). */
#include "va/va_victron.h"
#include "va/va_aes.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* The product-advertisement header ahead of the [EMD] record:
 *   md[0]      0x10, product advertisement ([ADV])
 *   md[1]      one byte [VEB] reads as the second half of a 16-bit
 *              "prefix"; its meaning is not published, so it is skipped
 *   md[2..3]   VE.Direct product id, little endian ([VEB]; the values
 *              match [VED]'s PID table)
 *   md[4]      [EMD] record type          (record bit 0)
 *   md[5..6]   [EMD] nonce, LSB first     (record bits 8..23)
 *   md[7]      [EMD] byte 0 of the key    (record bits 24..31)
 *   md[8..]    ciphertext: [EMD] record bits 32 onward */
#define HDR_LEN   8
#define REC_BASE  4          /* md offset of the [EMD] record */

int va_bits(const uint8_t *buf, size_t len, unsigned start, unsigned nbits, uint32_t *out) {
    if (nbits == 0 || nbits > 32) return -1;
    if ((size_t)start + nbits > len * 8u) return -1;
    uint32_t v = 0;
    for (unsigned i = 0; i < nbits; i++) {
        unsigned b = start + i;
        if ((buf[b >> 3] >> (b & 7)) & 1u) v |= (uint32_t)1u << i;
    }
    *out = v;
    return 0;
}

static int32_t sext(uint32_t v, unsigned nbits) {
    if (nbits < 32 && (v >> (nbits - 1)) & 1u) v |= ~(uint32_t)0 << nbits;
    return (int32_t)v;
}

static void put(va_readout_t *r, const char *name, const char *unit, double v,
                int integer, const char *text) {
    if (r->nvals >= VA_MAX_VALUES) return;
    va_value_t *x = &r->vals[r->nvals++];
    x->name = name; x->unit = unit; x->v = v; x->integer = integer; x->text = text;
}

/* A field of the decrypted payload, by [EMD]'s record bit numbering
 * (the payload starts at record bit 32). 0 when absent: past the end,
 * or at the NA code when has_na. */
static int field(const va_readout_t *r, const uint8_t *p, unsigned start, unsigned nbits,
                 int has_na, uint32_t na, uint32_t *out) {
    if (va_bits(p, r->plain_len, start - 32u, nbits, out) != 0) return 0;
    if (has_na && *out == na) return 0;
    return 1;
}

/* [EMD] "Battery Monitor" (and the BMV-712's record). */
static void decode_battery_monitor(va_readout_t *r, const uint8_t *p) {
    uint32_t v;
    if (field(r, p, 32, 16, 1, 0xFFFF, &v)) put(r, "ttg_min", "min", v, 1, NULL);
    if (field(r, p, 48, 16, 1, 0x7FFF, &v)) put(r, "voltage_v", "V", sext(v, 16) * 0.01, 0, NULL);
    if (field(r, p, 64, 16, 0, 0, &v))      put(r, "alarm_reason", "", v, 1, NULL);
    uint32_t aux, mode;
    int have_aux = field(r, p, 80, 16, 0, 0, &aux);
    if (field(r, p, 96, 2, 1, 0x3, &mode)) {
        static const char *const names[] = { "aux_voltage", "mid_voltage", "temperature" };
        put(r, "aux_input", "", mode, 1, names[mode]);
        if (have_aux) {
            if (mode == 0)      put(r, "aux_voltage_v", "V", sext(aux, 16) * 0.01, 0, NULL);
            else if (mode == 1) put(r, "mid_voltage_v", "V", aux * 0.01, 0, NULL);
            else                put(r, "temperature_c", "C", aux * 0.01 - 273.15, 0, NULL);
        }
    } else if (va_bits(p, r->plain_len, 96 - 32, 2, &mode) == 0) {
        put(r, "aux_input", "", 3, 1, "none");
    }
    if (field(r, p, 98, 22, 1, 0x3FFFFF, &v)) put(r, "current_a", "A", sext(v, 22) * 0.001, 0, NULL);
    /* [EMD]: "Consumed Ah = -Record value". */
    if (field(r, p, 120, 20, 1, 0xFFFFF, &v)) put(r, "consumed_ah", "Ah", -(double)v * 0.1, 0, NULL);
    /* Range 0 .. 100.0 %: a raw value above 1000 is out of range and is
     * left absent, never clamped. */
    if (field(r, p, 140, 10, 1, 0x3FF, &v) && v <= 1000) put(r, "soc_pct", "%", v * 0.1, 0, NULL);
}

/* [EMD] "DC/DC Converter" (the Orion Smart's record). */
static void decode_dcdc(va_readout_t *r, const uint8_t *p) {
    uint32_t v;
    if (field(r, p, 32, 8, 1, 0xFF, &v))     put(r, "device_state", "", v, 1, va_device_state_name((int)v));
    if (field(r, p, 40, 8, 1, 0xFF, &v))     put(r, "charger_error", "", v, 1, NULL);
    if (field(r, p, 48, 16, 1, 0xFFFF, &v))  put(r, "input_v", "V", v * 0.01, 0, NULL);
    if (field(r, p, 64, 16, 1, 0x7FFF, &v))  put(r, "output_v", "V", sext(v, 16) * 0.01, 0, NULL);
    if (field(r, p, 80, 32, 0, 0, &v))       put(r, "off_reason", "", v, 1, NULL);
}

va_ro_status_t va_readout_decode(const uint8_t *md, size_t n, const uint8_t key[16],
                                 va_readout_t *out) {
    memset(out, 0, sizeof(*out));
    if (n < 1) return out->status = VA_RO_TRUNCATED;
    if (md[0] != VA_PRODUCT_AD) return out->status = VA_RO_NOT_PRODUCT_AD;
    if (n < HDR_LEN + 1) return out->status = VA_RO_TRUNCATED;
    out->model_id    = (uint16_t)(md[2] | (md[3] << 8));
    out->record_type = md[REC_BASE];
    out->nonce       = (uint16_t)(md[REC_BASE + 1] | (md[REC_BASE + 2] << 8));
    /* [EMD]: when the byte does not match, "the device should stop
     * trying to decode the advertisement". Nothing is decrypted. */
    if (md[REC_BASE + 3] != key[0]) return out->status = VA_RO_KEY_MISMATCH;

    /* [EMD]: records of 16 bytes or less take one AES operation, true
     * of every record; a longer one (a future extension) is decoded
     * over its first 16 bytes, the fields here all lie inside them.
     * Counter block: the nonce LSB first, then zeros ([VEB], checked
     * against its vectors with openssl). */
    size_t clen = n - HDR_LEN;
    if (clen > 16) clen = 16;
    uint8_t ctr[16] = { 0 };
    ctr[0] = (uint8_t)(out->nonce & 0xFF);
    ctr[1] = (uint8_t)(out->nonce >> 8);
    uint8_t plain[16];
    va_aes128_t aes;
    va_aes128_init(&aes, key);
    va_aes128_ctr(&aes, ctr, md + HDR_LEN, plain, clen);
    va_wipe(&aes, sizeof(aes));
    out->plain_len = clen;

    switch (out->record_type) {
    case VA_REC_BATTERY_MONITOR: decode_battery_monitor(out, plain); out->status = VA_RO_OK; break;
    case VA_REC_DCDC:            decode_dcdc(out, plain);            out->status = VA_RO_OK; break;
    default:                     out->status = VA_RO_UNDECODED; break;
    }
    va_wipe(plain, sizeof(plain));
    return out->status;
}

const char *va_record_type_name(int rec) {
    switch (rec) {
    case VA_REC_TEST:             return "test";
    case VA_REC_SOLAR:            return "solar_charger";
    case VA_REC_BATTERY_MONITOR:  return "battery_monitor";
    case VA_REC_INVERTER:         return "inverter";
    case VA_REC_DCDC:             return "dcdc_converter";
    case VA_REC_SMART_LITHIUM:    return "smart_lithium";
    case VA_REC_INVERTER_RS:      return "inverter_rs";
    case VA_REC_GX:               return "gx_device";
    case VA_REC_AC_CHARGER:       return "ac_charger";
    case VA_REC_SMART_BP:         return "smart_battery_protect";
    case VA_REC_LYNX_BMS:         return "lynx_smart_bms";
    case VA_REC_MULTI_RS:         return "multi_rs";
    case VA_REC_VEBUS:            return "ve_bus";
    case VA_REC_DC_ENERGY_METER:  return "dc_energy_meter";
    default:                      return "unknown";
    }
}

const char *va_ro_status_name(va_ro_status_t s) {
    switch (s) {
    case VA_RO_OK:             return "ok";
    case VA_RO_UNDECODED:      return "undecoded";
    case VA_RO_NOT_PRODUCT_AD: return "not_product_ad";
    case VA_RO_TRUNCATED:      return "truncated";
    case VA_RO_KEY_MISMATCH:   return "key_mismatch";
    }
    return "unknown";
}

const char *va_model_name(uint16_t id) {
    switch (id) {
    /* [VED] PID table. */
    case 0xA381: return "BMV-712 Smart";
    case 0xA382: return "BMV-710H Smart";
    case 0xA383: return "BMV-712 Smart Rev2";
    case 0xA389: return "SmartShunt 500A/50mV";
    case 0xA38A: return "SmartShunt 1000A/50mV";
    case 0xA38B: return "SmartShunt 2000A/50mV";
    case 0xA3F0: return "Orion XS 12V/12V-50A";
    /* [VEB] only: not in [VED] (no VE.Direct port on the Orion Smart). */
    case 0xA3C0: return "Orion Smart 12V/12V-18A";
    default:     return NULL;
    }
}

const char *va_device_state_name(int s) {
    /* [VED] "CS" table. */
    switch (s) {
    case 0:   return "off";
    case 1:   return "low_power";
    case 2:   return "fault";
    case 3:   return "bulk";
    case 4:   return "absorption";
    case 5:   return "float";
    case 6:   return "storage";
    case 7:   return "equalize_manual";
    case 9:   return "inverting";
    case 11:  return "power_supply";
    case 245: return "starting_up";
    case 246: return "repeated_absorption";
    case 247: return "auto_equalize";
    case 248: return "battery_safe";
    case 252: return "external_control";
    default:  return NULL;
    }
}

/* ── 65970000 GATT service ── */

const va_gatt_char_t va_gatt_chars[] = {
    /* [VCS] table, mvader 2021-07-02. */
    { "6597ed8d-4bda-4c1e-af4b-551c4cf74769", "voltage_v",   "V",  VA_T_S16, 0.01,  1, 0x7FFF },
    { "6597ed8c-4bda-4c1e-af4b-551c4cf74769", "current_a",   "A",  VA_T_S32, 0.001, 1, 0x7FFFFFFF },
    { "6597ed8e-4bda-4c1e-af4b-551c4cf74769", "power_w",     "W",  VA_T_S16, 1.0,   1, 0x7FFF },
    { "6597eeff-4bda-4c1e-af4b-551c4cf74769", "consumed_ah", "Ah", VA_T_S32, 0.1,   0, 0 },
    { "65970fff-4bda-4c1e-af4b-551c4cf74769", "soc_pct",     "%",  VA_T_U16, 0.01,  1, 0xFFFF },
};
const int va_gatt_nchars = (int)(sizeof(va_gatt_chars) / sizeof(va_gatt_chars[0]));

static int ieq(const char *a, const char *b) {
    for (; *a && *b; a++, b++)
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    return *a == *b;
}

const va_gatt_char_t *va_gatt_find(const char *uuid) {
    if (!uuid) return NULL;
    for (int i = 0; i < va_gatt_nchars; i++)
        if (ieq(uuid, va_gatt_chars[i].uuid)) return &va_gatt_chars[i];
    return NULL;
}

int va_gatt_decode(const va_gatt_char_t *c, const uint8_t *b, size_t n, double *v) {
    size_t want = c->type == VA_T_S32 ? 4 : 2;
    if (n != want) return -1;
    uint32_t raw = b[0] | ((uint32_t)b[1] << 8);
    if (want == 4) raw |= ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    if (c->has_na && raw == c->na) return 0;
    switch (c->type) {
    case VA_T_U16: *v = raw * c->scale; break;
    case VA_T_S16: *v = (int16_t)(uint16_t)raw * c->scale; break;
    case VA_T_S32: *v = (double)(int32_t)raw * c->scale; break;
    }
    return 1;
}

int va_gatt_keepalive(unsigned ms, uint8_t out[2]) {
    if (ms == 0 || ms >= 0xFFFFu) return -1;
    out[0] = (uint8_t)(ms & 0xFF);
    out[1] = (uint8_t)(ms >> 8);
    return 0;
}

/* ── the record ── */

typedef struct { char *b; size_t sz, off; int err; } sb_t;

static void sb_raw(sb_t *s, const char *t, size_t n) {
    if (s->err || s->off + n >= s->sz) { s->err = 1; return; }
    memcpy(s->b + s->off, t, n);
    s->off += n;
    s->b[s->off] = '\0';
}
static void sb_puts(sb_t *s, const char *t) { sb_raw(s, t, strlen(t)); }
static void sb_fmt(sb_t *s, const char *fmt, double v) {
    char tmp[64];
    int k = snprintf(tmp, sizeof(tmp), fmt, v);
    if (k < 0 || (size_t)k >= sizeof(tmp)) { s->err = 1; return; }
    sb_raw(s, tmp, (size_t)k);
}
/* JSON string (RFC 8259 §7), at most `max` input bytes; control bytes
 * and non-ASCII are written as \u00XX so a hostile name cannot break
 * the line or smuggle invalid UTF-8 through. */
static void sb_str(sb_t *s, const char *t, size_t max) {
    sb_raw(s, "\"", 1);
    for (size_t i = 0; i < max && t[i]; i++) {
        unsigned char c = (unsigned char)t[i];
        char e[8];
        if (c == '"' || c == '\\') { e[0] = '\\'; e[1] = (char)c; sb_raw(s, e, 2); }
        else if (c < 0x20 || c >= 0x7F) { snprintf(e, sizeof(e), "\\u%04x", c); sb_raw(s, e, 6); }
        else sb_raw(s, (const char *)&c, 1);
    }
    sb_raw(s, "\"", 1);
}

int va_record_jsonl(const va_record_t *r, char *buf, size_t sz) {
    sb_t s = { buf, sz, 0, 0 };
    if (sz == 0) return -1;
    buf[0] = '\0';
    char mac[18];
    va_mac_str(r->mac, mac);
    sb_puts(&s, "{\"type\":\"victron\",\"t\":");
    sb_fmt(&s, "%.0f", (double)r->t);
    sb_puts(&s, ",\"source\":"); sb_str(&s, r->source, 16);
    sb_puts(&s, ",\"mac\":");    sb_str(&s, mac, 17);
    sb_puts(&s, ",\"serial\":");
    if (r->serial) sb_str(&s, r->serial, 24); else sb_puts(&s, "null");
    if (r->label) { sb_puts(&s, ",\"label\":"); sb_str(&s, r->label, 48); }
    if (r->has_model) {
        char id[8];
        snprintf(id, sizeof(id), "0x%04x", r->model_id);
        sb_puts(&s, ",\"model_id\":"); sb_str(&s, id, 6);
        const char *m = va_model_name(r->model_id);
        if (m) { sb_puts(&s, ",\"model\":"); sb_str(&s, m, 48); }
    }
    if (r->record_type >= 0) {
        sb_puts(&s, ",\"record\":"); sb_str(&s, va_record_type_name(r->record_type), 32);
    }
    if (r->has_rssi) { sb_puts(&s, ",\"rssi\":"); sb_fmt(&s, "%.0f", (double)r->rssi); }
    if (r->session)  { sb_puts(&s, ",\"session\":"); sb_str(&s, r->session, 32); }
    if (r->services) { sb_puts(&s, ",\"services\":"); sb_str(&s, r->services, 400); }
    sb_puts(&s, ",\"values\":{");
    for (int i = 0; i < r->nvals; i++) {
        const va_value_t *v = &r->vals[i];
        if (i) sb_puts(&s, ",");
        sb_str(&s, v->name, 32);
        sb_puts(&s, ":");
        if (v->integer) sb_fmt(&s, "%.0f", v->v);
        else            sb_fmt(&s, "%.3f", v->v);
        if (v->text) {
            /* An enumerated value's name rides beside it, never instead. */
            char k[48];
            snprintf(k, sizeof(k), "%s_name", v->name);
            sb_puts(&s, ",");
            sb_str(&s, k, 47);
            sb_puts(&s, ":");
            sb_str(&s, v->text, 32);
        }
    }
    sb_puts(&s, "}}\n");
    if (s.err) { buf[0] = '\0'; return -1; }
    return (int)s.off;
}

/* ── names and addresses ── */

int va_name_has_serial(const char *name, const char *serial) {
    if (!name || !serial) return 0;
    size_t n = strlen(name), k = strlen(serial);
    if (k == 0 || k > n) return 0;
    for (size_t i = 0; i + k <= n; i++) {
        if (i > 0 && isalnum((unsigned char)name[i - 1])) continue;
        if (i + k < n && isalnum((unsigned char)name[i + k])) continue;
        size_t j = 0;
        while (j < k && tolower((unsigned char)name[i + j]) == tolower((unsigned char)serial[j])) j++;
        if (j == k) return 1;
    }
    return 0;
}

void va_mac_str(const uint8_t m[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int va_mac_parse(const char *s, uint8_t mac[6]) {
    if (!s) return -1;
    if (!strncmp(s, "dev_", 4)) s += 4;
    for (int i = 0; i < 6; i++) {
        int hi = hexv((unsigned char)s[0]), lo = hi < 0 ? -1 : hexv((unsigned char)s[1]);
        if (hi < 0 || lo < 0) return -1;
        mac[i] = (uint8_t)(hi << 4 | lo);
        s += 2;
        if (i < 5) {
            if (*s != ':' && *s != '_') return -1;
            s++;
        }
    }
    return *s == '\0' ? 0 : -1;
}
