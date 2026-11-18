/* slothweb's rtl_433 tab (#208, docs/wiki/rtl433.md): the sub-GHz
 * devices a local rtl_433 decodes (car TPMS, weather stations, remotes),
 * as sloth reports them, kept by slothweb from the stream.
 *
 * sloth writes one change-only `rtl433_device` record per (model, id)
 * (src/jsonl.c emit_rtl433_device()): on first sight, on a change of
 * rtl433_device_sig()'s bands, and on the 300 s heartbeat while sloth
 * keeps the row. There is no "gone" record - sloth retires nothing by
 * age, a row leaves its table only by eviction - plus the rtl433_*
 * members of `sensor_health` when sloth runs with --rtl433. Every field
 * read here was read from that emitter; docs/wiki/jsonl-schema.md says
 * what each is.
 *
 * In memory only: WEB_RTL433_ROWS devices keyed by (model, id), the
 * least recently reported evicted and counted when a new one arrives.
 * A row with no record for WEB_RTL433_TTL_S (two heartbeats and a
 * margin) is one sloth no longer keeps: dropped and counted. A record
 * whose first_seen differs from the row's is sloth's new row for that
 * key (evicted there and heard again): the row starts over.
 * slothweb never writes sloth.db.
 *
 * Scope: rtl_433's SDR is a passive receiver, as the ADS-B and APRS
 * decoders' are, so the records are Monitor's (web_scope.c); under
 * Local the route checks the query and answers out_of_scope. Not in
 * the fleet export (ADR 0009, fail closed: withheld until the owner
 * classifies it).
 *
 * Every string is hostile - anything in range can transmit a frame a
 * decoder accepts. Each text member is held to sloth's own rule
 * (src/rtl433.c clean_str(): 1..cap printable ASCII, no quote or
 * backslash) and sloth's cap; mic and mod to the three words each sloth
 * allows. A record without a usable model, id or first_seen is
 * rejected and counted. Every number is range checked against the
 * bound sloth's parser applies and absent outside, never clamped. A
 * temperature or pressure keeps the unit of the key it arrived under,
 * never converted; a record carrying two units of one reading is
 * ambiguous and leaves it absent. */
#ifndef SLOTHWEB_RTL433_H
#define SLOTHWEB_RTL433_H

#include <pthread.h>
#include <stddef.h>

#include "web_json.h"
#include "web_jsonl.h"

/* sloth keeps RTL433_MAX_DEVICES (256) rows; the ones it has evicted
 * stay here until their TTL, so room for twice that. */
#define WEB_RTL433_ROWS       512
#define WEB_RTL433_MODEL_MAX  32     /* sloth's RTL433_MODEL_MAX */
#define WEB_RTL433_ID_MAX     16     /* sloth's RTL433_ID_MAX */
#define WEB_RTL433_TYPE_MAX   16     /* sloth's RTL433_TYPE_MAX */
#define WEB_RTL433_SRC_MAX    47     /* sloth's rtl433_health_t.src */
#define WEB_RTL433_ERR_MAX    95     /* sloth's rtl433_health_t.err */
#define WEB_RTL433_TTL_S      660
/* A row's worst-case JSON (every text member at its cap, each byte a
 * six-byte escape, every number at its widest): the list stops before
 * a row that might not fit and says "cut". */
#define WEB_RTL433_ROW_WORST  2048

typedef struct {
    int       used;
    char      model[WEB_RTL433_MODEL_MAX + 1];
    char      id[WEB_RTL433_ID_MAX + 1];
    long long ts;                     /* the newest record's ts */
    long long first_seen, last_seen, msgs, other_keys;
    unsigned  records;
    char      dev_type[WEB_RTL433_TYPE_MAX + 1];
    char      subtype[WEB_RTL433_TYPE_MAX + 1];
    char      channel[WEB_RTL433_ID_MAX + 1];
    char      mic[12];                /* "CRC" / "CHECKSUM" / "PARITY" */
    char      mod[8];                 /* "ASK" / "FSK" / "LoRa" */
    int       protocol;               /* -1 absent */
    int       has_freq, has_freq2, has_rssi, has_snr, has_noise;
    int       has_battery, has_temp, has_humidity, has_pressure;
    double    freq_mhz, freq2_mhz, rssi, snr, noise;
    double    battery_ok, temp, humidity, pressure;
    char      temp_unit[2];           /* "C" / "F" */
    char      pres_unit[4];           /* "kPa" / "hPa" / "psi" */
} web_rtl433_row_t;

/* rtl_433's reject reasons, in sloth's order (rtl433_reject_name()). */
#define WEB_RTL433_REJ_COUNT 5

typedef struct {
    int       seen;
    long long ts;
    char      state[12];     /* none / waiting / live / error, else "other" */
    char      src[WEB_RTL433_SRC_MAX + 1];
    int       missing;
    long long last_read, last_msg, devices, bytes, lines, msgs, bad_lines;
    long long rej[WEB_RTL433_REJ_COUNT];
    long long bad_values, other_keys, evicted, truncations, rotations, read_errors;
    char      err[WEB_RTL433_ERR_MAX + 1];
} web_rtl433_sh_t;

typedef struct web_rtl433 {
    pthread_mutex_t   mu;
    web_rtl433_row_t *rows;
    web_rtl433_sh_t   sh;
    char              src[WEB_RTL433_SRC_MAX + 1];
    unsigned long     records, evictions, aged, rejected;
} web_rtl433_t;

int  web_rtl433_init(web_rtl433_t *a);
void web_rtl433_destroy(web_rtl433_t *a);

/* Every decoded record; rtl433_device and sensor_health apply, the rest
 * return. */
void web_rtl433_record(web_rtl433_t *a, const web_jrec_t *r, long long now_ms);

/* /api/rtl433?limit=: the sensor block and up to `limit` (default and
 * most WEB_RTL433_ROWS) devices, the most recently heard first, as many
 * as fit ("cut" when the buffer stopped the list). A 400 names an
 * unknown parameter or a bad value. With none_here (Local) the query is
 * checked and the caller answers web_rtl433_out_of_scope_json()
 * instead. 0 with *len / *status set, -1 when the body did not fit. */
int web_rtl433_route(web_rtl433_t *a, const char *query, long long now_s, int none_here,
                     char *body, size_t cap, size_t *len, int *status);
size_t web_rtl433_out_of_scope_json(char *body, size_t cap);

/* The /api/health member: counts only. */
void web_rtl433_health_json(web_rtl433_t *a, web_jw_t *w);

#endif /* SLOTHWEB_RTL433_H */
