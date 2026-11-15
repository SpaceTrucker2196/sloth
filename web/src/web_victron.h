/* slothweb's Victron tab (2026-11-15, docs/wiki/victron.md): the owner's
 * Victron devices as sloth reports them off sloth-va's file, live from
 * the stream and over time from sloth.db.
 *
 * Live: sloth writes one change-only `victron_device` record per device
 * address (src/jsonl.c emit_victron_device()): on first sight, on a
 * change of victron_device_sig()'s bands and discrete facts, and on the
 * 300 s heartbeat; no "gone" record (sloth refuses a 17th address rather
 * than evicting). Plus the victron_* members of `sensor_health` while
 * sloth runs with --victron. Every field read here was read from that
 * emitter; docs/wiki/jsonl-schema.md says what each is.
 *
 * In memory only: WEB_VICTRON_ROWS rows keyed by address, the least
 * recently reported evicted and counted when a new one arrives. A row
 * with no record for WEB_VICTRON_TTL_S (two heartbeats and a margin) is
 * one sloth no longer keeps (it restarted without the flag, or without
 * that device): dropped and counted. A record whose first_seen differs
 * from the row's is sloth's new row for that address: it starts over.
 *
 * History: sloth.db's victron_devices and victron_readings (schema
 * v15), read through the M4 allow-list (web_slothdb.h) inside the
 * request budget. One device's one metric over a window, bucketed:
 *
 *   /api/victron?limit=          the sensor block and the devices, the
 *                                most recently heard first
 *   /api/victron/history?mac=&metric=&hours=
 *                                one metric of one device over the last
 *                                `hours` (1..WEB_VICTRON_HOURS_MAX,
 *                                default 24), at most
 *                                WEB_VICTRON_HIST_POINTS buckets of at
 *                                least DB_VICTRON_MIN_S (60 s), each its
 *                                mean, min and max and how many of its
 *                                rows were a GATT session's
 *
 * Staleness. sloth writes a device again on a banded change or the
 * 300 s heartbeat, so a live device's newest record can be 300 s old
 * with nothing wrong. A device is "stale" when the newest record's
 * last_seen is more than WEB_VICTRON_STALE_S behind now (one heartbeat
 * and a minute), or WEB_VICTRON_STALE_GATT_S for a device heard only
 * through GATT sessions (sloth-va's 300 s session interval on top).
 *
 * Scope: Monitor's and Hybrid's, the rtl_433 and APRS precedent (a radio
 * receiver's data, not the host's own interfaces'); Local answers
 * out_of_scope with the query checked. NOT in the fleet export, and the
 * importer refuses a peer's victron_device line (ADR 0009, fail closed):
 * the values of a GATT session came through an authenticated
 * connection, the record mixes both paths' values (sloth's merge is
 * sticky), and the owner has not classified the readout half.
 *
 * Every string is hostile: sloth-va's file could have been written by
 * another account. Each text member is held to sloth's own rule
 * (src/victron.c clean() and services_take()) and cap; a value only
 * under a name on sloth's allow-list and inside sloth's bound, absent
 * otherwise, never clamped. */
#ifndef SLOTHWEB_VICTRON_H
#define SLOTHWEB_VICTRON_H

#include <pthread.h>
#include <stddef.h>

#include "web_devices.h"
#include "web_json.h"
#include "web_jsonl.h"

/* sloth keeps VICTRON_MAX_DEVICES (16) rows; room for twice that while
 * a restarted sloth's old rows wait out their TTL. */
#define WEB_VICTRON_ROWS        32
#define WEB_VICTRON_VALS        16     /* sloth's allow-list */
#define WEB_VICTRON_SERIAL_MAX  23     /* victron_device_t.serial */
#define WEB_VICTRON_MODEL_MAX   31
#define WEB_VICTRON_RECORD_MAX  23
#define WEB_VICTRON_SESSION_MAX 23
#define WEB_VICTRON_SERVICES_MAX 400   /* VICTRON_SERVICES_MAX */
#define WEB_VICTRON_SRC_MAX     47     /* victron_health_t.src */
#define WEB_VICTRON_ERR_MAX     95
#define WEB_VICTRON_TTL_S       660
#define WEB_VICTRON_STALE_S     360
#define WEB_VICTRON_STALE_GATT_S 660
#define WEB_VICTRON_REJ_COUNT   5
/* A row's worst-case JSON: every text at its cap (none can need an
 * escape: sloth's charset), the services split, 16 values at their
 * widest. The list stops before a row that might not fit. */
#define WEB_VICTRON_ROW_WORST   3072
/* History: the window and the buckets. */
#define WEB_VICTRON_HOURS_MAX   720
#define WEB_VICTRON_HIST_POINTS 240
#define WEB_VICTRON_BUCKET_MIN  60     /* sloth's DB_VICTRON_MIN_S */

typedef struct {
    int       used;
    char      mac[18];
    long long ts;                     /* the newest record's ts */
    long long first_seen, last_seen, last_readout, last_gatt, readings, sessions;
    unsigned  records;
    char      serial[WEB_VICTRON_SERIAL_MAX + 1];
    char      model[WEB_VICTRON_MODEL_MAX + 1];
    char      record[WEB_VICTRON_RECORD_MAX + 1];
    char      session[WEB_VICTRON_SESSION_MAX + 1];
    char      services[WEB_VICTRON_SERVICES_MAX + 1];
    char      values_src[8];          /* "readout" / "gatt" / "" */
    int       has_rssi, rssi;
    int       has[WEB_VICTRON_VALS];
    double    v[WEB_VICTRON_VALS];
} web_victron_row_t;

typedef struct {
    int       seen;
    long long ts;
    char      state[12];     /* none / waiting / live / error, else "other" */
    char      src[WEB_VICTRON_SRC_MAX + 1];
    int       missing;
    long long last_read, last_rec, devices, bytes, lines, records, bad_lines;
    long long rej[WEB_VICTRON_REJ_COUNT];
    long long bad_values, other_keys, table_full, truncations, rotations, read_errors;
    char      err[WEB_VICTRON_ERR_MAX + 1];
} web_victron_sh_t;

typedef struct web_victron {
    pthread_mutex_t    mu;
    web_victron_row_t *rows;
    web_victron_sh_t   sh;
    char               src[WEB_VICTRON_SRC_MAX + 1];
    unsigned long      records, evictions, aged, rejected;
} web_victron_t;

int  web_victron_init(web_victron_t *a);
void web_victron_destroy(web_victron_t *a);

/* Every decoded record; victron_device and sensor_health apply, the
 * rest return. */
void web_victron_record(web_victron_t *a, const web_jrec_t *r, long long now_ms);

/* The value allow-list, sloth's (src/victron.c VALS[]): name i, its unit
 * ("" an enumeration), or NULL past the last; the index of a name, -1
 * off the list. web/tests/test_victron.c holds it to sloth.db's
 * victron_readings columns (src/db_schema.c db_victron_col()). */
const char *web_victron_val_name(int i);
const char *web_victron_val_unit(int i);
int         web_victron_val_index(const char *name);

/* /api/victron?limit=: 0 with *len / *status set, -1 when the body did
 * not fit. With none_here (Local) the query is checked and the caller
 * answers web_victron_out_of_scope_json() instead. */
int web_victron_route(web_victron_t *a, const char *query, long long now_s, int none_here,
                      char *body, size_t cap, size_t *len, int *status);
size_t web_victron_out_of_scope_json(char *body, size_t cap);

/* /api/victron/history?mac=&metric=&hours= (sloth.db), the M5 shape. */
int web_victron_history_route(const web_m4_t *m, const char *query, long long now_s,
                              char *body, size_t cap, size_t *len, int *status);

/* The /api/health member: counts only. */
void web_victron_health_json(web_victron_t *a, web_jw_t *w);

#endif /* SLOTHWEB_VICTRON_H */
