#ifndef SLOTH_JSONL_INTERNAL_H
#define SLOTH_JSONL_INTERNAL_H

/* The JSONL writer's primitives, for the files that build records (#213).
 *
 * src/jsonl.c was one translation unit: the sink, the change-only cache,
 * the line builders and every emitter. Any reference to it linked all of
 * it, and the emitters reach nearly every capture module, so a daemon
 * with no capture (sloth-rf, ADR 0010) could not write a record without
 * linking libpcap. It is three files now:
 *
 *   src/jsonl_core.c   the sink, the cache, the builders below, the
 *                      alert and sensor records, jsonl_emit_fields() and
 *                      the sensor_health blocks both daemons write
 *   src/jsonl_rf.c     the GNSS, ADS-B, APRS, rtl_433 and Victron
 *                      records, their sensor_health blocks, and what
 *                      sloth-rf writes
 *   src/jsonl.c        the capture's records, `sloth`'s sensor_health
 *                      and jsonl_emit_state_snapshots()
 *
 * Private to those three: nothing else includes this, and the public
 * API stays src/jsonl.h. The builders were file statics; they are
 * external only because the emitters moved apart, so each has the
 * jsonl_ prefix a name in libsloth_core.a's symbol table needs, and the
 * short names the emitters have always used are macros over them. The
 * macros are why the 2,900 lines that stayed in src/jsonl.c did not
 * change. */

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"

#define FNV64_OFFSET         0xcbf29ce484222325ULL
#define FNV64_PRIME          0x100000001b3ULL

/* Snapshot event "kinds" — one per deduped emitter. */
enum { JD_PNL = 1, JD_SEQNUM, JD_SENSOR_HEALTH, JD_WIFI_REG,
       JD_BLE_DEVICE, JD_BLE_ALERT, JD_GNSS_FIX, JD_GNSS_SKY, JD_GNSS_SAT,
       JD_ADSB_AIRCRAFT, JD_APRS_STATION, JD_RTL433_DEVICE, JD_OWNERSHIP,
       JD_KARMA_SUSPECT, JD_HARVEST_STA, JD_HARVEST_CHAIN,
       JD_VICTRON_DEVICE, JD_WIFI_DF, JD_DF_RADIO };

/* Sized for the hostile worst case, not the typical one. Beacon and
 * PNL records carry attacker-chosen SSID / WPS strings that
 * json_escape can expand 6x (\u00YY): a beacon with every string
 * field full runs ~4.5 KiB, a PNL client with 16 probed SSIDs ~3.4
 * KiB. At the old 2048 a hostile AP overflowed the buffer. appendf
 * keeps any future overrun in bounds; this keeps it from truncating. */
#define LINEBUF 8192

int      jsonl_any_sink(void);
uint64_t jsonl_fnv1a(const void *data, size_t n, uint64_t h);
int      jsonl_changed(uint8_t kind, const void *key, size_t keylen,
                       uint64_t sig, time_t now);
void     jsonl_appendf(char *buf, int sz, int *off, const char *fmt, ...)
             __attribute__((format(printf, 4, 5)));
void     jsonl_escape(const char *s, char *out, int sz, int *off);
void     jsonl_emit_line(const char *line);
void     jsonl_kv_str(char *buf, int sz, int *off, const char *key, const char *val);
void     jsonl_kv_int(char *buf, int sz, int *off, const char *key, long long val);
void     jsonl_kv_double(char *buf, int sz, int *off, const char *key, double val);
void     jsonl_kv_mac(char *buf, int sz, int *off, const char *key,
                      const uint8_t mac[6]);
void     jsonl_start_obj(char *buf, int sz, int *off, const char *type, time_t ts);
void     jsonl_end_obj(char *buf, int sz, int *off);
/* ,"intel_pack":{"version":...,"hash":...} (#231), into a LINEBUF line. */
void     jsonl_intel_pack(char *buf, int *off);

#define any_sink    jsonl_any_sink
#define fnv1a       jsonl_fnv1a
#define appendf     jsonl_appendf
#define json_escape jsonl_escape
#define emit_line   jsonl_emit_line
#define kv_str      jsonl_kv_str
#define kv_int      jsonl_kv_int
#define kv_double   jsonl_kv_double
#define kv_mac      jsonl_kv_mac
#define start_obj   jsonl_start_obj
#define end_obj     jsonl_end_obj

/* ── sensor_health, in blocks (#213) ─────────────────────────────────
 *
 * The record is one per daemon, and a daemon writes the blocks it has
 * something to say in: `sloth` all of them (jsonl_emit_sensor_health(),
 * src/jsonl.c), sloth-rf the process, receiver and decoder ones
 * (jsonl_emit_sensor_health_rf(), src/jsonl_rf.c). Each block is
 * written by one function, so the two records cannot drift apart in a
 * member's name, order or format; the order of the blocks is each
 * emitter's own, and `sloth`'s is the order the record always had.
 *
 * The signature halves are the same split: a struct of states and
 * bands, filled by one function, embedded in each emitter's signature. */

typedef struct {
    /* --location / --gps (2026-10-27): the arbitration state, the
     * fix's age as a three-state bucket (never / within
     * gps.max_fix_age_s / older), and none/some bands for the
     * checksum and parse tallies and the error. Never the age in
     * seconds, the satellite count or HDOP: each moves every second
     * a receiver is talking, and would sign a line per tick. */
    int      gps_configured, gps_state, gps_age_bucket;
    int      gps_bad_any, gps_err_any;
    /* The sensor's position (2026-11-06): its source and its 0.01
     * degree cell (about 1.1 km), never the figure - a fix wanders
     * metres a second. The exact figure rides every line written
     * and the heartbeat refreshes it. */
    int      loc_src, loc_cell_lat, loc_cell_lon;
    /* GNSS observation (2026-11-02): the clock offset (its held
     * band), the mean C/N0 and the jamming indicator (sticky across
     * the TPVs gpsd omits it from) as bands only (src/gps.c
     * gps_*_band); the satellite counts move too often to sign. */
    int      gnss_time_off_band, gnss_cn0_band, gnss_jam_band;
} jsonl_sh_gnss_sig_t;

typedef struct {
    /* --adsb (#26 slice 1): the source's state (which already folds
     * its freshness: live within ADSB_STALE_S of the decoder's clock
     * last advancing, stale after), and none/some bands of the
     * tallies and the error. Never the age, the aircraft count, the
     * reads or the decoder's message count: each moves every
     * second the decoder is writing. */
    int      adsb_configured, adsb_state;
    int      adsb_read_err_any, adsb_parse_err_any, adsb_overflow_any;
    int      adsb_bad_any, adsb_err_any;
    /* --aprs: the source's state (waiting / live / error; a quiet
     * channel is live) and none/some bands of the tallies and the
     * error. Never the line, packet, byte or station counts, nor
     * last_read: each moves with every poll or packet. */
    int      aprs_configured, aprs_state, aprs_missing;
    int      aprs_read_err_any, aprs_bad_any, aprs_overflow_any;
    int      aprs_err_any;
    /* #204: the region (rare: it moves with the continent), the
     * mismatch and the silent flag. Never quiet_since: it moves with
     * every packet. */
    int      aprs_region, aprs_freq_mismatch, aprs_silent;
    /* --rtl433 (#208): the source's state (waiting / live / error;
     * a quiet band is live) and none/some bands of the tallies and
     * the error. Never the line, message, byte or device counts,
     * nor last_read: each moves with every poll or decode. */
    int      rtl433_configured, rtl433_state, rtl433_missing;
    int      rtl433_read_err_any, rtl433_bad_any, rtl433_evicted_any;
    int      rtl433_other_keys_any, rtl433_bad_values_any;
    int      rtl433_err_any;
    /* --victron: the same shape as rtl433's. */
    int      victron_configured, victron_state, victron_missing;
    int      victron_read_err_any, victron_bad_any, victron_full_any;
    int      victron_other_keys_any, victron_bad_values_any, victron_err_any;
} jsonl_sh_rf_sig_t;

/* src/jsonl_core.c. The caller has zeroed `o` (the signature is hashed
 * as bytes, padding included). */
void jsonl_sh_gnss_sig(const sloth_state_t *s, jsonl_sh_gnss_sig_t *o);
/* evictions, evict_<table>..., storage_failures. */
void jsonl_sh_evictions(char *buf, int *off, uint64_t evict_total,
                        int storage_fail);
/* tuned_count, tuned, socket_peer_refused, socket_clients, parse_faults,
 * parse_fault_<kind>..., the memory figures, libs. `libs` is the
 * caller's: which libraries a daemon loaded is the daemon's to say. */
void jsonl_sh_process(char *buf, int *off, unsigned long long socket_refused,
                      int socket_clients, const char *libs);
/* gps_*, gnss_*, loc_*: only with --location or --gps. */
void jsonl_sh_gps(char *buf, int *off, const sloth_state_t *s);
/* daemon, db_max_mb, jsonl_version: the record's last three members,
 * the last two in the places tests/test_jsonl.c pins. */
void jsonl_sh_tail(char *buf, int *off, const char *daemon, int db_cap_mb);

/* src/jsonl_rf.c. */
void jsonl_sh_rf_sig(const sloth_state_t *s, jsonl_sh_rf_sig_t *o);
void jsonl_sh_adsb(char *buf, int *off, const sloth_state_t *s);
void jsonl_sh_aprs(char *buf, int *off, const sloth_state_t *s);
void jsonl_sh_aprs_region(char *buf, int *off, const sloth_state_t *s);
void jsonl_sh_rtl433(char *buf, int *off, const sloth_state_t *s);
/* victron_*: only with --victron; after the rtl433 block. */
void jsonl_sh_victron(char *buf, int *off, const sloth_state_t *s);

#endif /* SLOTH_JSONL_INTERNAL_H */
