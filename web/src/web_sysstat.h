/* slothweb: the sensor's host status and source inventory (2026-11-11,
 * docs/wiki/jsonl-schema.md "Host status and the source inventory").
 *
 * Fed from four record types sloth writes once a minute (JSONL 1.1.0,
 * src/sys_status.h): `sys_status` (CPU, load, memory, uptime, sloth's
 * RSS, the output filesystem, the hottest temperature, the
 * under-voltage alarm), `sys_sensor` (one temperature, voltage or
 * power-supply reading), `source_status` (one of sloth's sources,
 * configured or not) and `receiver_hw` (one attached receiver).
 *
 * Kept in memory only: the newest batch, replaced when a `sys_status`
 * with another `seq` arrives. A sensor or receiver that is not in the
 * newest batch is gone from the answer; a source row is updated in
 * place, because sloth also writes one on its own when its state
 * changes. Nothing here is in slothweb.db: the history is the series
 * below, in the store's existing tiers under their metric names, so
 * the store's version does not move.
 *
 * The series (web_rollup.c's table):
 *   sys.cpu, sys.mem_used, sys.rss, sys.undervolt   global
 *   sys.temp, sys.volt                              by sensor ("hottest"
 *                                                   is the hottest)
 *   source.rate, source.up                          by source name
 * One sample a minute, so the fine tier holds one bucket in six. The
 * keyed four are the "sys" key class (WEB_KC_SYS, 64 keys): sloth's
 * own bounded catalogue (36 sensors at most, 7 sources), established
 * from the first sample as the interface and channel classes are, and
 * never scored by the anomaly engine (a sensor warming up is not an
 * intrusion; no rule was asked for over it).
 *
 * Every string is the peer's. sloth reduces device strings to
 * printable ASCII, but the socket may be someone else's, so each is
 * kept only up to a JSON-output budget (sys_keep(): a byte that
 * web_jw_str() would write as six costs six), which bounds /api/sys at
 * its worst case with every slot full of '<'. The page writes them
 * with textContent.
 *
 * sloth's own state, so every scope's, as sensor_health is. With no
 * live stream (slothweb reading a copied sloth.db) nothing arrives and
 * /api/sys says "seen":false: sloth.db holds none of this. */
#ifndef SLOTHWEB_SYSSTAT_H
#define SLOTHWEB_SYSSTAT_H

#include <pthread.h>
#include <stddef.h>

#include "web_json.h"
#include "web_jsonl.h"
#include "web_rollup.h"

#define WEB_SYS_SENSORS  36      /* sloth: 16 temps, 16 volts, 4 supplies */
#define WEB_SYS_SOURCES  8       /* sloth: 7 */
#define WEB_SYS_HW       16
/* A report older than this many of its own intervals is stale. */
#define WEB_SYS_STALE_INTERVALS 3

typedef struct {
    int       used;
    char      cls[8];            /* "temp", "volt", "power" */
    char      id[25];
    char      key[WEB_KEY_MAX + 1];   /* the series key, "" when the id has none */
    char      label[49];
    int       has_val;
    double    val;
    int       alarm;             /* -1 absent */
    int       capacity;          /* -1 absent */
    char      status[25];
} web_sys_sensor_t;

typedef struct {
    int       used;
    char      name[25], kind[21], flag[33], state[17];
    char      detail[97], endpoint[65], hw[37], desc[57], driver[25];
    char      age_band[9], unit[17];
    int       has_age, has_count, has_rate, has_reconnects;
    long long age_s, count, errors, reconnects;
    double    rate;
    long long ts;                /* the row's own ts */
    long long rx_ms;             /* slothweb's monotonic clock when it arrived */
} web_sys_source_t;

typedef struct {
    int       used;
    char      key[37], kind[21], bus[9], id[13];
    char      desc[57], vendor[33], product[49], driver[25], ifaces[65];
    int       known;
} web_sys_hw_t;

typedef struct web_sys {
    pthread_mutex_t mu;
    int       seen;              /* a sys_status was read */
    long long ts, rx_ms, seq;      /* rx_ms: the monotonic clock at arrival */
    int       interval_s;
    int       has_cpu, has_load, has_mem, has_uptime, has_rss, has_disk;
    int       has_temp, undervolt;          /* undervolt: -1 absent */
    double    cpu_pct, iowait_pct, load1, load5, load15, temp_max_c;
    long long mem_total_kb, mem_avail_kb, uptime_s, rss_kb;
    long long disk_free_mb, disk_total_mb;
    char      cpu_band[13], mem_band[13], disk_band[13], temp_band[13];
    char      disk_for[9], temp_max_id[25];
    long long sensor_seq, hw_seq;
    web_sys_sensor_t sensors[WEB_SYS_SENSORS];
    web_sys_source_t sources[WEB_SYS_SOURCES];
    web_sys_hw_t     hw[WEB_SYS_HW];
    unsigned long records, rejected, overflow;
} web_sys_t;

int  web_sys_init(web_sys_t *y);
void web_sys_destroy(web_sys_t *y);

/* Every decoded record; the four types above apply, the rest return. */
void web_sys_record(web_sys_t *y, const web_jrec_t *r, long long now_ms);

/* The same four types into the rollup (web_metrics.c's one call). A
 * figure out of range is not sampled; an absent one is not a zero. */
void web_sys_metrics(web_rollup_t *ru, const web_jrec_t *r, long long now_s);

/* The "sys" key kind: 1..WEB_KEY_MAX bytes of [a-z0-9_.-] after
 * lower-casing and '/' to '.', so "hwmon1/temp2" is "hwmon1.temp2".
 * 0 with out filled, -1 when s has anything else. */
int  web_key_sys(const char *s, char *out);

/* Copy s into out (cap bytes) up to a JSON-output budget of cap - 1:
 * a byte web_jw_str() escapes to six costs six, a quote or backslash
 * two. Cut at a UTF-8 boundary. */
void web_sys_keep(char *out, size_t cap, const char *s);

/* /api/sys: the newest batch. No parameters; a 400 names an unknown
 * one. Answers under every scope. now_s is the wall clock (the "now"
 * member), now_ms the monotonic one web_sys_record() was given: an age
 * is the difference of two readings of that one clock, never a record's
 * ts against this host's wall clock (the sensor may be another machine,
 * and its ts is the peer's to choose). 0 with *len / *status set, -1
 * when the body did not fit. */
int  web_sys_route(web_sys_t *y, const char *query, long long now_s, long long now_ms,
                   char *body, size_t cap, size_t *len, int *status);

#endif /* SLOTHWEB_SYSSTAT_H */
