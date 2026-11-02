/* slothweb's BLE tables (owner request 2026-10-27, "add bluetooth to
 * the web ui"): the advertisers and the findings sloth's Bluetooth
 * receivers report, kept by slothweb itself.
 *
 * sloth.db has no BLE table, so the stream is the only source: the
 * `ble_device` record (one row per advertiser AS ONE SENSOR HEARD IT,
 * keyed addr + addr_type + iface: the host controller and an Ubertooth
 * hearing the same address are two rows, and their counts are never
 * summed), the `ble_alert` record (the structured companion of a
 * BLE_ADV_FLOOD / BLE_HID_UNEXPECTED / BLE_WATCHLIST finding, keyed by
 * sloth's alert key, standing until the `alert.resolve` of the same
 * key), and the Bluetooth members of `sensor_health` (the btmon_*
 * stream health, the ble_* decode counters and scan state, the btcap_*
 * Ubertooth block, the banded ble_rot_* hints). src/jsonl.c
 * jsonl_emit_ble_devices() / jsonl_emit_ble_alerts() and
 * docs/wiki/jsonl-schema.md say what each field is; every field read
 * here was read from the emitter.
 *
 * In memory: WEB_BLE_DEVICES rows, the least recently heard row with
 * neither a HID flag nor a watch category evicted and counted when a
 * new one arrives (the plain oldest only when every row is flagged), and
 * a row's adv_count and last_seen only ever moving up, as the store
 * keeps them; WEB_BLE_ALERTS findings, the
 * oldest resolved one evicted first; one copy of the latest
 * sensor_health's Bluetooth members. A row keeps the last WEB_BLE_PTS
 * (ts, adv_count) points of its own records, so the drawer can draw
 * the advertising rate between them without a per-address series in
 * the rollup (whose device class is 512 keys shared with the Wi-Fi
 * tables, and BLE addresses rotate: a resident random-address device is
 * a new key every fifteen minutes, which would churn that class and
 * evict the Wi-Fi devices' history). The rate is coarse, since the
 * record is change-only with a 300 s heartbeat and adv_count is not in
 * its signature, and the drawer says so.
 *
 * Persisted (web_store.h, slothweb.db v7): every row dirtied since the
 * last flush is upserted by the store thread each WEB_FLUSH_S
 * (web_tsdb.h), and on open the newest WEB_BLE_DEVICES rows and the
 * recent findings seed the tables, so a restart does not lose the
 * history. Retention is --web-retain-days, applied at compaction.
 *
 * Every string is hostile. The local name is a peer-chosen string: it
 * is kept in its display form (web_ssid.h: printable UTF-8 as it is,
 * every other octet as \xNN), cut at 32 octets' worth, flagged when
 * anything was escaped, and never a key. The sensor's iface, the
 * PDU name, the finding's kind, alert name, family, window, OUI table
 * and distance words are kept only when they match sloth's own closed
 * vocabularies (anything else is "other", counted); a watch category
 * is kept as sloth's slug (1..15 bytes of [a-z0-9_-]) or dropped. The
 * finding's key is kept for the resolve join and never rendered (the
 * web_live rule). No raw AD byte exists on the stream, and none is
 * stored. The distance is sloth's own estimate (src/rf_distance.c,
 * research/papers/rssi-distance-estimation.md): the four est_* fields
 * are shown as they came and never re-derived; absent means no
 * estimate, never 0.
 *
 * One mutex guards everything: the ingest thread writes, the store
 * thread takes the dirty rows, the HTTP thread reads. */
#ifndef SLOTHWEB_BLE_H
#define SLOTHWEB_BLE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_json.h"
#include "web_jsonl.h"

#define WEB_BLE_DEVICES    1024
#define WEB_BLE_ALERTS     128
#define WEB_BLE_PTS        16
/* A local name is at most 32 octets (BLE_DEV_NAME_MAX); the display
 * form is at most four bytes an octet. */
#define WEB_BLE_NAME_MAX   (32 * 4)
#define WEB_BLE_IFACE_MAX  23
#define WEB_BLE_CAT_MAX    15
#define WEB_BLE_KEY_MAX    95
#define WEB_BLE_SH_STR     32
#define WEB_BLE_SH_LIST    96
/* A finding re-emits on the 300 s heartbeat; one quiet for two of them
 * and a margin is no longer standing, whatever was missed. */
#define WEB_BLE_STAND_S    660
/* Resolved findings are listed for this long. */
#define WEB_BLE_RESOLVED_S 86400
/* The drawer's presence strip: a row's last day in quarter hours, a
 * bucket set when a record's last_seen falls in it. 96 bits a row (two
 * words and the newest bucket's index), kept and stored with the row,
 * so the strip costs no series and survives a restart. Coarse by
 * construction: the record is change-only with a 300 s heartbeat, so a
 * quiet bucket can be an unchanged advertiser whose heartbeat fell in
 * the next one. */
#define WEB_BLE_PRES_S     900
#define WEB_BLE_PRES_N     96

/* The sensor's interface: sloth's two names, or neither. */
enum { WEB_BLE_IF_MONITOR = 0, WEB_BLE_IF_UBERTOOTH, WEB_BLE_IF_OTHER,
       WEB_BLE_IF_COUNT };
/* The PDU names of src/ble_detect.c ble_adv_type_name(), in pdu_mask
 * bit order, then its "adv" for any other event type. */
enum { WEB_BLE_PDU_ADV_IND = 0, WEB_BLE_PDU_ADV_DIRECT_IND, WEB_BLE_PDU_ADV_SCAN_IND,
       WEB_BLE_PDU_ADV_NONCONN_IND, WEB_BLE_PDU_SCAN_RSP, WEB_BLE_PDU_EXT_ADV,
       WEB_BLE_PDU_EXT_SCAN_RSP, WEB_BLE_PDU_ADV, WEB_BLE_PDU_COUNT };
/* src/rf_distance.h rf_dist_band_t and rf_trend_t, by value; the P_tx
 * sources a BLE row can carry. */
enum { WEB_BLE_BAND_NONE = 0, WEB_BLE_BAND_IMMEDIATE, WEB_BLE_BAND_NEAR,
       WEB_BLE_BAND_ROOM, WEB_BLE_BAND_BUILDING, WEB_BLE_BAND_FAR, WEB_BLE_BAND_COUNT };
enum { WEB_BLE_TREND_UNKNOWN = 0, WEB_BLE_TREND_APPROACHING, WEB_BLE_TREND_STEADY,
       WEB_BLE_TREND_LEAVING, WEB_BLE_TREND_COUNT };
enum { WEB_BLE_PTX_EXT = 0, WEB_BLE_PTX_AD, WEB_BLE_PTX_ASSUMED, WEB_BLE_PTX_COUNT };
/* The finding kinds of src/ble_detect.c, and sloth's three alert types
 * (include/sloth_alerts.def, by name: never by number). */
enum { WEB_BLE_FIND_FLOOD = 0, WEB_BLE_FIND_HID_OUI, WEB_BLE_FIND_HID_ROTATE,
       WEB_BLE_FIND_WATCH, WEB_BLE_FIND_OTHER, WEB_BLE_FIND_COUNT };
enum { WEB_BLE_ALERT_FLOOD = 0, WEB_BLE_ALERT_HID, WEB_BLE_ALERT_WATCH,
       WEB_BLE_ALERT_OTHER, WEB_BLE_ALERT_COUNT };
enum { WEB_BLE_FAMILY_MFR = 0, WEB_BLE_FAMILY_SVC_DATA, WEB_BLE_FAMILY_OTHER };
enum { WEB_BLE_OUI_HAK5 = 0, WEB_BLE_OUI_ESPRESSIF, WEB_BLE_OUI_OTHER };

/* The vocabularies, for the page and the parity test. */
const char *web_ble_iface_name(int i);
const char *web_ble_pdu_name(int i);
const char *web_ble_band_name(int b);
const char *web_ble_band_short(int b);
const char *web_ble_trend_name(int t);
const char *web_ble_trend_glyph(int t);
const char *web_ble_ptx_name(int p);
const char *web_ble_ptx_short(int p);
const char *web_ble_kind_name(int k);
const char *web_ble_alert_name(int a);
const char *web_ble_family_name(int f);
const char *web_ble_oui_table_name(int o);
/* "P" public, "R" random, "p"/"r" the resolved identity forms, "?" (the
 * TUI's type_ch()). */
char        web_ble_type_ch(int addr_type);
/* The address in words, which the letter alone does not say for a
 * random address: its two most significant bits (Core v5.4 Vol 6 Part
 * B §1.3.2) make it "random static" (11), "random RPA" (01, a
 * resolvable private address that rotates), "random NRPA" (00) or
 * "random reserved" (10); "public", "resolved public" / "resolved
 * random" (the controller's identity forms), "anonymous" (255), or
 * "unknown". addr is in display order, most significant octet first. */
const char *web_ble_addr_kind(const uint8_t addr[6], int addr_type);

/* One advertiser row as the store keeps it (slothweb.db v7 ble_device);
 * also what seeds the table at start. Text is already in its display
 * form; est_dist_dm is decimetres, -1 for no estimate. */
typedef struct {
    char      addr[18];
    int       addr_type;
    char      iface[WEB_BLE_IFACE_MAX + 1];
    int       adapter, sampled, pdu_mask;
    char      name[WEB_BLE_NAME_MAX + 1];
    int       name_np, name_complete;
    int       uuid16, mfr_id, mfr_subtype, svc_data_uuid16, appearance, hid;
    int       tx_power, flags, rssi, rssi_best;
    long long adv_count;
    char      watch_category[WEB_BLE_CAT_MAX + 1];
    int       ext_adv, primary_phy, secondary_phy, adv_sid;
    long long first_seen, last_seen;
    int       est_dist_dm, est_band, est_trend, est_ptx;
    /* The presence strip: the newest bucket (last_seen / WEB_BLE_PRES_S)
     * and its 96 bits, bit i the bucket i before it (lo bits 0..63, hi
     * bits 64..95), as the store's signed integers. */
    long long pres_bucket, pres_lo, pres_hi;
} web_store_bdev_t;

/* One finding as the store keeps it (ble_alert): the key as a 16-digit
 * FNV-1a hash, never the key; the per-kind integers in eight generic
 * columns (n0..n7, al_to_row() in web_ble.c says which is which), the
 * one word of the kind in label, sloth's citation line for a flood in
 * detail. Everything al_json() renders and the drawer matches on is
 * here, so a seeded finding reads as the live one did. */
#define WEB_BLE_LABEL_MAX  63
#define WEB_BLE_DETAIL_MAX 159
#define WEB_BLE_NCOLS      8
typedef struct {
    char      key_hash[17];
    int       kind;                  /* WEB_BLE_FIND_* */
    char      alert[24];
    char      iface[WEB_BLE_IFACE_MAX + 1];
    int       sampled;
    long long first_ts, last_ts, resolved_ts;   /* resolved_ts -1 standing */
    long long n[WEB_BLE_NCOLS];
    int       rssi;                  /* median RSSI, 0 none */
    char      label[WEB_BLE_LABEL_MAX + 1];
    char      detail[WEB_BLE_DETAIL_MAX + 1];
} web_store_balert_t;

typedef struct {
    long long          ts;
    unsigned long long count;
} web_ble_pt_t;

typedef struct {
    int       used, dirty;
    uint8_t   addr[6];
    int       addr_type;
    int       iface;                 /* WEB_BLE_IF_* */
    int       adapter, sampled, channel, last_pdu, pdu_mask;
    char      name[WEB_BLE_NAME_MAX + 1];
    int       name_np, name_complete;
    int       uuid16, mfr_id, mfr_subtype, svc_data_uuid16, appearance, hid;
    int       tx_power;              /* -128 absent */
    int       flags;
    int       has_rssi, rssi, rssi_best;
    unsigned long long adv_count;
    char      watch_category[WEB_BLE_CAT_MAX + 1];
    int       ext_adv, primary_phy, secondary_phy, adv_sid;
    long long first_seen, last_seen;
    int       est_valid, est_dist_dm, est_band, est_trend, est_ptx;
    long long pres_bucket;           /* 0 none yet */
    uint64_t  pres[2];
    unsigned long long touched;
    web_ble_pt_t pts[WEB_BLE_PTS];
    int       npts, pt_head;
    unsigned long long records;
} web_ble_dev_t;

typedef struct {
    int       used, dirty, standing;
    char      key[WEB_BLE_KEY_MAX + 1];
    int       kind, alert, ty;
    int       iface, sampled;
    long long first_ts, last_ts, resolved_ts;
    /* adv_flood */
    int       adv_type, family, id, subtype, window, window_s;
    long long distinct, fresh, total;
    int       distinct_capped;
    double    rate;
    int       has_rssi, median_rssi;
    char      spam_source[WEB_BLE_DETAIL_MAX + 1];
    /* hid_oui */
    uint8_t   addr[6];
    int       addr_type, hid, appearance, oui_table;
    /* hid_rotate, watchlist */
    long long addrs;
    char      category[WEB_BLE_CAT_MAX + 1];
    unsigned long long seq;
} web_ble_alert_t;

/* The latest sensor_health's Bluetooth members, as they came; -1 and
 * "" where the record had none. */
typedef struct {
    int       seen;                  /* a sensor_health with btmon_iface was read */
    long long ts;
    char      btmon_iface[WEB_BLE_SH_STR + 1], btmon_err[WEB_BLE_SH_STR + 1];
    char      btmon_exit[WEB_BLE_SH_STR + 1], btmon_exit_detail[WEB_BLE_SH_STR + 1];
    int       btmon_open, btmon_running, btmon_stats_valid;
    long long btmon_recv, btmon_drop, btmon_ifdrop, btmon_last_frame_ts, btmon_stale_secs;
    long long ble_controllers, ble_devices, ble_records, ble_adv_reports;
    long long ble_ext_adv_undecoded, ble_ext_adv_reports, ble_ext_adv_fragments;
    long long ble_ext_adv_partial, ble_ext_trains_evicted, ble_records_ignored;
    long long ble_records_malformed, ble_host_commands, ble_index_records;
    char      ble_scan_mode[WEB_BLE_SH_STR + 1], ble_scan_filter[WEB_BLE_SH_STR + 1];
    int       ble_scan_accept_list, ble_scan_enabled;
    char      ble_own_tx[WEB_BLE_SH_STR + 1], ble_own_tx_kind[WEB_BLE_SH_STR + 1];
    char      ble_own_tx_on[WEB_BLE_SH_LIST + 1], ble_own_tx_asserted[WEB_BLE_SH_LIST + 1];
    long long ble_own_tx_count, ble_own_tx_secs;
    int       ble_own_tx_baseline;
    char      btcap_iface[WEB_BLE_SH_STR + 1], btcap_state[WEB_BLE_SH_STR + 1];
    char      btcap_err[WEB_BLE_SH_STR + 1], btcap_sampling[WEB_BLE_SH_STR + 1];
    long long btcap_dlt, btcap_refused_dlt, btcap_stale_secs, btcap_recv, btcap_drop;
    long long btcap_truncated, btcap_adv, btcap_scan_req, btcap_connect_ind;
    long long btcap_ext_adv_undecoded, btcap_data_pdus, btcap_other_pdus;
    long long btcap_bredr, btcap_bredr_iac, btcap_bredr_laps;
    int       rot_present;           /* --ble-rotation-hints is on */
    char      ble_rot_hints[WEB_BLE_SH_STR + 1], ble_rot_poisoned[WEB_BLE_SH_STR + 1];
    char      ble_rot_seam_evictions[WEB_BLE_SH_STR + 1];
    long long evict_ble_device, evict_bredr_lap, evict_ble_flood;
} web_ble_sh_t;

typedef struct {
    unsigned long long records, device_records, alert_records, resolves;
    unsigned long evictions, alert_evictions, evicted_dirty;
    unsigned long other_iface, other_word, name_escaped, bad_records;
    unsigned long seeded, seeded_alerts, redirtied;
    int           rows, alert_rows, standing, hid, watch;
} web_ble_stats_t;

typedef struct web_ble {
    pthread_mutex_t    mu;
    int                store_on;
    web_ble_dev_t     *dev;
    web_ble_alert_t   *al;
    web_ble_sh_t       sh;
    web_ble_stats_t    st;
    unsigned long long touch, seq;
} web_ble_t;

/* 0, or -1 (memory). store_on says whether dirty rows are taken. */
int  web_ble_init(web_ble_t *b, int store_on);
void web_ble_destroy(web_ble_t *b);

/* One decoded record (web_ingest.c one_line(), after the live state):
 * ble_device, ble_alert, alert.resolve and sensor_health are read, the
 * rest passed over. now_ms is the ingest clock, for the LRU. */
void web_ble_record(web_ble_t *b, const web_jrec_t *r, long long now_ms);

/* The store's seed (web_store_ble_load() -> here, before any thread
 * starts): a row as the store kept it, not dirty. 1 taken, 0 not. */
int  web_ble_seed(web_ble_t *b, const web_store_bdev_t *r);
int  web_ble_seed_alert(web_ble_t *b, const web_store_balert_t *r);

/* The dirty rows, cleared, into out (at most max). Store thread. */
size_t web_ble_take(web_ble_t *b, web_store_bdev_t *out, size_t max);
size_t web_ble_take_alerts(web_ble_t *b, web_store_balert_t *out, size_t max);

/* A write of what web_ble_take*() gave failed (web_store_ble_write()
 * -1, the transaction rolled back): those rows are dirty again, so the
 * next flush writes them, rather than clean in memory and stale on
 * disk until their next record. A row evicted since is skipped. */
void web_ble_redirty(web_ble_t *b, const web_store_bdev_t *rows, size_t n,
                     const web_store_balert_t *alerts, size_t na);

void web_ble_stats(web_ble_t *b, web_ble_stats_t *out);
/* What the seed restored, for main.c's start notice: "N advertisers and
 * M findings", each counted as web_ble_seed() / web_ble_seed_alert()
 * took it, never web_store_ble_load()'s sum of the two. */
void web_ble_restored(web_ble_t *b, char *out, size_t n);
/* A copy of the latest sensor_health's Bluetooth members. */
void web_ble_sensor(web_ble_t *b, web_ble_sh_t *out);

/* The routes (web_routes.c: Monitor and Hybrid serve them, Local is
 * out_of_scope there). Each renders its JSON body into body (cap
 * bytes) and sets *status; 0, or -1 when even an error did not fit.
 *   /api/ble?sort=&dir=&limit=&offset=&q=     the advertisers
 *   /api/ble/alerts                           the findings
 *   /api/ble/<addr>?type=&iface=              one row and what names it
 * check_only validates the query and renders nothing (a 200 of length
 * 0), for the router's out-of-scope answer. */
#define WEB_BLE_LIMIT     100
#define WEB_BLE_LIMIT_MAX 1024
int  web_ble_devices_route(web_ble_t *b, const char *query, long long now_s,
                           int check_only, char *body, size_t cap, size_t *len,
                           int *status);
int  web_ble_alerts_route(web_ble_t *b, const char *query, long long now_s,
                          int check_only, char *body, size_t cap, size_t *len,
                          int *status);
int  web_ble_device_route(web_ble_t *b, const char *path_addr, const char *query,
                          long long now_s, int check_only, char *body, size_t cap,
                          size_t *len, int *status);

/* /api/live's "ble" member (the object, no key) and /api/health's
 * (the counters and bounds). */
void web_ble_live_json(web_ble_t *b, web_jw_t *w, long long now_s);
void web_ble_health_json(web_ble_t *b, web_jw_t *w);

/* FNV-1a 64 of s as 16 lower-case hex digits into out[17]: the store's
 * key for a finding (never the key itself). */
void web_ble_key_hash(const char *s, char out[17]);

#endif
