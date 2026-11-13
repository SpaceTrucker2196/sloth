/* slothweb: the KARMA and key-harvest evidence, as sloth reports it
 * (#187, #172; docs/wiki/jsonl-schema.md "Credential lures").
 *
 * sloth writes three change-only records off the tables its rules read
 * (JSONL 1.3.0): `karma_suspect` per [y] row (a BSSID beacon-fanning
 * past karma.ssid_thresh, or answering directed probes for names it
 * never beaconed), `harvest_station` per station with an M1 left
 * unanswered, and `harvest_chain` per BSSID whose claimed deauths were
 * followed by a victim's fresh M1/M2. Each row is written when its
 * counts move and on the 300 s heartbeat, and once as `"state":"gone"`
 * when it leaves sloth's table. The alert says a rule fired; these say
 * what it counted, which is what the WiFi view's card shows.
 *
 * Kept here in memory, newest record per key, bounded at sloth's own
 * table sizes. A row sloth retires goes at once; a row not refreshed
 * for two heartbeats and a minute (a sloth that stopped, or restarted
 * without it) is left out of answers, never shown as current.
 *
 * "None" is told from "not known": sloth writes nothing while its
 * tables are empty, so an empty card means something only from a
 * stream that writes these records at all. The stream's contract
 * version (`jsonl_version` on `sensor_health`) is kept for that: from
 * 1.3.0 an empty table is "none", before it "this sloth does not report
 * these", and with no sensor_health yet "not known".
 *
 * A record past the bounds below, with a malformed member, or for a
 * new key when the table is full is refused whole and counted. Strings
 * (an SSID, a tool name) leave only through web_jw_str(). The monitor
 * radio's, so Monitor's and Hybrid's (web_scope.h); /api/lures answers
 * out_of_scope under Local.
 *
 * One BSSID's KARMA detail (/api/lures/bssid, #187), from three more
 * things the stream says about it, each kept here bounded:
 *   - its karma_suspect rows over time: a change entry per record whose
 *     counts or strings moved (a heartbeat that repeats the last one
 *     only stretches it), the newest WEB_LURE_HIST per BSSID for
 *     WEB_LURE_DET BSSIDs, kept past sloth's `gone` (the detail says
 *     when it left the table) and given up, least recently written
 *     first, only to a new BSSID;
 *   - the #151 hardware verdict, `hw_verdict` / `hw_signals`, as the
 *     newest KARMA_AP record for it (key "karma:<bssid>") carries them:
 *     the field absent is "no verdict", which a later record may say;
 *   - the probe-response latency a `beacon` carries as `probe_lat`
 *     (JSONL 1.6.0, #187 S3; web_jsonl.h keeps the object's scalars),
 *     the newest per BSSID for WEB_LURE_LAT BSSIDs: an observation
 *     sloth puts in no verdict, and neither does slothweb. A beacon
 *     without the member drops what was held (sloth has not measured it
 *     on this run).
 * The alerts are web_live's incidents of KARMA_AP and KARMA_PROBE_FORGE
 * whose key names the BSSID at its field ("karma:<bssid>",
 * "karmaforge:<bssid>"), never as a substring: the open ones and the
 * recently closed the stream still holds, by slothweb's handle, which
 * is the alert page's id. */
#ifndef SLOTHWEB_LURE_H
#define SLOTHWEB_LURE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_json.h"
#include "web_jsonl.h"
#include "web_live.h"

#define WEB_LURE_KARMA   64     /* sloth: MAX_KARMA_APS */
#define WEB_LURE_STA     32     /* sloth: HARVEST_MAX_STA */
#define WEB_LURE_CHAIN   16     /* sloth: HARVEST_MAX_CHAIN */
/* Two of sloth's 300 s heartbeats and a minute. */
#define WEB_LURE_STALE_MS (660LL * 1000)
/* An SSID decoded from 32 octets that were not UTF-8 is three octets a
 * byte (U+FFFD); a tool attribution is sloth's 47. */
#define WEB_LURE_SSID_MAX 96
#define WEB_LURE_TOOL_MAX 47
/* The largest count any member may carry: sloth's are bounded by its
 * tables (8 SSIDs of history, 16 targets, 8 victims), so this only
 * keeps a malformed record's numbers out of the page. */
#define WEB_LURE_COUNT_MAX 1000000

/* The KARMA detail's bounds (#187). */
#define WEB_LURE_HIST    16     /* change entries per BSSID */
#define WEB_LURE_DET     64     /* BSSIDs with a detail: MAX_KARMA_APS */
#define WEB_LURE_LAT     256    /* BSSIDs with a probe_lat */
#define WEB_LURE_ALERTS  16     /* incidents listed per BSSID */
/* `suspected-pineapple-mk7`, `tool+stack+pair+oui`: sloth's words, at
 * most this long, [a-z0-9-] and [a-z+] only. */
#define WEB_LURE_HW_MAX  47
/* A latency in µs: a pair is one dwell, so ten seconds is past any. */
#define WEB_LURE_LAT_MAX 10000000LL

enum { WEB_LURE_K_KARMA, WEB_LURE_K_STA, WEB_LURE_K_CHAIN, WEB_LURE_KINDS };

/* One change of a karma_suspect row: the counts and strings it carried
 * from ts (the first record saying so) to ts_last (the newest). */
typedef struct {
    long long ts, ts_last;
    long long ssids, ie_postures, ie_collapsed, forged, forge_stations,
              pnl_best, lure_chain, score, last_seen;
    char      top_ssid[WEB_LURE_SSID_MAX + 1];
    char      tool[WEB_LURE_TOOL_MAX + 1];
} web_lure_hent_t;

typedef struct {
    int             used;
    uint8_t         mac[6];
    long long       rx_ms;           /* last written: the eviction order */
    int             n, head;         /* ring: head the oldest */
    unsigned long   changes;         /* entries ever added */
    long long       gone_ts;         /* sloth's gone record's ts, 0 live */
    int             hw_seen;         /* a KARMA_AP record came */
    long long       hw_ts;
    char            hw_verdict[WEB_LURE_HW_MAX + 1];   /* "" none */
    char            hw_signals[WEB_LURE_HW_MAX + 1];
    web_lure_hent_t h[WEB_LURE_HIST];
} web_lure_det_t;

typedef struct {
    int       used;
    uint8_t   mac[6];
    long long rx_ms, ts;
    char      src[8];                /* "tsft" or "pcap" */
    long long n_dir, med_dir, p10_dir, p90_dir, min_dir, n_wild, med_wild;
} web_lure_lat_t;

typedef struct {
    int       used;
    uint8_t   mac[6];
    long long ts, rx_ms;
    /* karma_suspect */
    long long ssids, ie_postures, ie_collapsed, forged, forge_stations,
              pnl_best, lure_chain, score;
    char      top_ssid[WEB_LURE_SSID_MAX + 1];
    char      tool[WEB_LURE_TOOL_MAX + 1];
    /* harvest_station */
    long long asked, m1_bssids, unanswered, unanswered_kde, answered;
    /* harvest_chain */
    long long victims, disconnects;
    /* both harvest records */
    long long dropped, first_seen;
    long long last_seen;
} web_lure_row_t;

typedef struct web_lure {
    pthread_mutex_t mu;
    web_lure_row_t  karma[WEB_LURE_KARMA];
    web_lure_row_t  sta[WEB_LURE_STA];
    web_lure_row_t  chain[WEB_LURE_CHAIN];
    /* sensor_health's jsonl_version, MAJOR.MINOR.PATCH; 0 0 0 unknown */
    int             ver_seen, ver[3];
    unsigned long   records, rejected, overflow, gone;
    /* The KARMA detail (#187). */
    web_lure_det_t  det[WEB_LURE_DET];
    web_lure_lat_t  lat[WEB_LURE_LAT];
    unsigned long   det_evicted, lat_evicted, hw_rejected, lat_rejected;
} web_lure_t;

int  web_lure_init(web_lure_t *l);
void web_lure_destroy(web_lure_t *l);

/* Every decoded record: the three lure types apply, and sensor_health's
 * jsonl_version is noted; the rest return. */
void web_lure_record(web_lure_t *l, const web_jrec_t *r, long long now_ms);

/* 1 the stream writes these records (1.3.0 or later), 0 it does not,
 * -1 not known (no sensor_health with a version yet). */
int  web_lure_reported(web_lure_t *l);

/* /api/lures: no parameters. 0 with *status and *len set (400 for a
 * parameter, 503 with no tables), -1 when the answer did not fit.
 * none_here: Local's, the query checked and *len 1 for the caller's
 * out_of_scope answer. */
int  web_lure_route(web_lure_t *l, const char *query, long long now_s,
                    long long now_ms, int none_here, char *body, size_t cap,
                    size_t *len, int *status);
size_t web_lure_out_of_scope_json(char *body, size_t cap);

/* /api/lures/bssid?bssid=: one BSSID's KARMA detail (above). bssid is
 * required, "xx:xx:xx:xx:xx:xx" either case, and is the only parameter
 * (400 "missing_bssid", "bad_bssid", or the parser's word). 200 for any
 * well-formed BSSID, held or not: "state" says which ("live", "gone",
 * "stale", or "none" with nothing held). live may be NULL (no alerts
 * then). Otherwise as web_lure_route(). */
int  web_lure_bssid_route(web_lure_t *l, web_live_t *live, const char *query,
                          long long now_s, long long now_ms, int none_here,
                          char *body, size_t cap, size_t *len, int *status);

#endif /* SLOTHWEB_LURE_H */
