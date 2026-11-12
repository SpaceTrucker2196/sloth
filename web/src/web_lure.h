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
 * out_of_scope under Local. */
#ifndef SLOTHWEB_LURE_H
#define SLOTHWEB_LURE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_json.h"
#include "web_jsonl.h"

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

enum { WEB_LURE_K_KARMA, WEB_LURE_K_STA, WEB_LURE_K_CHAIN, WEB_LURE_KINDS };

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

#endif /* SLOTHWEB_LURE_H */
