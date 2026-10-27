/* The Alerts page and the alert detail page (owner request
 * 2026-10-23..26): incidents from the live stream's lifecycle records
 * (web_live.h) and from sloth.db's alerts table (web_alertdb.h), merged.
 * GET only (HEAD is a 405: there is no answer to describe without
 * reading sloth.db), every parameter validated whole as /api/series's
 * are, a refusal a 400 with a reason word of slothweb's own.
 *
 *   /api/alerts?state=&sev=&type=&q=&window=&limit=&offset=
 *       open incidents first (the stream's: the Overview's open-alerts
 *       tile counts exactly these), highest severity then newest change
 *       first; then the closed ones, newest last_seen first: the
 *       stream's recently resolved incidents and sloth.db's rows. One
 *       row per alert key, from both sources: the stream's incidents of
 *       a key are its open one (else its newest closed one) with the
 *       rest counted in, sloth.db's rows of a key are grouped, and a key
 *       the stream has is shown once, as the stream's. "incidents" and
 *       "count" are the key's, all time: sloth.db's totals over every
 *       row of the key (1 + reopens a v8 row) or the stream's, the
 *       larger of the two, as the alert's page shows them.
 *         state   open | closed | all (default)
 *         sev     low,warn,crit (or 0,1,2), any of them
 *         type    an alert type's name (PORT_SCAN) or number
 *         q       1..63 bytes: a substring of the title, the address or
 *                 the type's name, ASCII case-insensitively
 *         window  seconds of last_seen, 60..400 days (default 7 days);
 *                 open incidents are listed whatever their age
 *         limit   1..WEB_ALERTS_LIMIT_MAX (default WEB_ALERTS_LIMIT)
 *         offset  0..WEB_ALERTS_OFFSET_MAX
 *       Each row: id ("s<handle>", slothweb's handle for a stream
 *       incident, web_live.h, or "d<rowid>"; never alerts.key nor
 *       sloth's incident_id, which inverts to the key's hash), state,
 *       source, type, type_name, title, sev, technique, ip, port,
 *       first_seen, last_seen, count, incidents, reason. And the facets
 *       (keys per type), the open count, the total, and how many
 *       matching sloth.db rows were read ("scan"): the filters apply
 *       inside the bounded read, at most WEB_ADB_SCAN_CAP rows newest
 *       first, and the answer says when it stopped there and the oldest
 *       last_seen it reached ("oldest").
 *   /api/alert?id=
 *       one alert, everything the detail page shows: what it is, why it
 *       matters and how to investigate and fix it (web_alertkb.h), the
 *       evidence (severity history, counts, first and last seen, whether
 *       sloth saved a pcap; count as the list row has it, latest_count
 *       the one incident's), the detail text only for a type
 *       web_alert_detail_ok() admits, every incident of the same key as
 *       runs (incidents less than WEB_ALERT_RUN_GAP_S apart are one run),
 *       and the device it names (a MAC, the address) for the page to
 *       read with /api/device/{mac}. */
#ifndef SLOTHWEB_ALERTS_H
#define SLOTHWEB_ALERTS_H

#include <stddef.h>

#include "web_devices.h"
#include "web_live.h"

#define WEB_ALERTS_LIMIT       50
#define WEB_ALERTS_LIMIT_MAX   100
#define WEB_ALERTS_OFFSET_MAX  1000
#define WEB_ALERTS_WINDOW_S    (7LL * 86400)
#define WEB_ALERTS_WINDOW_MAX  (400LL * 86400)
#define WEB_ALERT_RUN_GAP_S    1800
#define WEB_ALERT_RUNS         100

/* The routes: the body into body (cap bytes), *status set; 0, or -1
 * when not even an error fit. live may be NULL (no data socket). */
int web_alerts_route(const web_m4_t *m, web_live_t *live, const char *query,
                     long long now_s, char *body, size_t cap, size_t *len,
                     int *status);
int web_alert_route(const web_m4_t *m, web_live_t *live, const char *query,
                    long long now_s, char *body, size_t cap, size_t *len,
                    int *status);

#endif
