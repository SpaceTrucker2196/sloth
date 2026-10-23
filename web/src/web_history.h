/* slothweb History routes (#163, M5): docs/web-ui-spec.md §8.10, the
 * time-travel browser, over sloth.db read through the M4 reader and its
 * allow-list (web_slothdb.h). Every route needs --sloth-db; without it
 * each is a 503 "no_sloth_db".
 *
 *   /api/history/overview?from=&to=&cols=
 *       the 30 d strip the range picker drags on: per cell (cols cells,
 *       1..WEB_HIST_COLS_MAX, default WEB_HIST_COLS) the devices first
 *       seen in it and the alert episodes begun in it, and the survey
 *       sessions that overlap the range as markers. from and to default
 *       to the last 30 days; the range is at most 400 days.
 *   /api/history/devices?from=&to=&limit=&offset=
 *       who was here: the devices whose [first_seen, last_seen]
 *       overlaps [from, to] (sqlite-schema.md's recipe), as /api/devices
 *       renders a row, with the presence strip restricted to the range
 *       (web_devices.h; it is in web_devices.c for the row renderer).
 *   /api/history/alerts?from=&to=&limit=
 *       alert episodes overlapping the range, newest first: title, the
 *       IP it names, type, severity, count, first and last seen. Never
 *       the key or the detail (web_slothdb.h's withheld columns).
 *   /api/history/flows?from=&to=&limit=
 *       ssh_flows, rdp_flows, smb_sessions and snmp_flows rows
 *       overlapping the range: protocol, src, dst, the count each keeps
 *       (banners, connect requests, messages, PDUs), the SMB server
 *       port or SNMP version. mqtt_flows is not read: the table holds a
 *       username, and the allow-list keeps it whole off.
 *   /api/sessions
 *       sloth.db's survey sessions, newest first (at most
 *       WEB_HIST_SESSIONS).
 *   /api/sessions/new?id=
 *       --report's "New since last survey" for one session, in the
 *       browser (src/posture.c, src/db.c db_new_since()): since is the
 *       previous session's COALESCE(ended, started), the session that
 *       was newest when this one began; then the access points, devices
 *       and probe clients first seen at or after it, each newest first
 *       with --report's identity and label and its total (at most
 *       WEB_HIST_NEW listed, as --report lists 32). For an older
 *       session the window also closes where that session did (its
 *       ended, else the next one's start), so it says what --report
 *       said at the end of that visit; for the latest it is --report's
 *       window exactly. A first visit has no previous session and,
 *       like --report, no list: "previous":null.
 *
 * Parameters are validated whole as /api/series's are; a refusal is a
 * 400 with a reason word of slothweb's own. Lists stop early with
 * "more" rather than not fit their buffer. */
#ifndef SLOTHWEB_HISTORY_H
#define SLOTHWEB_HISTORY_H

#include <stddef.h>

#include "web_devices.h"

#define WEB_HIST_COLS      180
#define WEB_HIST_COLS_MAX  360
#define WEB_HIST_SPAN_MAX  (400LL * 86400)
#define WEB_HIST_DEFAULT_S (30LL * 86400)
#define WEB_HIST_LIMIT     100
#define WEB_HIST_LIMIT_MAX 200
#define WEB_HIST_SESSIONS  200
#define WEB_HIST_NEW       32

/* from and to of a History query, defaults applied (the last 30 days
 * to now). 0, or -1 with the reason in *why. For the routes here and
 * /api/history/devices. */
int web_hist_range(const char *from_s, const char *to_s, long long now_s,
                   long long *from, long long *to, const char **why);

int web_history_overview_route(const web_m4_t *m, const char *query,
                               long long now_s, char *body, size_t cap,
                               size_t *len, int *status);
int web_history_alerts_route(const web_m4_t *m, const char *query,
                             long long now_s, char *body, size_t cap,
                             size_t *len, int *status);
int web_history_flows_route(const web_m4_t *m, const char *query,
                            long long now_s, char *body, size_t cap,
                            size_t *len, int *status);
int web_sessions_route(const web_m4_t *m, const char *query, long long now_s,
                       char *body, size_t cap, size_t *len, int *status);
int web_sessions_new_route(const web_m4_t *m, const char *query,
                           long long now_s, char *body, size_t cap,
                           size_t *len, int *status);
/* The answers every sloth.db route shares (web_flows.c too): an error
 * body {"error":reason[,"detail":...]}; whether --sloth-db is set in a
 * build that can read it; the 503 "no_sloth_db"; an open, or the 503
 * that says why not (0 open, 1 answered, -1); and the 503 of a read
 * that failed or ran past its budget, closing c. */
int web_hist_error(int status, const char *reason, const char *detail,
                   char *body, size_t cap, size_t *len, int *st);
int web_hist_configured(const web_m4_t *m);
int web_hist_no_db(char *body, size_t cap, size_t *len, int *status);
int web_hist_open(const web_m4_t *m, web_sdb_conn_t *c, long long now_s,
                  char *body, size_t cap, size_t *len, int *status);
int web_hist_read_failed(web_sdb_conn_t *c, char *body, size_t cap,
                         size_t *len, int *status);

/* In web_devices.c. */
int web_history_devices_route(const web_m4_t *m, const char *query,
                              long long now_s, char *body, size_t cap,
                              size_t *len, int *status);

#endif
