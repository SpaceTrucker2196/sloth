/* The alert page's proof (owner requests 2026-10-27: "show the full
 * packet capture in alerts at the bottom as well"; "full verbose
 * details of the alert, include bibliography, when possible prove the
 * alert with evidence"): what /api/alert adds about one alert, and the
 * two routes that read its capture.
 *
 *   /api/alert, appended members:
 *     "captures"       the alert's pcap files (web_pcapdir.h), newest
 *                      first, at most WEB_PCAPDIR_HITS: n (the index the
 *                      routes below take), file, sink, size, sha256,
 *                      written_at, matched_by (incident | record |
 *                      rule_time); never the incident_id, the session
 *                      or a directory path
 *     "captures_note"  why the list may be short, or null
 *     "evidence"       observed against threshold where known: the
 *                      counts, the detail's name=value numerals (only
 *                      for a type web_alert_detail_ok() admits), the
 *                      assessment's thresholds; and why there is no
 *                      capture when there is none, in sloth's own terms
 *                      (src/alerts/engine.c dump_new_alert_pcaps())
 *     "assessment"     docs/wiki/alert-assessments/<TYPE>.md as built
 *                      in (web_alertasm.h), or null
 *
 *   /api/pcap/frames?id=&n=&offset=
 *       capture n of alert id, read whole (at most WEB_PCAP_FILE_MAX),
 *       its SHA-256 recomputed and compared with the manifest's
 *       ("hash"), and one page of WEB_PCAP_PAGE decoded frames from
 *       offset with each frame's hex dump (web_pcap.h). GET only.
 *   /api/pcap?id=&n=
 *       the same file's bytes, application/vnd.tcpdump.pcap, as an
 *       attachment. GET only.
 *
 * n names a file only through its alert: a file the alert's lookup
 * does not return is a 404 whatever the directory holds, so neither
 * route can be pointed at another file, and neither ever takes a name
 * or a path from the request. */
#ifndef SLOTHWEB_EVIDENCE_H
#define SLOTHWEB_EVIDENCE_H

#include <stddef.h>

#include "web_alerts.h"
#include "web_devices.h"
#include "web_json.h"
#include "web_live.h"

/* The members above, each with its leading comma, at w's position. */
void web_evidence_alert_json(web_jw_t *w, const web_m4_t *m, const web_alert_tgt_t *t);

int web_pcap_frames_route(const web_m4_t *m, web_live_t *live, const char *query,
                          long long now_s, char *body, size_t cap, size_t *len,
                          int *status);

/* 200: *data is the file (malloc'd: the caller frees it, or hands it to
 * the server as an owned body), *n its length, name its file name.
 * Otherwise a JSON error in body and *data NULL. 0, or -1 when not even
 * the error fit. */
int web_pcap_download_route(const web_m4_t *m, web_live_t *live, const char *query,
                            long long now_s, unsigned char **data, size_t *n,
                            char *name, size_t namesz, char *body, size_t cap,
                            size_t *len, int *status);

/* The monotonic clock the index's rescan is paced by. */
long long web_evidence_now_ms(void);

#endif
