/* slothweb: many alerts triaged as one incident (#198: on one field
 * sensor 952 untriaged alerts came down to five causes, and the only
 * way to say so was 952 POSTs, 33 minutes at the write limit).
 *
 * An incident is the operator's (or an agent's) statement that a set
 * of alerts is one thing: an id, a title, a state (false, noise,
 * incident or known: a decision, never "untriaged"), a note, who, from
 * where, when and how (via, the triage table's values). Its members
 * are
 *
 *   alerts    by id ("s<handle>" or "d<rowid>"), resolved as the
 *             triage routes resolve one and filed as a triage row
 *             files one (subject, finding, descriptor), so a member
 *             survives the stream handle aging out and a rebuild of
 *             sloth.db exactly as its triage does. Anomalies are not
 *             members: an anomaly's id already names every episode of
 *             it, so one triage row is its incident.
 *   filters   a standing filter: an alert type (or any), an address
 *             (an IP, or a MAC: the address the alert's descriptor
 *             names, web_frrs.c's desc_addr(), so "ip" is the alert's
 *             own address, which for most rules is the source) and a
 *             first_seen window (either end open); at least one of the
 *             three. An alert matching a live filter of an incident is
 *             a member whenever it began, until the incident closes:
 *             one that began after the filter was set is "auto-joined",
 *             and after the close a filter takes no alert that began
 *             later. Nothing is written when an alert joins: membership
 *             is read, so it costs no write and cannot race the stream.
 *
 * What a member reads as (the precedence, decided for #198): its own
 * newest triage row when that row is a decision (not a clear) at or
 * after the incident's decision (the open, or the close when there is
 * one), else the incident's state. So the newer statement wins, and on
 * the same second the alert's own, the more specific one; a member the
 * operator triaged on its own later keeps that, and clearing its own
 * row returns it to its incident's state. An alert in two incidents
 * reads the one decided last (then the higher id), its explicit
 * membership before a filter's on the same incident. The incident
 * shows on the triage answer ("incident": id, title, state, governs,
 * joined, auto) only when there is one, so every answer about an alert
 * in no incident is byte for byte what it was before this module.
 *
 * Append-only, as triage is: an incident is closed by a second row
 * (closes: the first's id, the state it closed at, a closing note), a
 * member is removed by a row naming it (removes), and nothing is
 * deleted or rewritten. Closed is final: no member changes after it.
 * An agent (via agent, web_agent.h) may open incidents, add members to
 * any open one, remove only members an agent added (403
 * not_agent_member) and close only incidents an agent opened (403
 * not_agent_incident), as it takes back only agents' notes and links:
 * a judgement call for #198, so an agent never ends the operator's
 * statement. Bounds: WEB_INC_CAP incidents, WEB_INC_MEMBER_CAP member
 * rows, WEB_INC_PER rows on one incident, WEB_INC_FILTERS live filters
 * on one; at any of them a write is refused, 507: these rows are the
 * operator's and never fold.
 *
 *   POST /api/frrs/incident
 *     {"op":"add","title":..,"state":..,"note":..,"by":..
 *      [,"ids":"d1,s2,..."][,"type":..][,"ip":..|"mac":..][,"from":N][,"to":N]}
 *     {"op":"member","incident":N,"ids":"..."}         alerts added
 *     {"op":"member","incident":N,"type":..,...}       a filter added
 *     {"op":"member","incident":N,"remove":M}          member row M taken back
 *     {"op":"close","incident":N[,"state":..][,"note":..],"by":..}
 *       through web_frrs.c's write path and gate, one token each; the
 *       ids at most WEB_FRRS_BULK_MAX, each one's outcome in "results"
 *   GET  /api/frrs/incidents?state=open|closed|all     newest first
 *   GET  /api/frrs/incident?id=N                       one, with its members
 *
 * Every stored string is a validated id or address, slothweb's own
 * words, or text from the validated POST body (frrs_text()); nothing
 * from the stream. Every statement binds its values. */
#ifndef SLOTHWEB_INCIDENT_H
#define SLOTHWEB_INCIDENT_H

#include <stddef.h>

#include "web_frrs.h"

#define WEB_INC_CAP          1024
#define WEB_INC_MEMBER_CAP   20000
#define WEB_INC_PER          4096
#define WEB_INC_FILTERS      8
/* /api/frrs/incidents lists at most this many, /api/frrs/incident this
 * many of one incident's alerts (the newest). */
#define WEB_INC_LIST         200
#define WEB_INC_SHOWN        500

/* The routes (dispatched by web_frrs_route()): the body into body,
 * *status set; 0, or -1 when not even an error fit. via is how the
 * write arrived, decided by the gate and never by the body. */
int  web_incident_post(const web_m4_t *m, web_live_t *live, const web_jrec_t *r,
                       const char *peer, int via, long long now_s, char *body, size_t cap,
                       size_t *len, int *status);
int  web_incident_list(const web_m4_t *m, const char *query, char *body, size_t cap,
                       size_t *len, int *status);
int  web_incident_get(const web_m4_t *m, const char *query, char *body, size_t cap,
                      size_t *len, int *status);

/* The incidents opened, for /api/health; -1 without a store. */
long long web_incident_rows(web_frrs_t *f);

#endif
