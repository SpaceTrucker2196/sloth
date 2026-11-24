#ifndef SLOTH_INTERFERENCE_H
#define SLOTH_INTERFERENCE_H

#include <stdio.h>
#include <time.h>

#include "site_db.h"

/* sloth --interference-report FILE --db DB [--from T] [--to T] (#250).
 *
 * One Markdown document, one section per RF_DEGRADED, RTS_FLOOD or
 * GNSS_JAMMING episode (an alert_incidents row) that overlaps the
 * window, for a reader outside the site: an internet provider, a
 * landlord, an equipment vendor, a regulator. FM 6-02.43 (2009) A-7
 * asks that harmful interference be resolved at the lowest level and
 * reported in time when it cannot be; this is that report's evidence.
 *
 * Its own flag and not only a file of the handoff packet: the reader
 * is someone else, the window is chosen per report, and it is sent on
 * its own. The handoff packet carries the last 30 days of it too.
 *
 * WHAT EACH SECTION HOLDS, from sloth.db opened read-only
 * (src/site_db.h):
 *   - the episode's times, severity, evaluations;
 *   - its channel (RF_DEGRADED's key), its transmitter (RTS_FLOOD's);
 *   - the figures the rule wrote (retry ratio and bad-FCS share over N
 *     frames; RTS count, rate and NAV; GNSS C/N0 and jamming
 *     indicator), when the finding's stored detail is this episode's:
 *     sloth.db keeps a finding's latest detail only, so an earlier
 *     episode of the same key says "not stored";
 *   - from coverage_intervals (v18), for the episode and for the same
 *     length before it (at most IFR_BEFORE_MAX_S): frames heard on its
 *     channel and control frames per minute, and the share of the
 *     covered time each radio spent on the channel;
 *   - channel utilisation: not stored as a history; the APs' latest
 *     QBSS load is shown, labelled as such;
 *   - the access points on the channel whose sightings span the
 *     episode, each with a count of the clients associated in it.
 *     Client addresses are not written: the reader is outside the
 *     site and the count is what the report needs;
 *   - "not located": one sensor measures what reaches it. A location
 *     needs several (sloth-mesh#19).
 * The wording is about the observable. The retry ratio a jammer
 * causes is the one a microwave oven, a hidden node and a client at
 * the edge of range cause (the RF_DEGRADED rule's own comment), and a
 * GNSS receiver cannot tell interference from jamming (DHS 2017).
 *
 * GNSS_JAMMING is sloth-rf's alert. It is here only when sloth-rf
 * wrote to the same file (`sloth-rf --db` the same path); the report
 * says which daemons' rows the file holds. */

/* The "before" window: the episode's own length, at most this. Ten
 * minutes is ten coverage intervals, enough to see the channel's
 * ordinary load and short enough to stay the same afternoon. */
#define IFR_BEFORE_MAX_S 600
/* The access points listed per episode; the rest are counted. */
#define IFR_MAX_APS 20

/* Write the report for [from, to] (0: open) from an open file; the
 * number of episodes written, or -1 on a query failure (the reason in
 * err). `db_path` is only named in the header. */
int interference_report(const site_db_t *d, const char *db_path,
                        time_t from, time_t to, time_t now, FILE *out,
                        char *err, size_t errsz);

/* The command: open `db`, write `out_path` ("-" stdout; else created
 * 0600 through src/secure_file.h, an existing file validated first),
 * print one line to `msg`. Exit code: 0 written, 2 not. */
int interference_main(const char *db, const char *out_path, time_t from,
                      time_t to, FILE *msg);

#endif /* SLOTH_INTERFERENCE_H */
