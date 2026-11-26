#ifndef SLOTH_HANDOFF_H
#define SLOTH_HANDOFF_H

#include <stdio.h>
#include <time.h>

#include "df.h"
#include "preflight.h"

/* sloth --handoff OUT_DIR [the normal options] (#250).
 *
 * What a site's next operator needs, in one directory: FM 2-0 (2004)
 * 4-16 lists what a unit taking over must receive, the reports and
 * their formats, past, present and planned activity, the procedures,
 * and "equipment operation and idiosyncrasies". The command starts no
 * capture, opens no radio and writes nothing but OUT_DIR; sloth.db is
 * read through src/site_db.h (read-only). Files:
 *
 *   README.txt              what each file is, and what was not written
 *   config.json             the command line, radios, hop plan,
 *                           positions, designation counts, inventory
 *                           identity, intel pack, database
 *   preflight.txt / .json   --preflight for this command line, with the
 *                           rule status counts (observable/partly/blind)
 *   networks.tsv            designated SSIDs and BSSIDs, the roster,
 *                           the inventory's identity
 *   baseline.tsv            the --baseline-in file, when one is named
 *   snapshot.tsv            the site snapshot (#27) from sloth.db's
 *                           beacon_aps: the APs heard in the
 *                           HANDOFF_SNAPSHOT_WINDOW_S before the newest
 *                           one; with no --db, the --snapshot-out file
 *   findings_open.tsv       incidents with no close recorded, and state
 *   findings_closed_30d.tsv incidents closed in the last 30 days, by kind
 *   interference.md         --interference-report for the last 30 days
 *   false_positives.txt     empty: triage is sloth-mesh's
 *
 * snapshot.tsv from --db is a "# sloth-snapshot v1" file; baseline.tsv,
 * and snapshot.tsv copied from --snapshot-out, may be v2 (#249: client
 * and BLE rows a v1 reader skips). The next run reads either with
 * --baseline-in, and its exit diff (access points) is against this
 * site.
 *
 * WITHHELD. No file holds a column sloth.db's readers withhold
 * (sloth-mesh's web_secret.h list): alerts.key and alerts.detail carry
 * a clear-text credential's user name, an RDP cookie and an MQTT user
 * name; alert_incidents.key is the same key; cleartext_creds.username,
 * mqtt_flows.last_username, rogue_radius.last_identity and
 * rdp_flows.last_cookie are the names themselves. A finding is written
 * as its kind, severity, times and incident id. interference.md reads
 * detail and key for RF_DEGRADED, RTS_FLOOD and GNSS_JAMMING alone,
 * and writes what it parses out of them (the channel number, the RTS
 * transmitter's address, the rule's figures), never their text: a
 * word in those kinds' detail does not reach the packet either. The
 * transmitter's address is written because it is what the report's
 * reader looks for; it is heard over the air. The --inventory file is not
 * copied (it is the operator's JSON, whose unknown keys sloth parses
 * and does not read, so it could hold anything); its identity is. The
 * packet is a local file for the site's operator and not a fleet
 * export (ADR 0009 governs those); it names its host all the same.
 *
 * OUT_DIR is created 0700, or must be an empty private directory
 * (src/secure_file.h): a packet is never written over another's files.
 * Every file is created 0600 with O_EXCL. */

/* An AP in the snapshot was heard within this of the newest AP heard:
 * a day, the survey cycle the snapshot was made for. An AP last heard
 * before that is not part of the site as it was last seen. */
#define HANDOFF_SNAPSHOT_WINDOW_S (24 * 3600)
/* The closed findings counted: the last 30 days, the issue's window and
 * the database's default retention (DB_DEFAULT_RETAIN_DAYS). */
#define HANDOFF_CLOSED_DAYS 30
/* A file copied into the packet is at most this; a snapshot of the
 * largest inventory sloth keeps is well under it. */
#define HANDOFF_COPY_MAX (16L * 1024 * 1024)

typedef struct {
    const char        *out_dir;
    int                argc;
    char *const       *argv;
    const char        *db;            /* --db, NULL none */
    const char        *baseline_in;   /* --baseline-in */
    const char        *snapshot_out;  /* --snapshot-out */
    const char        *inventory;     /* --inventory path, named only */
    const char        *site_label;    /* --site-label */
    const char        *location;      /* --location */
    const df_cli_t    *df;            /* --df-iface / --df-origin, may be NULL */
    const pf_config_t *pf;            /* the preflight's view of the command line */
    const pf_ops_t    *ops;           /* NULL: preflight_default_ops() */
    time_t             now;
} handoff_cfg_t;

/* Write the packet. 0 written (a line per file to `msg`), 2 not: the
 * reason on `msg`, and nothing is created when the database or the
 * directory is refused. */
int handoff_write(const handoff_cfg_t *c, FILE *msg);

#endif /* SLOTH_HANDOFF_H */
