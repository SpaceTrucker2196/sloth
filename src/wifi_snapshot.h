#ifndef WIFI_SNAPSHOT_H
#define WIFI_SNAPSHOT_H

#include "sloth.h"
#include <stdio.h>

/* Passive site snapshot export/import (issue #27).
 *
 * A snapshot is a normalised, human-diffable inventory of the passive
 * AP observations from one session — no raw pcap, just BSSID / SSID /
 * security / channel / vendor per AP. It lets an assessor answer "what
 * changed since last visit?" across repeat trips without a database. */

/* Write the current AP inventory to `path` (tab-separated, one AP per
 * line, with a header carrying the label and timestamp). `label` and
 * `now` are stamped into the header.
 *
 * Created 0600; an existing file must be a regular file owned by the
 * effective uid with no group/other bits and a single link, and a
 * symlink is refused — validated before truncation, so a refused file
 * is left as it was (#87). Returns 0 on success, -1 on error with the
 * reason in wifi_snapshot_error(). */
int wifi_snapshot_write(const sloth_state_t *s, const char *path,
                        const char *label, long now);
const char *wifi_snapshot_error(void);

/* Compare the current AP inventory against the baseline snapshot at
 * `baseline_path` and write a drift report (new APs, disappeared APs,
 * changed security/channel) to `out`. Returns the number of differences,
 * or -1 if the baseline file can't be read. */
int wifi_snapshot_diff(const sloth_state_t *s, const char *baseline_path,
                       FILE *out);

#endif /* WIFI_SNAPSHOT_H */
