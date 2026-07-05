#ifndef UPDATER_H
#define UPDATER_H

#include "sloth.h"

/* Version check-in module (notify-only).
 *
 * Reads a locally-populated release manifest and compares its "latest"
 * field to SLOTH_VERSION. Sloth never touches the network directly —
 * populating the manifest is the operator's responsibility, e.g. via a
 * systemd timer running examples/updater/check-latest.sh.
 *
 * See docs/wiki/version-checkin.md for the architecture and
 * docs/wiki/manifest-format.md for the file schema. */

/* Register the manifest path. NULL disables the checker entirely. */
void updater_init(const char *manifest_path);

/* Called from the main loop. Cheap when the check interval hasn't
 * elapsed; when it has, stat()s the manifest and re-reads iff its
 * mtime changed. */
void updater_tick(time_t now);

/* Copy the current status into sloth_state_t. Called each poll after
 * updater_tick so the help view / dashboard sees a stable snapshot. */
void updater_snapshot(sloth_state_t *s);

#endif /* UPDATER_H */
