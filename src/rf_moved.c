#include <stdio.h>
#include <string.h>

#include "rf_moved.h"

/* src/rf_moved.h. */

const char *const rf_moved_flags[] = {
    "--adsb", "--aprs", "--aprs-freq", "--aprs-silent-hours",
    "--rtl433", "--victron", NULL,
};

int rf_moved_flag(const char *arg) {
    if (!arg) return 0;
    for (int i = 0; rf_moved_flags[i]; i++)
        if (strcmp(arg, rf_moved_flags[i]) == 0) return 1;
    return 0;
}

void rf_moved_message(const char *flag, char *out, size_t outsz) {
    if (!out || outsz == 0) return;
    snprintf(out, outsz,
             "sloth-wifi: %s is sloth-rf's flag since the split (JSONL 2.0.0): "
             "this daemon reads no SDR decoder. Run 'sloth-migrate-rf --apply' "
             "to move it from /etc/default/sloth to /etc/default/sloth-rf, then "
             "start sloth-rf (docs/wiki/deployment.md section 11.4)",
             flag ? flag : "");
}
