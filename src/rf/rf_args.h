#ifndef SLOTH_RF_ARGS_H
#define SLOTH_RF_ARGS_H

#include <stdio.h>
#include "gnss_flags.h"
#include "rf_flags.h"

/* sloth-rf's command line (#213), apart from its main() so the test
 * binary can drive it: sloth_test links no main but its own.
 *
 * Every flag here that `sloth` also has is read, checked and refused by
 * the function `sloth` uses (src/gnss_flags.h, src/rf_flags.h,
 * src/daemon_start.h), so the two daemons cannot disagree about one.
 * `make replay-check` runs both binaries on the same refusals and
 * compares what they print. */

typedef struct {
    const char  *jsonl_path;      /* -o FILE, --out FILE */
    const char  *db_path;         /* --db FILE */
    const char  *data_socket;     /* --data-socket [SPEC] */
    int          ds_allow_remote; /* --data-socket-allow-remote */
    int          strict;          /* --strict */
    const char  *site_label;      /* --site-label TEXT */
    const char  *user;            /* --user NAME */
    int          no_privdrop;     /* --no-privdrop */
    long         max_ticks;       /* --ticks N; 0 = run until a signal */
    gnss_flags_t gnss;            /* --location --gps --gps-allow-remote --gps-baud */
    rf_flags_t   rf;              /* --adsb --aprs --aprs-freq --aprs-silent-hours --rtl433 --victron */
} rf_args_t;

/* Read argv into `a`. Returns -1 to go on, or the exit code: 0 after
 * --help, --version and --tune-list (each printed), 2 on a flag that is
 * unknown or whose value is refused (the reason on stderr). */
int rf_args_parse(int argc, char **argv, rf_args_t *a);

/* The whole-command-line checks, before anything opens: the receiver's
 * flags, each decoder's SPEC, and --strict's hold on a routable
 * --data-socket. Configures the three decoder readers and --victron's. 0, or the exit
 * code with the reason on stderr. */
int rf_args_check(const rf_args_t *a);

void rf_usage(FILE *fp, const char *argv0);

#endif /* SLOTH_RF_ARGS_H */
