#ifndef SLOTH_GNSS_FLAGS_H
#define SLOTH_GNSS_FLAGS_H

/* The --location / --gps flags' command-line half (#213).
 *
 * Both daemons take these four flags (ADR 0010: one gpsd reader, linked
 * into both), and they have to refuse the same things with the same
 * words and the same exit code - a remote gpsd under --strict is not
 * more acceptable to one of them. The checks were inline in
 * src/main.c; they are here so sloth-rf's main (src/rf/main.c) calls
 * them and not a copy. Each function prints its own refusal or
 * announcement on stderr, exactly as main.c did, and returns the exit
 * code: 0 to go on, 2 to exit.
 *
 * The messages say "sloth:", in both daemons. That is the product's
 * prefix, the one every shared module under src/ already prints
 * (db.c, data_socket.c, secure_file.c, privdrop.c), and keeping it is
 * what makes the two daemons' refusals the same bytes. */

typedef struct {
    const char *location;      /* --location LAT,LON[,ALT]; NULL not given */
    const char *gps;           /* --gps SPEC; NULL not given */
    int         allow_remote;  /* --gps-allow-remote */
    int         baud;          /* --gps-baud N; 0 not given (9600) */
} gnss_flags_t;

/* --gps-baud's value, as the flag is read. */
int gnss_flag_baud(const char *arg, int *out);

/* Whole-command-line checks, before anything opens: a mistyped
 * --location exits here; --gps is checked for shape and scope.
 * `strict` is --strict; `replay` is `sloth`'s --replay (sloth-rf has no
 * such flag and passes 0). */
int gnss_flags_check(const gnss_flags_t *f, int strict, int replay);

/* Configure the reader, just before the privilege drop: a serial
 * receiver is opened here, because the drop clears the supplementary
 * groups and the device is usually group dialout; gpsd is only
 * recorded and is dialled by the worker after the drop. A no-op
 * without --gps. On 2 the caller stops whatever it opened. */
int gnss_flags_open(const gnss_flags_t *f);

#endif /* SLOTH_GNSS_FLAGS_H */
