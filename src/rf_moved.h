#ifndef SLOTH_RF_MOVED_H
#define SLOTH_RF_MOVED_H

#include <stddef.h>

/* The decoder flags sloth-wifi no longer takes (#216, ADR 0010).
 *
 * Until the cutover the one binary read the ADS-B, APRS, rtl_433 and
 * Victron inputs itself. They are sloth-rf's now, and a sensor whose
 * /etc/default/sloth still names one must not start as if nothing had
 * changed, silently reading no aircraft: it exits 2 with one line that
 * says which daemon takes the flag and which tool moves it
 * (docs/wiki/deployment.md section 11.4).
 *
 * The list is here, apart from src/rf_flags.c (sloth-rf's parser of
 * the same six), because this daemon links no decoder file; and apart
 * from src/main.c so tests/test_rf_moved.c holds the words. */

/* Is `arg` one of --adsb, --aprs, --aprs-freq, --aprs-silent-hours,
 * --rtl433, --victron? Exact spellings only. */
int rf_moved_flag(const char *arg);

/* The one line, without a newline, into `out`. Always terminated. */
void rf_moved_message(const char *flag, char *out, size_t outsz);

/* The flags, NULL-terminated, for the usage text and the tests. */
extern const char *const rf_moved_flags[];

#endif /* SLOTH_RF_MOVED_H */
