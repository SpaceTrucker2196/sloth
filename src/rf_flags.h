#ifndef SLOTH_RF_FLAGS_H
#define SLOTH_RF_FLAGS_H

#include <stdint.h>

/* The decoder flags' command-line half (#213): --adsb, --aprs,
 * --aprs-freq, --aprs-silent-hours, --rtl433 and --victron (sloth-va's
 * file: not a decoder, but read and refused the way --rtl433's is).
 *
 * sloth-rf's alone since the cutover (#216, ADR 0010). For one release
 * both mains parsed these six, which is why the checks came out of
 * src/main.c into a file of their own; sloth-wifi now refuses each
 * flag before it would reach one (src/rf_moved.h) and does not link
 * this file. Each function prints on stderr exactly what main.c did
 * and returns the exit code: 0 to go on, 2 to exit. The prefix is
 * still "sloth:", as src/gnss_flags.h's shared checks print it:
 * sloth-rf's output was held unchanged across the cutover. */

typedef struct {
    const char *adsb;          /* --adsb SPEC; NULL not given */
    const char *aprs;          /* --aprs SPEC */
    const char *rtl433;        /* --rtl433 SPEC */
    const char *victron;       /* --victron SPEC (2026-11-15) */
    uint32_t    aprs_freq;     /* --aprs-freq HZ; 0 not given */
    int         aprs_silent_h; /* --aprs-silent-hours N; -1 not given */
} rf_flags_t;
#define RF_FLAGS_INIT { NULL, NULL, NULL, NULL, 0, -1 }

/* The two flags with a value to parse, as each is read. */
int rf_flag_aprs_freq(const char *arg, uint32_t *out);
int rf_flag_aprs_silent_hours(const char *arg, int *out);

/* Whole-command-line checks: each SPEC, and nothing else. A decoder's
 * file is opened by its worker each poll, after the privilege drop,
 * and one that is not there yet is a state, not a refusal. Configures
 * the four readers and announces what each will read. `replay` is
 * `sloth`'s --replay (sloth-rf passes 0). */
int rf_flags_check(const rf_flags_t *f, int replay);

#endif /* SLOTH_RF_FLAGS_H */
