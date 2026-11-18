#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "rf_trim.h"
#include "sloth_clock.h"
#include "adsb.h"
#include "aprs.h"
#include "rtl433.h"
#include "sys_status.h"

/* src/rf_trim.h. */

static struct {
    int  trimmed[SYS_SRC_COUNT];
    char spec[SYS_SRC_COUNT][64];
} g_trim;

void rf_trim_reset(void) { memset(&g_trim, 0, sizeof(g_trim)); }

int rf_trim_detect(char *desc, int cap) {
    int r = sys_usb_has_kind("sdr", desc, cap);
    return r > 0 ? RF_SDR_PRESENT : r == 0 ? RF_SDR_ABSENT : RF_SDR_UNKNOWN;
}

static void mark(int id, const char *spec) {
    g_trim.trimmed[id] = 1;
    snprintf(g_trim.spec[id], sizeof(g_trim.spec[id]), "%s", spec);
}

/* The mtime lookup behind the fail-open guard: 0 with *mtime set, or
 * the errno stat() failed with. */
static int real_mtime(const char *path, time_t *mtime) {
    struct stat st;
    if (stat(path, &st) != 0) return errno ? errno : EIO;
    *mtime = st.st_mtime;
    return 0;
}

static int (*g_mtime)(const char *, time_t *) = real_mtime;

void rf_trim_test_set_mtime(int (*fn)(const char *path, time_t *mtime)) {
    g_mtime = fn ? fn : real_mtime;
}

enum { FRESH_NO = 0, FRESH_YES, FRESH_UNKNOWN };

/* The fail-open guard (src/rf_trim.h). FRESH_YES when `path` was
 * modified within `window` s of now, or in the future (a clock that
 * disagrees is not proof the feed stopped), with its age into *age
 * (negative: ahead of now). FRESH_NO when it is older, or not there
 * (ENOENT, ENOTDIR): trimmed as before. FRESH_UNKNOWN, with the errno
 * into *err, for any other stat() failure - EACCES on a directory the
 * service user cannot search, ProtectHome= over a /home path: the
 * file may well be fed, so fail open and let its reader report the
 * real reason (down, permission denied) instead of "no SDR". The
 * comparison is done in time_t before any subtraction, and the age is
 * clamped, so a corrupt or far-future mtime cannot overflow a 32-bit
 * long. */
static int written_recently(const char *path, long window, long *age,
                            int *err) {
    time_t m;
    const int e = g_mtime(path, &m);
    if (e == ENOENT || e == ENOTDIR) return FRESH_NO;
    if (e != 0) { *err = e; return FRESH_UNKNOWN; }
    const time_t now = sloth_wall();
    /* m > now and m <= now are compared, never subtracted, so the
     * difference is taken only in the direction where it is positive,
     * and in unsigned arithmetic, where it cannot overflow. */
    const unsigned long long d = m > now
        ? (unsigned long long)m - (unsigned long long)now
        : (unsigned long long)now - (unsigned long long)m;
    const long a = d > (unsigned long long)LONG_MAX ? LONG_MAX : (long)d;
    if (m > now) { *age = -a; return FRESH_YES; }
    *age = a;
    return d <= (unsigned long long)window ? FRESH_YES : FRESH_NO;
}

/* One line for an input kept by the guard, in the trim lines' shape. */
static void say_kept(FILE *log, const char *flag, const char *spec, int fresh,
                     long age, int err, long window) {
    if (!log) return;
    if (fresh == FRESH_UNKNOWN)
        fprintf(log, "sloth-rf: %s %s kept: no SDR on USB but its file "
                     "could not be checked (%s); its reader reports it\n",
                flag, spec, strerror(err));
    else if (age < 0)
        fprintf(log, "sloth-rf: %s %s kept: no SDR on USB but its file's "
                     "mtime is %ld s ahead of the clock (clock skew; read as "
                     "another feed writing it)\n", flag, spec, -age);
    else
        fprintf(log, "sloth-rf: %s %s kept: no SDR on USB but its file was "
                     "written %ld s ago (another feed writes it; trimmed "
                     "when unwritten for %ld s)\n", flag, spec, age, window);
}

int rf_trim_apply(rf_flags_t *f, int have_gps, int no_trim, int sdr,
                  const char *sdr_desc, FILE *log) {
    rf_trim_reset();
    if (!f) return RF_TRIM_GO;
    const int any_local = f->adsb || f->aprs || f->rtl433;
    if (no_trim) {
        if (any_local && log)
            fprintf(log, "sloth-rf: --no-sdr-trim: every decoder input is "
                         "started whatever USB lists\n");
        return RF_TRIM_GO;
    }
    if (sdr == RF_SDR_PRESENT) {
        if (any_local && log)
            fprintf(log, "sloth-rf: SDR attached: %s; decoder inputs kept\n",
                    sdr_desc && sdr_desc[0] ? sdr_desc : "(unnamed)");
        return RF_TRIM_GO;
    }
    if (sdr != RF_SDR_ABSENT) {
        if (any_local && log)
            fprintf(log, "sloth-rf: cannot list /sys/bus/usb/devices: no "
                         "input trimmed\n");
        return RF_TRIM_GO;
    }

    /* No SDR. A SPEC that does not parse is not trimmed: rf_flags_check()
     * refuses it with the words it always has, on every host alike. */
    static const char why[] = "no SDR on USB at startup (no known SDR "
                              "USB ID under /sys/bus/usb/devices); "
                              "--no-sdr-trim keeps it";
    int trimmed = 0;
    long age = 0;
    int err = 0, fresh;
    if (f->adsb) {
        adsb_spec_t asp;
        if (adsb_spec_parse(f->adsb, &asp, NULL, 0) == 0 &&
            asp.kind == ADSB_SPEC_FILE) {
            fresh = written_recently(asp.path, RF_TRIM_FRESH_ADSB_S, &age, &err);
            if (fresh != FRESH_NO) {
                say_kept(log, "--adsb", f->adsb, fresh, age, err,
                         RF_TRIM_FRESH_ADSB_S);
            } else {
                if (log) fprintf(log, "sloth-rf: --adsb %s not started: %s\n",
                                 f->adsb, why);
                mark(SYS_SRC_ADSB, f->adsb);
                f->adsb = NULL;
                trimmed++;
            }
        }
    }
    if (f->aprs) {
        char path[256];
        if (aprs_spec_parse(f->aprs, path, sizeof(path), NULL, 0) == 0) {
            fresh = written_recently(path, RF_TRIM_FRESH_EVENTS_S, &age, &err);
            if (fresh != FRESH_NO) {
                say_kept(log, "--aprs", f->aprs, fresh, age, err,
                         RF_TRIM_FRESH_EVENTS_S);
            } else {
                if (log) fprintf(log, "sloth-rf: --aprs %s not started%s: %s\n",
                                 f->aprs,
                                 f->aprs_freq || f->aprs_silent_h >= 0
                                     ? " (with its --aprs-freq / "
                                       "--aprs-silent-hours)" : "",
                                 why);
                mark(SYS_SRC_APRS, f->aprs);
                f->aprs = NULL;
                /* They describe the decoder just trimmed; left set they
                 * would be refused as qualifiers with no --aprs. */
                f->aprs_freq = 0;
                f->aprs_silent_h = -1;
                trimmed++;
            }
        }
    }
    if (f->rtl433) {
        char path[256];
        if (rtl433_spec_parse(f->rtl433, path, sizeof(path), NULL, 0) == 0) {
            fresh = written_recently(path, RF_TRIM_FRESH_EVENTS_S, &age, &err);
            if (fresh != FRESH_NO) {
                say_kept(log, "--rtl433", f->rtl433, fresh, age, err,
                         RF_TRIM_FRESH_EVENTS_S);
            } else {
                if (log) fprintf(log, "sloth-rf: --rtl433 %s not started: %s\n",
                                 f->rtl433, why);
                mark(SYS_SRC_RTL433, f->rtl433);
                f->rtl433 = NULL;
                trimmed++;
            }
        }
    }
    if (trimmed && !f->adsb && !f->aprs && !f->rtl433 && !f->victron && !have_gps)
        return RF_TRIM_NOTHING_LEFT;
    return RF_TRIM_GO;
}

int rf_trim_trimmed(int id, char *spec, int cap) {
    if (id < 0 || id >= SYS_SRC_COUNT || !g_trim.trimmed[id]) return 0;
    if (spec && cap > 0) snprintf(spec, (size_t)cap, "%s", g_trim.spec[id]);
    return 1;
}
