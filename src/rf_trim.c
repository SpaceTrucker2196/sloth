#include <stdio.h>
#include <string.h>

#include "rf_trim.h"
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
    if (f->adsb) {
        adsb_spec_t asp;
        if (adsb_spec_parse(f->adsb, &asp, NULL, 0) == 0 &&
            asp.kind == ADSB_SPEC_FILE) {
            if (log) fprintf(log, "sloth-rf: --adsb %s not started: %s\n",
                             f->adsb, why);
            mark(SYS_SRC_ADSB, f->adsb);
            f->adsb = NULL;
            trimmed++;
        }
    }
    if (f->aprs) {
        char path[256];
        if (aprs_spec_parse(f->aprs, path, sizeof(path), NULL, 0) == 0) {
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
    if (f->rtl433) {
        char path[256];
        if (rtl433_spec_parse(f->rtl433, path, sizeof(path), NULL, 0) == 0) {
            if (log) fprintf(log, "sloth-rf: --rtl433 %s not started: %s\n",
                             f->rtl433, why);
            mark(SYS_SRC_RTL433, f->rtl433);
            f->rtl433 = NULL;
            trimmed++;
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
