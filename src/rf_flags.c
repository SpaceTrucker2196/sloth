#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rf_flags.h"
#include "adsb.h"
#include "aprs.h"
#include "rtl433.h"
#include "victron.h"
#include "capture/adsb_reader.h"
#include "capture/aprs_reader.h"
#include "capture/rtl433_reader.h"
#include "capture/victron_reader.h"

/* src/rf_flags.h. Moved out of src/main.c, text unchanged. */

int rf_flag_aprs_freq(const char *arg, uint32_t *out) {
    if (aprs_freq_parse(arg, out) != 0) {
        fprintf(stderr, "sloth: --aprs-freq %s: want the decoder's "
                        "configured frequency in Hz, 144000000.."
                        "148000000 (e.g. 144390000)\n", arg);
        return 2;
    }
    return 0;
}

int rf_flag_aprs_silent_hours(const char *arg, int *out) {
    char *end = NULL;
    long h = strtol(arg, &end, 10);
    if (!end || end == arg || *end || h < 0 || h > APRS_SILENT_H_MAX) {
        fprintf(stderr, "sloth: --aprs-silent-hours %s: want 0 (off) "
                        "to %d\n", arg, APRS_SILENT_H_MAX);
        return 2;
    }
    *out = (int)h;
    return 0;
}

int rf_flags_check(const rf_flags_t *f, int replay) {
    /* #26 slice 1: --adsb. Only the SPEC is checked here: the file is
     * opened by the worker each poll, after the drop, and a decoder
     * that has not written it yet is a state (waiting / error), not a
     * refusal. */
    if (f->adsb) {
        char aerr[200];
        if (replay) {
            fprintf(stderr, "sloth: --replay reads savefiles, not a live "
                            "decoder: --adsb does not apply\n");
            return 2;
        }
        if (adsb_reader_configure(f->adsb, aerr, sizeof(aerr)) != 0) {
            fprintf(stderr, "sloth: --adsb %s: %s\n", f->adsb, aerr);
            return 2;
        }
        adsb_spec_t asp;
        if (adsb_spec_parse(f->adsb, &asp, NULL, 0) == 0) {
            if (asp.kind == ADSB_SPEC_SBS || asp.kind == ADSB_SPEC_BEAST)
                /* MISSION.md section 2: a network-using input is announced. */
                fprintf(stderr, "sloth: --adsb connecting to the decoder's "
                                "%s output at %s%s%s:%d over TCP after the "
                                "privilege drop (loopback; read-only: sloth "
                                "sends nothing on the socket; no SDR)\n",
                        asp.kind == ADSB_SPEC_BEAST ? "Beast" : "SBS",
                        strchr(asp.host, ':') ? "[" : "", asp.host,
                        strchr(asp.host, ':') ? "]" : "", asp.port);
            else
                fprintf(stderr, "sloth: --adsb reading %s about once a second "
                                "(read-only; no SDR, no network)\n", asp.path);
        }
    }
    /* --aprs: the SPEC only, as --adsb; Dire Wolf creates its log with
     * its first packet, so a file not there yet is a state. */
    if (f->aprs) {
        char aerr[200];
        if (replay) {
            fprintf(stderr, "sloth: --replay reads savefiles, not a live "
                            "decoder: --aprs does not apply\n");
            return 2;
        }
        if (aprs_reader_configure(f->aprs, aerr, sizeof(aerr)) != 0) {
            fprintf(stderr, "sloth: --aprs %s: %s\n", f->aprs, aerr);
            return 2;
        }
        char apath[256];
        if (aprs_spec_parse(f->aprs, apath, sizeof(apath), NULL, 0) == 0)
            fprintf(stderr, "sloth: --aprs tailing %s from its end "
                            "(read-only; no radio, no network)\n", apath);
        aprs_set_expect(f->aprs_freq,
                        f->aprs_silent_h < 0 ? APRS_SILENT_S_DEFAULT
                                             : f->aprs_silent_h * 3600);
    } else if (f->aprs_freq || f->aprs_silent_h >= 0) {
        fprintf(stderr, "sloth: --aprs-freq and --aprs-silent-hours "
                        "describe the --aprs decoder: give --aprs\n");
        return 2;
    }
    /* --rtl433 (#208): the SPEC only, as --aprs. rtl_433 creates its
     * event log with its first decode, so a file not there yet is a
     * state. sloth reads the file and never the SDR. */
    if (f->rtl433) {
        char rerr[200];
        if (replay) {
            fprintf(stderr, "sloth: --replay reads savefiles, not a live "
                            "decoder: --rtl433 does not apply\n");
            return 2;
        }
        if (rtl433_reader_configure(f->rtl433, rerr, sizeof(rerr)) != 0) {
            fprintf(stderr, "sloth: --rtl433 %s: %s\n", f->rtl433, rerr);
            return 2;
        }
        char rpath[256];
        if (rtl433_spec_parse(f->rtl433, rpath, sizeof(rpath), NULL, 0) == 0)
            fprintf(stderr, "sloth: --rtl433 tailing %s from its end "
                            "(read-only; no SDR, no network)\n", rpath);
    }
    /* --victron: sloth-va's output, as --rtl433. sloth-va is the
     * component that connects to the devices (ADR 0011); sloth only
     * reads what it wrote, and creates nothing at the path. */
    if (f->victron) {
        char verr[200];
        if (replay) {
            fprintf(stderr, "sloth: --replay reads savefiles, not a live "
                            "source: --victron does not apply\n");
            return 2;
        }
        if (victron_reader_configure(f->victron, verr, sizeof(verr)) != 0) {
            fprintf(stderr, "sloth: --victron %s: %s\n", f->victron, verr);
            return 2;
        }
        char vpath[256];
        if (victron_spec_parse(f->victron, vpath, sizeof(vpath), NULL, 0) == 0)
            fprintf(stderr, "sloth: --victron tailing %s from its end "
                            "(read-only; sloth-va's file, no Bluetooth)\n", vpath);
    }
    return 0;
}
