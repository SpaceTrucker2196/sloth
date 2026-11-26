#ifndef SLOTH_SWEEP_RUN_H
#define SLOTH_SWEEP_RUN_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "sweep.h"

/* ── sloth --sweep LABEL --sweep-minutes N (#249) ────────────────────
 *
 * The run around src/sweep.c: the label's files, the poll tick that
 * keeps the inventory and the coverage, the end, and the writes. main.c
 * holds one of these for a sweep run and calls the three steps; the
 * flag checks are sweep_run_check_*() so a test reaches them.
 *
 * Files, all in the sweep directory (--sweep-dir, or the --db file's
 * directory), all 0600 through secure_file:
 *
 *   sweep-LABEL.baseline.tsv        the accepted baseline, snapshot v2.
 *                                   Read here, never written: accepting
 *                                   a sweep is slothweb's (owner ruling
 *                                   2026-11-25, sloth-mesh).
 *   sweep-LABEL.<UTC start>.tsv     this sweep's inventory, snapshot v2,
 *                                   what an accept copies to the
 *                                   baseline
 *   sweep-LABEL.<UTC start>.md      the report
 *   sweep-LABEL.<UTC start>.json    the same as JSON
 *
 * The three per-sweep files are created O_EXCL: a sweep never replaces
 * another's record. */

#define SWEEP_LABEL_MAX   48
#define SWEEP_MINUTES_MAX 1440
#define SWEEP_PATH_MAX    1024

/* A label is 1..SWEEP_LABEL_MAX of [A-Za-z0-9._-], not starting with
 * '.' or '-': it is part of four file names. 1 valid. */
int sweep_label_ok(const char *label);
/* "N" in 1..SWEEP_MINUTES_MAX, the whole string. 0, or -1. */
int sweep_minutes_parse(const char *s, unsigned *out);

typedef struct {
    char         label[SWEEP_LABEL_MAX + 1];
    char         dir[SWEEP_PATH_MAX];
    unsigned     minutes;
    time_t       start;
    uint64_t     start_ms;
    char         baseline[SWEEP_PATH_MAX];
    int          base_version;        /* 0 none */
    sw_inv_t    *inv;                 /* heard */
    sw_inv_t    *base;                /* read from the baseline, NULL none */
    sw_cov_t     cov;
    int          done;
    int          end_why;
} sweep_run_t;

/* The label's baseline, checked before anything opens (main.c exits 2
 * on -1, as on any other refusal): 1 present and readable, 0 none yet,
 * -1 with `err` filled (not a regular file, not readable, a path that
 * does not fit). sweep_run_begin() reads it again for the run. */
int  sweep_baseline_check(const char *dir, const char *label, char *err,
                          size_t errsz);

/* Start: read the label's baseline if there is one, allocate, and take
 * the plan from `full` (chanhop_init_sweep()'s list). 0, or -1 with
 * `err` filled (no memory, a baseline that cannot be read). */
int  sweep_run_begin(sweep_run_t *r, const char *label, unsigned minutes,
                     const char *dir, const chanhop_t *full,
                     uint64_t now_ms, time_t wall, char *err, size_t errsz);

/* One poll, after poll_data(): merge the state's tables in, sample
 * every radio's scheduler (h0, then the further radios' through
 * mon_hop_sched()), and decide the end. Returns 1 once the sweep is
 * over: the time given ran out, or every radio holding a share
 * finished its pass. */
int  sweep_run_tick(sweep_run_t *r, const sloth_state_t *s,
                    const chanhop_t *h0, uint64_t now_ms);

/* The end: compare, write the inventory and the two reports, emit the
 * sweep_report record, one stderr line per file. `stopped` 1 when the
 * run ended before sweep_run_tick() said so (a signal, q). 0 when every
 * file was written, -1 otherwise. Frees what begin allocated. */
int  sweep_run_finish(sweep_run_t *r, const sloth_state_t *s, int stopped,
                      int ble_configured, time_t wall, FILE *msg);

/* Frees without writing. */
void sweep_run_free(sweep_run_t *r);

/* The baseline path and the per-sweep stem (no extension) for a label;
 * -1 when they do not fit. */
int  sweep_baseline_path(const char *dir, const char *label, char *out, size_t n);
int  sweep_record_stem(const char *dir, const char *label, time_t start,
                       char *out, size_t n);

#endif /* SLOTH_SWEEP_RUN_H */
