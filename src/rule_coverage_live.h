#ifndef SLOTH_RULE_COVERAGE_LIVE_H
#define SLOTH_RULE_COVERAGE_LIVE_H

#include "sloth.h"
#include "rule_coverage.h"
#include "sys_status.h"

/* ── Coverage assessment, the running half (#242 slice 2) ─────────────
 *
 * rule_coverage.h is the pure half: the declarations and the status
 * derived from an environment. This file builds the environment each
 * tick from what the daemon has, keeps the status of every kind this
 * daemon raises, and writes it:
 *
 *   rule_status   one record per kind, when its status or reason
 *                 changes, and on the stream's heartbeat
 *   coverage      one record with the three counts and the radio
 *                 figures the 802.11 statuses were derived from, when
 *                 any of them changes, and on the heartbeat
 *
 * sensor_health carries the three counts as well (jsonl_sh_tail()).
 *
 * The inputs come from the source rows (src/sys_status.h), so a daemon
 * that reports no row for an input has none of it. The 802.11 figures,
 * the host tables and the operator's configuration belong to the daemon
 * with the capture: it registers a filler (src/rule_coverage_capture.c,
 * from capture_side_install()), which keeps the radio table and the
 * ownership module out of sloth-rf's link. Unregistered, those fields
 * stay zero.
 *
 * Receive-only: every figure is one sloth already holds. Nothing here
 * opens a device, retunes a radio or sends anything. */

/* Fill env->input[COV_IN_HOST], bands, radios, channels, hopping and
 * config. The source-derived inputs are already filled; a filler may
 * leave them.
 *
 * Returns 0 when there is nothing to assess, and then no status is
 * kept and no record written: a --replay run reads files, and "which
 * rules can this sensor's radios feed" is not a question about a file.
 * (Its source rows read `down`, since no device is open, while every
 * frame of the file reaches the rules: a status derived from them would
 * call a replay blind while it raises alerts.) */
typedef int (*cov_side_fn)(const sloth_state_t *s, cov_env_t *env);

/* Which daemon this is and its filler (NULL for none). Once, at start;
 * also drops what was last derived. */
void cov_live_set_side(cov_daemon_t daemon, cov_side_fn fill);

/* The poll loop's hook: after sys_status_poll(), whose rows it reads.
 * Nothing before the first system sample. */
void cov_live_poll(const sloth_state_t *s);

/* The JSONL hook: the rows that are due and the summary. */
void cov_live_emit(void);

/* 1 once a status has been derived. */
int cov_live_valid(void);

/* Why there is no status, for a reader that must say so rather than
 * print zero counts (the posture report, the Stats view; #242 item 3):
 *   COV_LIVE_PENDING   no system sample has been taken yet (the first
 *                      tick has not run, or this is a test)
 *   COV_LIVE_DECLINED  the side's filler declined: a --replay run
 *   COV_LIVE_VALID     a status is kept (cov_live_valid() is 1) */
typedef enum { COV_LIVE_PENDING = 0, COV_LIVE_DECLINED, COV_LIVE_VALID } cov_live_state_t;
cov_live_state_t cov_live_state(void);
/* One sentence for a state that is not VALID; "" for VALID. */
const char *cov_live_state_why(cov_live_state_t st);

/* The kinds that are not observable, grouped by status and reason:
 * the blind groups first, then the partly ones, each in the precedence
 * order of cov_rule_status() (the first thing to fix first), and the
 * kinds of a group in sloth_alerts.def order. Empty groups are left
 * out; every partly and blind kind is in exactly one group, so the
 * groups' sizes add up to cov_live_counts()' partly + blind. `out`
 * holds COV_GAP_MAX groups to be sure of that. Returns the groups
 * written, 0 when nothing is derived. */
#define COV_GAP_MAX (2 * COV_R_COUNT)
typedef struct {
    cov_status_t st;
    cov_reason_t why;
    int          n;
    alert_type_t kind[ALERT_TYPE_COUNT];
} cov_gap_t;
int cov_live_gaps(cov_gap_t *out, int max);

/* "EVIL_TWIN" for ALERT_TYPE_EVIL_TWIN: the spelling of sloth_alerts.def
 * and of the `kind` of a rule_status record. */
const char *cov_kind_name(alert_type_t t);

/* The two limits of docs/wiki/coverage-assessment.md § 5 that every
 * reader of a status needs beside it, as the report and the Stats view
 * print them. tests/test_posture.c holds each to that page verbatim. */
#define COV_LIMIT_COUNT 2
extern const char *const cov_limits[COV_LIMIT_COUNT];
/* The status of `t` in this daemon; 0 (and nothing written) when the
 * kind is another daemon's, out of range, or nothing is derived yet. */
int cov_live_get(alert_type_t t, cov_status_t *st, cov_reason_t *why);
/* How many of this daemon's kinds read each status; zeroes before the
 * first derivation. Any pointer may be NULL. */
void cov_live_counts(int *observable, int *partly, int *blind);
const cov_env_t *cov_live_env(void);
/* Which daemon this is (cov_live_set_side()). */
cov_daemon_t cov_live_daemon(void);

/* The environment the source rows give, for tests: every input the
 * rows of `sn` answer for. */
void cov_env_from_sources(const sys_snapshot_t *sn, cov_env_t *env);

void cov_live_reset(void);

/* src/rule_coverage_capture.c: the capture side's filler. */
int cov_capture_fill(const sloth_state_t *s, cov_env_t *env);

#endif /* SLOTH_RULE_COVERAGE_LIVE_H */
