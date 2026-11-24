#ifndef SLOTH_ALERT_QUALITY_H
#define SLOTH_ALERT_QUALITY_H

#include <stddef.h>
#include <stdint.h>
#include "sloth.h"
#include "rule_coverage.h"

/* ── Quality fields on each finding (#246) ────────────────────────────
 *
 * FM 2-0 asks of every product whether it is complete, timely and
 * confirmed by another source. A finding carried a confidence and an
 * evidence class; it did not say whether the sensor watched the whole
 * of its evidence, how late the alert was, or whether a second radio
 * agrees. alert_quality_t (include/sloth.h) holds the answers, and this
 * module computes them inside fire_inv(), before the incident's first
 * record goes out. They are evidence about the observation, never an
 * input to a rule: nothing here changes when a rule fires, its
 * severity, key, title or detail.
 *
 *   complete      `full`, or `partial` with one word (cov_reason_t):
 *                 source_down   the rule's input read down
 *                 source_stale  its input delivered nothing lately
 *                 suppressed    SENSOR_SUPPRESSED is open on its evidence
 *                 drops         the monitor handle dropped frames inside
 *                               the window of the cited frames
 *                 hop           a hopping radio was away from a cited
 *                               frame's channel for part of the window
 *                               (to COV_TL_SLACK_MS); for a finding that
 *                               cites no frames, its rule reads partly,
 *                               hop (an EVENT, RATE or EXCHANGE rule
 *                               under --hop)
 *                 in that order of precedence. Not assessed (absent)
 *                 where the coverage assessment is not
 *                 (rule_coverage_live.h: a --replay run, before the
 *                 first status sample) or where it calls the rule
 *                 blind for anything but its source being down.
 *                 `fixed_channel` never makes a finding partial: a
 *                 radio that is not retuned sat on the channel its
 *                 evidence was heard on for the whole window.
 *   latency_ms    the oldest cited frame's capture time to the moment
 *                 the incident opened. Only for a finding that cites
 *                 frames the evidence ring still holds, in an assessed
 *                 run (a replayed file's capture times are not this
 *                 run's clock); absent otherwise, never 0 for unknown.
 *                 The cited frames are the newest the rule kept (at
 *                 most ALERT_EVIDENCE_IDS), so this is a lower bound
 *                 on how long the evidence took to become a finding.
 *   corroboration the monitor radios (src/mon_radios.h) that delivered
 *                 a cited frame, over the incident's life. A radio
 *                 whose copy of a frame lost the cross-radio
 *                 de-duplication to another radio's did not deliver
 *                 it and is not counted, so this is a lower bound on
 *                 the radios that heard the evidence. Absent when no
 *                 cited frame is held; a second site through the mesh
 *                 is out of scope.
 *   src_state     ok, stale or down: the rule's input
 *                 (include/sloth_alert_inputs.def) in this tick's
 *                 coverage environment, the sensor_health word.
 *
 * Two halves, as the coverage assessment is. This file links into
 * both daemons and names no capture module: it reads the coverage
 * status (rule_coverage_live.h) and judges. What the cited frames say
 * (their capture times, channels, radios, the dwell and drop history
 * over their window) is the capture side's: a function on the rule
 * table (alert_rule_table_t.evidence, src/alerts/rules.h), sloth-wifi's
 * being aq_capture_evidence() in src/alert_quality_capture.c. sloth-rf
 * registers none, and its findings carry complete and src_state only. */

typedef enum {
    AQ_COMPLETE_NONE = 0,
    AQ_COMPLETE_FULL,
    AQ_COMPLETE_PARTIAL
} aq_complete_t;

typedef enum {
    AQ_SRC_NONE = 0,
    AQ_SRC_OK,
    AQ_SRC_STALE,
    AQ_SRC_DOWN
} aq_src_t;

/* What the cited frames say, filled by the capture side. */
typedef struct {
    int      n;              /* cited frames the evidence ring still holds */
    int64_t  first_ms;       /* the oldest one's capture time, wall ms */
    int64_t  last_ms;        /* the newest one's */
    uint8_t  radio_mask;     /* bit k: radio k delivered one */
    /* Over [first_ms, last_ms], filled only when asked for: */
    int64_t  uncovered_ms;   /* the most any cited channel was without a
                              * radio, cov_tl_uncovered_ms(); -1 unknown */
    int      drops;          /* cov_tl_drops_in(): 1, 0, -1 unknown */
} aq_evidence_t;

/* The capture side's reader: the frames `ids[0..n)` cite. `window` 0
 * leaves uncovered_ms and drops at -1 (the caller does not need them).
 * Fills *out; the return is out->n. */
typedef int (*aq_evidence_fn)(const uint64_t *ids, int n, int window,
                              aq_evidence_t *out);

/* The judge's inputs: the kind's status in this tick's environment, and
 * the evidence window when there is one. */
typedef struct {
    cov_status_t st;
    cov_reason_t why;
    int          hopping;        /* a radio is retuned on a schedule */
    int          window;         /* cited frames are held: the window is known */
    int64_t      uncovered_ms;   /* -1 unknown */
    int          drops;          /* 1, 0, -1 unknown */
} aq_in_t;

/* `complete` and its word from the inputs. Pure. *why is COV_R_NONE
 * unless the result is AQ_COMPLETE_PARTIAL. */
aq_complete_t aq_judge(const aq_in_t *in, cov_reason_t *why);

/* Stamp a->quality for this evaluation. `opening` 1 when fire_inv()
 * is opening the incident (the latency is taken then), `fire_ms` the
 * wall clock in ms at the fire, `fn` the table's evidence reader or
 * NULL. Reads the coverage status this tick's health stage derived. */
void alert_quality_stamp(alert_t *a, int opening, int64_t fire_ms,
                         aq_evidence_fn fn);

/* Words. "" for out of range and for NONE. */
const char *aq_complete_name(int c);     /* "full", "partial" */
const char *aq_src_name(int s);          /* "ok", "stale", "down" */
/* The cited radios, the exported `corroboration`. */
int aq_corroboration(const alert_quality_t *q);

/* The one line the TUI's alert detail and --report print, e.g.
 * "complete partial (hop), latency 1240 ms, corroboration 2 radios,
 * source ok"; parts not known are left out, and with nothing known the
 * line is "". Length written. */
int alert_quality_line(const alert_quality_t *q, char *out, size_t sz);

/* What a partial finding adds to its title line where a person reads it
 * (the TUI's alert detail, --report): " (partial: hop)"; "" for any
 * other. The alert's `title` field itself never changes: it is the rule
 * name, part of the finding's persisted identity in the stream and in
 * sloth.db (docs/wiki/jsonl-schema.md, `title`). */
const char *alert_quality_title_tag(const alert_quality_t *q, char *buf, size_t sz);

#endif /* SLOTH_ALERT_QUALITY_H */
