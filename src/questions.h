#ifndef SLOTH_QUESTIONS_H
#define SLOTH_QUESTIONS_H

#include <stddef.h>
#include <stdint.h>
#include "sloth.h"
#include "rule_coverage.h"

/* ── Site questions (#244) ───────────────────────────────────────────
 *
 * About a hundred alert kinds and no list of what the operator wants to
 * know. A site question is one question in plain words, the decision it
 * supports, a priority, and the alert kinds that are its indicators
 * (FM 2-0 (2004) figure 1-2: priority question, indicators, collection;
 * 1-34: one question, supporting a decision). Each question gets a
 * status from the alerts held now and the coverage status of its
 * indicators (rule_coverage.h), so an empty answer says whether the
 * sensor could have seen anything.
 *
 * The seven default questions are include/sloth_questions.def; which
 * kind answers which is include/sloth_question_map.def. Receive-only:
 * everything here is derived from findings and figures sloth already
 * holds. */

/* The default questions, in sloth_questions.def order. */
typedef enum {
#define X(qid, prio, text, decision) Q_ID_##qid,
#include "sloth_questions.def"
#undef X
    Q_DEFAULT_COUNT
} q_default_t;

/* A default question's bit in a QMASK of sloth_question_map.def. */
#define QM(qid) (1u << Q_ID_##qid)

/* The default table's row for `t`: the mask of the questions the kind
 * answers, and why it answers none ("" when it answers one). 0 and ""
 * out of range. */
unsigned    q_default_mask(alert_type_t t);
const char *q_default_reason(alert_type_t t);

/* A default question's own columns; "" / 0 out of range. */
const char *q_default_id(int i);
int         q_default_priority(int i);
const char *q_default_text(int i);
const char *q_default_decision(int i);

#define Q_MAX          32
#define Q_ID_LEN       16
#define Q_TEXT_LEN     160
#define Q_PRIORITY_MAX 9

typedef struct {
    char    id[Q_ID_LEN];          /* [A-Za-z0-9_-], 1..15 characters */
    int     priority;              /* 1 (most urgent) .. Q_PRIORITY_MAX */
    char    text[Q_TEXT_LEN];
    char    decision[Q_TEXT_LEN];
    uint8_t kind[ALERT_TYPE_COUNT];/* 1: the kind is an indicator */
    int     nkinds;
} q_question_t;

typedef struct {
    int          n;
    q_question_t q[Q_MAX];
} q_set_t;

/* The seven default questions with their indicators. */
void q_set_defaults(q_set_t *set);

/* ── A question's status ──────────────────────────────────────────────
 *
 *   finding            an indicator has an open finding (preliminary,
 *                      confirmed or lapsed; not withdrawn, not resolved)
 *   no_finding         none, and every indicator is observable
 *   no_finding_partly  none, and some indicator is partly observable or
 *                      blind
 *   not_observable     none, and every indicator is blind
 *   not_assessed       none, and there is no coverage status (before
 *                      the first sample, or a --replay run)
 * A finding is reported whatever the coverage: a replayed evil twin is a
 * finding beside coverage that was never assessed. Appended only: the
 * words are written to the stream and to sloth.db. */
typedef enum {
    Q_ST_FINDING = 0,
    Q_ST_NO_FINDING,
    Q_ST_NO_FINDING_PARTLY,
    Q_ST_NOT_OBSERVABLE,
    Q_ST_NOT_ASSESSED,
    Q_ST_COUNT
} q_status_t;
const char *q_status_name(q_status_t st);

/* What a daemon has of each kind's coverage: which kinds it raises
 * (cov_daemon_raises()) and, when `assessed`, each one's status. */
typedef struct {
    int     assessed;
    uint8_t raises[ALERT_TYPE_COUNT];
    uint8_t st[ALERT_TYPE_COUNT];    /* cov_status_t */
    uint8_t why[ALERT_TYPE_COUNT];   /* cov_reason_t */
} q_cov_t;

/* The coverage `d` has under `env` (cov_rule_status()); a NULL `env`
 * leaves it not assessed. Pure: what tests build by hand. */
void q_cov_from_env(q_cov_t *c, cov_daemon_t d, const cov_env_t *env);

#define Q_IDS_MAX 8

typedef struct {
    q_status_t   st;
    int          kinds;         /* indicators this daemon raises */
    int          observable, partly, blind;   /* of them, when assessed */
    cov_reason_t why;           /* first blind reason, else first partly
                                 * one, in sloth_alerts.def order */
    int          n_alerts;      /* open findings on the indicators */
    int          nids;          /* their incident ids, newest first */
    char         ids[Q_IDS_MAX][ALERT_INCIDENT_ID_LEN];
    uint8_t      found[ALERT_TYPE_COUNT];     /* 1: a kind with a finding */
} q_result_t;

/* 1 when `a` is an open finding: not resolved, not withdrawn. */
int q_alert_open(const alert_t *a);

/* The status of `q` from the `n` alerts at `a` (a daemon's snapshot,
 * newest first) and its coverage `c`. Returns 0, with `out` zeroed, when
 * none of the question's indicators is raised by this daemon: such a
 * question has no answer here and is not reported. */
int q_derive(const q_question_t *q, const alert_t *a, int n, const q_cov_t *c,
             q_result_t *out);

/* Comma-joined kind names of `found` ("EVIL_TWIN,KARMA_AP"), "" for
 * none; the length written, truncating at sz-1. */
int q_found_str(const uint8_t found[ALERT_TYPE_COUNT], char *out, size_t sz);

/* ── The operator's questions (--questions PATH) ─────────────────────
 *
 * The operator's own file (owner ruling 2026-11-25; sloth-mesh may
 * write it later). One question per line:
 *
 *   id|priority|question|decision|KIND,KIND,...
 *
 * `#` starts a comment line; blank lines are skipped; spaces around a
 * field are dropped. id is 1..15 of [A-Za-z0-9_-]; priority 1..9; the
 * question and the decision are non-empty and under Q_TEXT_LEN bytes;
 * the kinds are sloth_alerts.def names (EVIL_TWIN; ALERT_TYPE_EVIL_TWIN
 * too), at least one.
 * Refused, with the line number: an unknown kind, a duplicate id, a
 * field missing or out of range, more than Q_MAX questions, none at
 * all. A refused file leaves `set` as it was.
 *
 * Returns 0 and fills `set`, or -1 with one sentence in `err`. */
int q_set_parse(q_set_t *set, const char *text, char *err, size_t errsz);
/* The same from a file of at most 64 KiB. */
int q_set_load(q_set_t *set, const char *path, char *err, size_t errsz);

/* The kind named `name` (sloth_alerts.def spelling, with or without
 * ALERT_TYPE_, as --value-period takes it); -1 for none. */
int q_kind_by_name(const char *name);

#endif /* SLOTH_QUESTIONS_H */
