/* Site questions (#244): src/questions.h. */

#include <stdio.h>
#include <string.h>
#include "questions.h"
#include "alert_lifecycle.h"
#include "rule_coverage_live.h"

/* ── The default tables ───────────────────────────────────────────── */

typedef struct {
    const char *id;
    int         priority;
    const char *text;
    const char *decision;
} q_def_row_t;

static const q_def_row_t k_questions[] = {
#define X(qid, prio, text, decision) { #qid, prio, text, decision },
#include "sloth_questions.def"
#undef X
};

typedef struct {
    unsigned    mask;
    const char *reason;
} q_map_row_t;

static const q_map_row_t k_map[] = {
#define X(id, qmask, reason) { qmask, reason },
#include "sloth_question_map.def"
#undef X
};

/* A row appended to sloth_alerts.def with none in the map fails the
 * build before it fails the test; so does an eighth default question
 * past what a mask holds. */
typedef char q_map_matches_kinds[
    (sizeof(k_map) / sizeof(k_map[0]) == ALERT_TYPE_COUNT) ? 1 : -1];
typedef char q_defaults_fit_a_mask[(Q_DEFAULT_COUNT <= 32 && Q_DEFAULT_COUNT <= Q_MAX) ? 1 : -1];

unsigned q_default_mask(alert_type_t t) {
    if ((int)t < 0 || t >= ALERT_TYPE_COUNT) return 0;
    return k_map[t].mask;
}

const char *q_default_reason(alert_type_t t) {
    if ((int)t < 0 || t >= ALERT_TYPE_COUNT) return "";
    return k_map[t].reason;
}

static const q_def_row_t *qrow(int i) {
    return (i >= 0 && i < Q_DEFAULT_COUNT) ? &k_questions[i] : NULL;
}
const char *q_default_id(int i)       { const q_def_row_t *r = qrow(i); return r ? r->id : ""; }
int         q_default_priority(int i) { const q_def_row_t *r = qrow(i); return r ? r->priority : 0; }
const char *q_default_text(int i)     { const q_def_row_t *r = qrow(i); return r ? r->text : ""; }
const char *q_default_decision(int i) { const q_def_row_t *r = qrow(i); return r ? r->decision : ""; }

void q_set_defaults(q_set_t *set) {
    if (!set) return;
    memset(set, 0, sizeof(*set));
    for (int i = 0; i < Q_DEFAULT_COUNT; i++) {
        q_question_t *q = &set->q[set->n++];
        snprintf(q->id, sizeof(q->id), "%s", k_questions[i].id);
        q->priority = k_questions[i].priority;
        snprintf(q->text, sizeof(q->text), "%s", k_questions[i].text);
        snprintf(q->decision, sizeof(q->decision), "%s", k_questions[i].decision);
        for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
            if (!(k_map[t].mask & (1u << i))) continue;
            q->kind[t] = 1;
            q->nkinds++;
        }
    }
}

/* ── Status ───────────────────────────────────────────────────────── */

const char *q_status_name(q_status_t st) {
    switch (st) {
    case Q_ST_FINDING:           return "finding";
    case Q_ST_NO_FINDING:        return "no_finding";
    case Q_ST_NO_FINDING_PARTLY: return "no_finding_partly";
    case Q_ST_NOT_OBSERVABLE:    return "not_observable";
    case Q_ST_NOT_ASSESSED:      return "not_assessed";
    case Q_ST_COUNT:             break;
    }
    return "";
}

void q_cov_from_env(q_cov_t *c, cov_daemon_t d, const cov_env_t *env) {
    if (!c) return;
    memset(c, 0, sizeof(*c));
    c->assessed = env != NULL;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        c->raises[t] = (uint8_t)cov_daemon_raises(d, (alert_type_t)t);
        if (!c->raises[t] || !env) continue;
        cov_reason_t why = COV_R_NONE;
        c->st[t]  = (uint8_t)cov_rule_status((alert_type_t)t, env, &why);
        c->why[t] = (uint8_t)why;
    }
}

int q_alert_open(const alert_t *a) {
    return a && !a->resolved && a->state != ALERT_STATE_WITHDRAWN;
}

int q_derive(const q_question_t *q, const alert_t *a, int n, const q_cov_t *c,
             q_result_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!q || !c) return 0;
    cov_reason_t first_blind = COV_R_NONE, first_partly = COV_R_NONE;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        if (!q->kind[t] || !c->raises[t]) continue;
        out->kinds++;
        if (!c->assessed) continue;
        cov_reason_t why = (cov_reason_t)c->why[t];
        switch ((cov_status_t)c->st[t]) {
        case COV_OBSERVABLE: out->observable++; break;
        case COV_PARTLY:
            out->partly++;
            if (first_partly == COV_R_NONE) first_partly = why;
            break;
        case COV_BLIND:
            out->blind++;
            if (first_blind == COV_R_NONE) first_blind = why;
            break;
        }
    }
    if (!out->kinds) return 0;
    out->why = first_blind != COV_R_NONE ? first_blind : first_partly;

    for (int i = 0; a && i < n; i++) {
        const alert_t *al = &a[i];
        if ((int)al->type < 0 || al->type >= ALERT_TYPE_COUNT) continue;
        if (!q->kind[al->type] || !c->raises[al->type] || !q_alert_open(al)) continue;
        out->n_alerts++;
        out->found[al->type] = 1;
        if (out->nids < Q_IDS_MAX && al->incident_id[0])
            snprintf(out->ids[out->nids++], ALERT_INCIDENT_ID_LEN, "%s", al->incident_id);
    }

    if (out->n_alerts)                    out->st = Q_ST_FINDING;
    else if (!c->assessed)                out->st = Q_ST_NOT_ASSESSED;
    else if (out->blind == out->kinds)    out->st = Q_ST_NOT_OBSERVABLE;
    else if (out->blind || out->partly)   out->st = Q_ST_NO_FINDING_PARTLY;
    else                                  out->st = Q_ST_NO_FINDING;
    return 1;
}

int q_found_str(const uint8_t found[ALERT_TYPE_COUNT], char *out, size_t sz) {
    if (!out || !sz) return 0;
    out[0] = '\0';
    size_t off = 0;
    for (int t = 0; found && t < ALERT_TYPE_COUNT; t++) {
        if (!found[t]) continue;
        int k = snprintf(out + off, sz - off, "%s%s", off ? "," : "",
                         cov_kind_name((alert_type_t)t));
        if (k < 0 || (size_t)k >= sz - off) { out[off] = '\0'; break; }
        off += (size_t)k;
    }
    return (int)off;
}
