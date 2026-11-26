/* Site questions (#244): src/questions.h. */

#include <stdio.h>
#include <string.h>
#include "questions.h"

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
