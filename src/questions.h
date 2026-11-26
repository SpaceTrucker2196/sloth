#ifndef SLOTH_QUESTIONS_H
#define SLOTH_QUESTIONS_H

#include <stddef.h>
#include <stdint.h>
#include "sloth_alert.h"

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

#endif /* SLOTH_QUESTIONS_H */
