/* Site questions (#244): src/questions.h. */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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

/* ── The operator's file ──────────────────────────────────────────── */

int q_kind_by_name(const char *name) {
    if (!name) return -1;
    /* As --value-period: with or without the prefix. */
    if (strncmp(name, "ALERT_TYPE_", 11) == 0) name += 11;
    if (!name[0]) return -1;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++)
        if (strcmp(cov_kind_name((alert_type_t)t), name) == 0) return t;
    return -1;
}

/* Trim spaces in place; returns the start. */
static char *trim(char *p) {
    while (*p == ' ' || *p == '\t') p++;
    size_t n = strlen(p);
    while (n && (p[n - 1] == ' ' || p[n - 1] == '\t' || p[n - 1] == '\r')) p[--n] = '\0';
    return p;
}

#define Q_LINE_MAX 2048

static int fail(char *err, size_t errsz, int line, const char *fmt, const char *arg) {
    if (err && errsz) {
        char what[256];
        snprintf(what, sizeof(what), fmt, arg ? arg : "");
        snprintf(err, errsz, "line %d: %s", line, what);
    }
    return -1;
}

static int parse_line(char *ln, int lineno, q_set_t *set, char *err, size_t errsz) {
    char *f[5];
    int nf = 0;
    char *p = ln;
    f[nf++] = p;
    for (; *p; p++) {
        if (*p != '|') continue;
        if (nf == 5) return fail(err, errsz, lineno, "more than five fields", NULL);
        *p = '\0';
        f[nf++] = p + 1;
    }
    if (nf != 5)
        return fail(err, errsz, lineno,
                    "want id|priority|question|decision|KIND,KIND", NULL);
    for (int i = 0; i < 5; i++) f[i] = trim(f[i]);

    const char *id = f[0];
    size_t il = strlen(id);
    if (il == 0 || il >= Q_ID_LEN)
        return fail(err, errsz, lineno, "the id must be 1 to 15 characters", NULL);
    for (size_t i = 0; i < il; i++)
        if (!isalnum((unsigned char)id[i]) && id[i] != '_' && id[i] != '-')
            return fail(err, errsz, lineno, "the id \"%s\" may hold only letters, digits, '_' and '-'", id);
    for (int i = 0; i < set->n; i++)
        if (strcmp(set->q[i].id, id) == 0)
            return fail(err, errsz, lineno, "duplicate id \"%s\"", id);

    char *end = NULL;
    errno = 0;
    long prio = strtol(f[1], &end, 10);
    if (!f[1][0] || *end || errno || prio < 1 || prio > Q_PRIORITY_MAX)
        return fail(err, errsz, lineno, "the priority \"%s\" is not 1 to 9", f[1]);
    if (!f[2][0] || strlen(f[2]) >= Q_TEXT_LEN)
        return fail(err, errsz, lineno, "the question must be 1 to 159 bytes", NULL);
    if (!f[3][0] || strlen(f[3]) >= Q_TEXT_LEN)
        return fail(err, errsz, lineno, "the decision must be 1 to 159 bytes", NULL);
    if (set->n >= Q_MAX)
        return fail(err, errsz, lineno, "more than 32 questions", NULL);

    q_question_t q;
    memset(&q, 0, sizeof(q));
    snprintf(q.id, sizeof(q.id), "%s", id);
    q.priority = (int)prio;
    snprintf(q.text, sizeof(q.text), "%s", f[2]);
    snprintf(q.decision, sizeof(q.decision), "%s", f[3]);
    char *save = NULL;
    for (char *k = strtok_r(f[4], ",", &save); k; k = strtok_r(NULL, ",", &save)) {
        k = trim(k);
        if (!k[0]) continue;
        int t = q_kind_by_name(k);
        if (t < 0) return fail(err, errsz, lineno, "unknown alert kind \"%s\"", k);
        if (!q.kind[t]) q.nkinds++;
        q.kind[t] = 1;
    }
    if (!q.nkinds) return fail(err, errsz, lineno, "no alert kind", NULL);
    set->q[set->n++] = q;
    return 0;
}

int q_set_parse(q_set_t *set, const char *text, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (!set || !text) return -1;
    static q_set_t tmp;   /* ~13 KiB: off the stack */
    memset(&tmp, 0, sizeof(tmp));
    int lineno = 0;
    const char *p = text;
    while (*p) {
        lineno++;
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len >= Q_LINE_MAX) return fail(err, errsz, lineno, "line too long", NULL);
        char ln[Q_LINE_MAX];
        memcpy(ln, p, len);
        ln[len] = '\0';
        char *t = trim(ln);
        if (t[0] && t[0] != '#' && parse_line(t, lineno, &tmp, err, errsz) < 0) return -1;
        if (!eol) break;
        p = eol + 1;
    }
    if (!tmp.n) {
        if (err && errsz) snprintf(err, errsz, "no questions");
        return -1;
    }
    *set = tmp;
    return 0;
}

#define Q_FILE_MAX (64 * 1024)

int q_set_load(q_set_t *set, const char *path, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (!set || !path) return -1;
    FILE *f = fopen(path, "r");
    if (!f) {
        if (err && errsz) snprintf(err, errsz, "cannot open: %s", strerror(errno));
        return -1;
    }
    char *buf = malloc(Q_FILE_MAX + 1);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, Q_FILE_MAX + 1, f);
    int rerr = ferror(f);
    fclose(f);
    if (rerr || n > Q_FILE_MAX) {
        if (err && errsz) snprintf(err, errsz, rerr ? "read failed" : "larger than 64 KiB");
        free(buf);
        return -1;
    }
    buf[n] = '\0';
    if (memchr(buf, '\0', n)) {
        if (err && errsz) snprintf(err, errsz, "not a text file");
        free(buf);
        return -1;
    }
    int rc = q_set_parse(set, buf, err, errsz);
    free(buf);
    return rc;
}
