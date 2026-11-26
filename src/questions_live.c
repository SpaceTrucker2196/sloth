/* Site questions, the running half (#244): src/questions_live.h. */

#include <string.h>
#include "questions_live.h"
#include "rule_coverage_live.h"
#include "jsonl.h"
#include "jsonl_internal.h"
#include "sloth_clock.h"

static struct {
    int     loaded;            /* set holds the file's questions */
    q_set_t set;
    char    path[256];
} g;

static void ensure(void) {
    if (!g.loaded && g.set.n == 0) q_set_defaults(&g.set);
}

void q_live_reset(void) {
    memset(&g, 0, sizeof(g));
    q_set_defaults(&g.set);
}

const q_set_t *q_live_questions(void) { ensure(); return &g.set; }
const char *q_live_path(void) { return g.loaded ? g.path : ""; }

int q_live_flag(const char *path) {
    if (!path || !path[0]) {
        fprintf(stderr, "sloth: --questions needs a PATH\n");
        return 2;
    }
    static q_set_t set;
    char err[256];
    if (q_set_load(&set, path, err, sizeof(err)) != 0) {
        fprintf(stderr, "sloth: --questions %s: %s\n", path, err);
        return 2;
    }
    g.set = set;
    g.loaded = 1;
    snprintf(g.path, sizeof(g.path), "%s", path);
    return 0;
}

void q_live_cov(q_cov_t *c) {
    if (!c) return;
    memset(c, 0, sizeof(*c));
    c->assessed = cov_live_state() == COV_LIVE_VALID;
    cov_daemon_t d = cov_live_daemon();
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        c->raises[t] = (uint8_t)cov_daemon_raises(d, (alert_type_t)t);
        cov_status_t st;
        cov_reason_t why;
        if (!c->assessed || !c->raises[t] || !cov_live_get((alert_type_t)t, &st, &why))
            continue;
        c->st[t]  = (uint8_t)st;
        c->why[t] = (uint8_t)why;
    }
}

int q_live_answers(const sloth_state_t *s, q_answer_t out[Q_MAX]) {
    if (!out) return 0;
    ensure();
    q_cov_t c;
    q_live_cov(&c);
    int n = 0;
    for (int prio = 1; prio <= Q_PRIORITY_MAX; prio++) {
        for (int i = 0; i < g.set.n && n < Q_MAX; i++) {
            if (g.set.q[i].priority != prio) continue;
            q_answer_t *a = &out[n];
            if (!q_derive(&g.set.q[i], s ? s->alerts : NULL,
                          s ? (s->alert_count < MAX_ALERTS ? s->alert_count : MAX_ALERTS) : 0,
                          &c, &a->r))
                continue;
            a->qi = i;
            n++;
        }
    }
    return n;
}

static void ids_str(const q_result_t *r, char *out, size_t sz) {
    out[0] = '\0';
    size_t off = 0;
    for (int i = 0; i < r->nids; i++) {
        int k = snprintf(out + off, sz - off, "%s%s", off ? "," : "", r->ids[i]);
        if (k < 0 || (size_t)k >= sz - off) { out[off] = '\0'; break; }
        off += (size_t)k;
    }
}

/* ── The report ───────────────────────────────────────────────────── */

static void md_statement(FILE *out, const q_result_t *r) {
    const char *why = cov_reason_name(r->why);
    char kinds[1024];
    switch (r->st) {
    case Q_ST_FINDING: {
        q_found_str(r->found, kinds, sizeof(kinds));
        char ids[Q_IDS_MAX * ALERT_INCIDENT_ID_LEN + 16];
        ids_str(r, ids, sizeof(ids));
        fprintf(out, "**Finding**: %d open finding%s (%s); incident%s %s%s.",
                r->n_alerts, r->n_alerts == 1 ? "" : "s", kinds,
                r->nids == 1 ? "" : "s", ids, r->n_alerts > r->nids ? ", ..." : "");
        break;
    }
    case Q_ST_NO_FINDING:
        fprintf(out, "**No finding**; indicators observable.");
        break;
    case Q_ST_NO_FINDING_PARTLY:
        fprintf(out, "**No finding**; indicators partly observable: %s.", why[0] ? why : "?");
        break;
    case Q_ST_NOT_OBSERVABLE:
        fprintf(out, "**Not observable**: %s.", why[0] ? why : "?");
        break;
    case Q_ST_NOT_ASSESSED:
        fprintf(out, "**No finding**; coverage not assessed: %s.",
                cov_live_state_why(cov_live_state()));
        break;
    case Q_ST_COUNT:
        break;
    }
}

static void md_coverage(FILE *out, const q_result_t *r) {
    if (cov_live_state() != COV_LIVE_VALID) {
        fprintf(out, " Indicators: %d, not assessed.", r->kinds);
        return;
    }
    fprintf(out, " Indicators: %d; observable %d, partly %d, blind %d.", r->kinds,
            r->observable, r->partly, r->blind);
}

void q_report_md(FILE *out, const sloth_state_t *s) {
    if (!out) return;
    ensure();
    fprintf(out, "## Site questions\n\n");
    if (g.loaded)
        fprintf(out, "The operator's questions (`--questions %s`), ", g.path);
    else
        fprintf(out, "The seven default questions, ");
    fprintf(out, "most urgent first. Each says whether the alert kinds that answer "
                 "it could see: no finding is not nothing there "
                 "(docs/wiki/site-questions.md).\n\n");
    q_answer_t ans[Q_MAX];
    int n = q_live_answers(s, ans);
    uint8_t answered[Q_MAX] = { 0 };
    for (int i = 0; i < n; i++) {
        const q_question_t *q = &g.set.q[ans[i].qi];
        answered[ans[i].qi] = 1;
        fprintf(out, "### %s (priority %d): %s\n\n", q->id, q->priority, q->text);
        md_statement(out, &ans[i].r);
        md_coverage(out, &ans[i].r);
        fprintf(out, " Decision: %s\n\n", q->decision);
    }
    for (int i = 0; i < g.set.n; i++)
        if (!answered[i])
            fprintf(out, "_%s is not answered by this daemon: none of its alert kinds "
                         "is raised here._\n\n", g.set.q[i].id);
    for (int i = 0; i < COV_LIMIT_COUNT; i++)
        fprintf(out, "%s%s", cov_limits[i], i + 1 < COV_LIMIT_COUNT ? " " : "\n\n");
}

static void json_str(FILE *out, const char *v) {
    char buf[1024];
    int off = 0;
    jsonl_escape(v ? v : "", buf, (int)sizeof(buf), &off);
    fprintf(out, "\"%s\"", buf);
}

void q_report_json(FILE *out, const sloth_state_t *s) {
    if (!out) return;
    ensure();
    fprintf(out, "  \"questions\": {\"source\":");
    json_str(out, g.loaded ? g.path : "defaults");
    fprintf(out, ",\"assessed\":%s,\"items\":[",
            cov_live_state() == COV_LIVE_VALID ? "true" : "false");
    q_answer_t ans[Q_MAX];
    int n = q_live_answers(s, ans);
    for (int i = 0; i < n; i++) {
        const q_question_t *q = &g.set.q[ans[i].qi];
        const q_result_t *r = &ans[i].r;
        char kinds[1024], ids[Q_IDS_MAX * ALERT_INCIDENT_ID_LEN + 16];
        q_found_str(r->found, kinds, sizeof(kinds));
        ids_str(r, ids, sizeof(ids));
        fprintf(out, "%s{\"qid\":", i ? "," : "");
        json_str(out, q->id);
        fprintf(out, ",\"priority\":%d,\"question\":", q->priority);
        json_str(out, q->text);
        fprintf(out, ",\"decision\":");
        json_str(out, q->decision);
        fprintf(out, ",\"status\":\"%s\",\"why\":\"%s\",\"kinds\":%d",
                q_status_name(r->st), cov_reason_name(r->why), r->kinds);
        if (cov_live_state() == COV_LIVE_VALID)
            fprintf(out, ",\"observable\":%d,\"partly\":%d,\"blind\":%d",
                    r->observable, r->partly, r->blind);
        fprintf(out, ",\"n_alerts\":%d,\"found\":\"%s\",\"ids\":\"%s\"}",
                r->n_alerts, kinds, ids);
    }
    fprintf(out, "]},\n");
}

/* ── The stream ───────────────────────────────────────────────────── */

void q_emit(const sloth_state_t *s) {
    if (!jsonl_any_sink()) return;
    time_t wall = sloth_wall();
    int assessed = cov_live_state() == COV_LIVE_VALID;
    q_answer_t ans[Q_MAX];
    int n = q_live_answers(s, ans);
    for (int i = 0; i < n; i++) {
        const q_question_t *q = &g.set.q[ans[i].qi];
        const q_result_t *r = &ans[i].r;
        char kinds[1024], ids[Q_IDS_MAX * ALERT_INCIDENT_ID_LEN + 16];
        q_found_str(r->found, kinds, sizeof(kinds));
        ids_str(r, ids, sizeof(ids));
        /* Words, counts and incident ids: each changes only when the
         * answer does (agents/AGENTS.md, change-only emission). */
        const int sig_v[8] = { (int)r->st, (int)r->why, r->kinds, assessed,
                               r->observable, r->partly, r->blind, r->n_alerts };
        uint64_t sig = jsonl_fnv1a(sig_v, sizeof(sig_v), 0);
        sig = jsonl_fnv1a(kinds, strlen(kinds), sig);
        sig = jsonl_fnv1a(ids, strlen(ids), sig);
        sig = jsonl_fnv1a(q->text, strlen(q->text), sig);
        if (!jsonl_changed(JD_QUESTION, q->id, strlen(q->id), sig, wall)) continue;

        jsonl_field_t f[16];
        int k = 0;
#define FS(key, v) f[k++] = (jsonl_field_t){ (key), JSONL_F_STR, (v), 0, 0.0, 0 }
#define FI(key, v) f[k++] = (jsonl_field_t){ (key), JSONL_F_INT, NULL, (long long)(v), 0.0, 0 }
        FS("qid", q->id);
        FI("priority", q->priority);
        FS("question", q->text);
        FS("decision", q->decision);
        FS("source", g.loaded ? "file" : "defaults");
        FS("status", q_status_name(r->st));
        FS("why", cov_reason_name(r->why));
        FI("kinds", r->kinds);
        FI("assessed", assessed);
        if (assessed) {
            FI("observable", r->observable);
            FI("partly", r->partly);
            FI("blind", r->blind);
        }
        FI("n_alerts", r->n_alerts);
        FS("found", kinds);
        FS("ids", ids);
#undef FS
#undef FI
        jsonl_emit_fields("question_status", wall, f, k);
    }
}
