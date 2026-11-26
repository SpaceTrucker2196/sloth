#include <stdio.h>
#include <string.h>
#include "sloth.h"
#include "tui.h"
#include "views/view_page.h"
#include "views/questions.h"
#include "questions_live.h"
#include "rule_coverage_live.h"

/* [!] Site questions (#244). Reads q_live_answers() each draw: the
 * answers are derived from the alert snapshot and the coverage status,
 * so the view holds nothing but its cursor. */

#define Q_PAGE 20

static int g_sel;
static int g_n;     /* rows at the last draw, for the key handler */

int  view_questions_sel(void)   { return g_sel; }
void view_questions_reset(void) { g_sel = 0; g_n = 0; }

static void status_colour(q_status_t st) {
    switch (st) {
    case Q_ST_FINDING:        tui_bright(); break;
    case Q_ST_NO_FINDING:     tui_normal(); break;
    default:                  tui_dim();    break;
    }
}

void view_questions_draw(const sloth_state_t *s) {
    static q_answer_t ans[Q_MAX];
    int n = q_live_answers(s, ans);
    const q_set_t *set = q_live_questions();
    g_n = n;
    if (g_sel >= n) g_sel = n > 0 ? n - 1 : 0;

    int findings = 0;
    for (int i = 0; i < n; i++) findings += ans[i].r.st == Q_ST_FINDING;
    tui_normal(); TPRINT(" Site questions: ");
    tui_bright(); TPRINT("%d", n);
    tui_normal(); TPRINT("  with a finding: ");
    tui_bright(); TPRINT("%d", findings);
    tui_dim();    TPRINT("  %s  [up/dn] select\n",
                         q_live_path()[0] ? "--questions file" : "defaults");
    if (cov_live_state() != COV_LIVE_VALID) {
        tui_dim();
        TPRINT(" coverage not assessed: %s\n", cov_live_state_why(cov_live_state()));
    }

    tui_clip_rows(1);
    tui_dim();
    TPRINT(" %-8s %-3s %-17s %-16s %s\n", "Id", "Pri", "Status", "Why / found", "Question");
    tui_normal();
    if (n == 0) {
        tui_dim();
        TPRINT("  (no question is answered by this daemon: none of their alert kinds "
               "is raised here)\n");
        tui_normal();
        return;
    }

    int page = view_page_budget(6, Q_PAGE);
    int top = g_sel - page / 2;
    if (top + page > n) top = n - page;
    if (top < 0) top = 0;
    int end = top + page < n ? top + page : n;
    for (int i = top; i < end; i++) {
        const q_question_t *q = &set->q[ans[i].qi];
        const q_result_t *r = &ans[i].r;
        char what[64];
        if (r->st == Q_ST_FINDING) q_found_str(r->found, what, sizeof(what));
        else snprintf(what, sizeof(what), "%s", cov_reason_name(r->why));
        if (i == g_sel) tui_sel(); else tui_normal();
        TPRINT(" %-8.8s %-3d ", q->id, q->priority);
        if (i != g_sel) status_colour(r->st);
        TPRINT("%-17s", q_status_name(r->st));
        if (i != g_sel) tui_dim();
        TPRINT(" %-16.16s", what[0] ? what : "-");
        if (i != g_sel) tui_normal();
        TPRINT(" %s\n", q->text);
        if (i == g_sel) tui_reset();
    }

    /* The selected question. */
    const q_question_t *q = &set->q[ans[g_sel].qi];
    const q_result_t *r = &ans[g_sel].r;
    tui_normal();
    TPRINT("\n %s: %s\n", q->id, q->text);
    tui_dim();
    TPRINT(" Decision: %s\n", q->decision);
    if (cov_live_state() == COV_LIVE_VALID)
        TPRINT(" Indicators: %d; observable %d, partly %d, blind %d\n",
               r->kinds, r->observable, r->partly, r->blind);
    else
        TPRINT(" Indicators: %d, not assessed\n", r->kinds);
    if (r->n_alerts) {
        char kinds[1024];
        q_found_str(r->found, kinds, sizeof(kinds));
        TPRINT(" Findings: %d (%s); incidents", r->n_alerts, kinds);
        for (int i = 0; i < r->nids; i++) TPRINT(" %s", r->ids[i]);
        TPRINT("\n");
    }
    tui_normal();
}

void view_questions_key(sloth_state_t *s, int key) {
    (void)s;
    switch (key) {
    case SLOTH_KEY_UP:
        if (g_sel > 0) g_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (g_sel < g_n - 1) g_sel++;
        break;
    default:
        break;
    }
}
