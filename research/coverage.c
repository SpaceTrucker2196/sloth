#include <stdio.h>
#include <string.h>

#include "coverage.h"
#include "query.h"

/* Ordered by severity descending, then by occurrence count, then by
 * kind — the operator's reading order, and stable, so the selected row
 * does not move under the cursor between polls when two rows tie. */
static int cov_worse(const research_cov_t *a, const research_cov_t *b) {
    if (a->severity != b->severity) return a->severity > b->severity;
    if (a->fired    != b->fired)    return a->fired    > b->fired;
    return strcmp(a->kind, b->kind) < 0;
}

void research_coverage_snapshot(sloth_state_t *s, struct rq_handle *h) {
    if (!s) return;

    s->research_cov_count = 0;
    s->research_open      = h ? 1 : 0;

    for (int i = 0; i < s->alert_count; i++) {
        const alert_t *a = &s->alerts[i];
        const char *kind = alert_type_name(a->type);
        if (!kind || !kind[0]) continue;

        /* One row per *kind*, not per alert. Two PORT_SCAN alerts
         * against different hosts cite the same document, and listing
         * it twice would make the corpus look better covered than it
         * is. */
        research_cov_t *row = NULL;
        for (int k = 0; k < s->research_cov_count; k++) {
            if (strcmp(s->research_cov[k].kind, kind) == 0) {
                row = &s->research_cov[k];
                break;
            }
        }
        if (!row) {
            if (s->research_cov_count >= MAX_RESEARCH_COV) continue;
            row = &s->research_cov[s->research_cov_count++];
            memset(row, 0, sizeof(*row));
            snprintf(row->kind,  sizeof(row->kind),  "%s", kind);
            snprintf(row->label, sizeof(row->label), "%s", a->title);
            row->severity = (int)a->sev;

            rq_hit_t hits[RQ_MAX_HITS];
            int n = rq_for_alert(h, kind, hits, RQ_MAX_HITS);
            /* Truncation is reported rather than hidden. A row showing
             * eight documents when the corpus holds twelve reads as
             * complete coverage of a kind that has more to say. */
            row->docs_truncated = n > MAX_RESEARCH_DOCS;
            if (n > MAX_RESEARCH_DOCS) n = MAX_RESEARCH_DOCS;
            /* Explicit precisions rather than relying on snprintf's
             * bound. A hit's fields are wider than the display row's,
             * so the truncation is intended — and GCC is right to warn
             * about one it cannot see stated. Bound the input, do not
             * silence the warning; same treatment as #58. */
            for (int d = 0; d < n; d++) {
                snprintf(row->docs[d].title, sizeof(row->docs[d].title),
                         "%.79s", hits[d].title);
                snprintf(row->docs[d].source_url,
                         sizeof(row->docs[d].source_url),
                         "%.127s", hits[d].source_url);
                snprintf(row->docs[d].retrieved,
                         sizeof(row->docs[d].retrieved),
                         "%.15s", hits[d].retrieved);
            }
            row->doc_count = n;
        } else if ((int)a->sev > row->severity) {
            /* The worst severity this kind reached, not the first seen.
             * A WARN and a CRIT of the same kind sort by the CRIT. */
            row->severity = (int)a->sev;
            snprintf(row->label, sizeof(row->label), "%s", a->title);
        }
        row->fired += a->count > 0 ? a->count : 1;
    }

    /* Insertion sort: the table is at most MAX_RESEARCH_COV rows and
     * this runs once per poll. */
    for (int i = 1; i < s->research_cov_count; i++) {
        research_cov_t tmp = s->research_cov[i];
        int j = i - 1;
        while (j >= 0 && cov_worse(&tmp, &s->research_cov[j])) {
            s->research_cov[j + 1] = s->research_cov[j];
            j--;
        }
        s->research_cov[j + 1] = tmp;
    }

    if (s->research_sel >= s->research_cov_count)
        s->research_sel = s->research_cov_count > 0
                        ? s->research_cov_count - 1 : 0;
    if (s->research_sel < 0) s->research_sel = 0;
}
