#ifndef RESEARCH_COVERAGE_H
#define RESEARCH_COVERAGE_H

#include "sloth.h"

struct rq_handle;

/* Research-corpus coverage for the alerts that fired — issue #73,
 * slice 3.
 *
 * Fills s->research_cov[] with one row per distinct alert *kind* in
 * s->alerts[], each carrying whatever the corpus has for it. The [f]
 * view renders that; the report already cites the same data through
 * posture.c.
 *
 * `h` may be NULL — no corpus is the ordinary case, and the view then
 * shows every fired kind with zero documents rather than an empty
 * screen. That distinction matters: "nothing is cited" and "the corpus
 * is not loaded" look identical if the table is simply empty.
 *
 * Unconditional, not gated on WITH_SQLITE. query.h stubs every rq_*
 * call to a no-op without it, so the no-SQLite build takes the same
 * path as a missing corpus and the view still explains itself. */
void research_coverage_snapshot(sloth_state_t *s, struct rq_handle *h);

/* How many of the fired kinds *can* be cited, and how many are. Kinds
 * whose alert_technique() is empty are excluded from both halves: a
 * rule reporting sloth's own posture has no external source, and
 * counting it against coverage makes the target unreachable.
 *
 * Lives here rather than in the view because it is arithmetic with a
 * judgement in it, and the view is not in a position to be tested on
 * what it prints. */
int research_coverage_ratio(const sloth_state_t *s, int *cited_out);

#endif /* RESEARCH_COVERAGE_H */
