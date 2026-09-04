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

#endif /* RESEARCH_COVERAGE_H */
