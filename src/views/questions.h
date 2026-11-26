#ifndef VIEWS_QUESTIONS_H
#define VIEWS_QUESTIONS_H

#include "sloth.h"

/* [!] Site questions (#244): each question this daemon answers, most
 * urgent first, with its status; the selected one's decision, findings
 * and coverage below. src/questions_live.h has the answers. */
void view_questions_draw(const sloth_state_t *s);
void view_questions_key(sloth_state_t *s, int key);
/* The selected row, for tests. */
int  view_questions_sel(void);
void view_questions_reset(void);

#endif /* VIEWS_QUESTIONS_H */
