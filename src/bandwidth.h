#ifndef BANDWIDTH_H
#define BANDWIDTH_H

#include "ntop.h"

void             bw_update(ntop_state_t *s);
void             bw_reset(void);   /* for testing */
const conn_bw_t *bw_lookup(const ntop_state_t *s, const conn_t *c);
void             bw_fmt_rate(double bps, char *buf, int sz);

#endif /* BANDWIDTH_H */
