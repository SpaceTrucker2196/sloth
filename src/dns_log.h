#ifndef DNS_LOG_H
#define DNS_LOG_H

#include <stdint.h>
#include "sloth.h"

int  dns_log_parse(const uint8_t *msg, int len,
                   const char *src_ip,
                   dns_log_entry_t *out);

void dns_log_record(const dns_log_entry_t *e);
void dns_log_snapshot(sloth_state_t *s);
void dns_log_clear(void);

#endif /* DNS_LOG_H */
