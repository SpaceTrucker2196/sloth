#ifndef QUIC_LOG_H
#define QUIC_LOG_H

#include <stdint.h>
#include "sloth.h"

int  quic_log_parse(const uint8_t *data, int len,
                    const char *src_ip, const char *dst_ip,
                    const char *host,      /* may be NULL */
                    quic_log_entry_t *out);

void quic_log_record(const quic_log_entry_t *e);
void quic_log_snapshot(sloth_state_t *s);
void quic_log_clear(void);

#endif /* QUIC_LOG_H */
