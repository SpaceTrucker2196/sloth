#ifndef NTP_LOG_H
#define NTP_LOG_H

#include <stdint.h>
#include "sloth.h"

/* Parse an NTP datagram (UDP/123 payload).
 * Returns 1 on success, 0 on rejected/short input.
 * Fills `out` with src/dst/mode/version/stratum/ref.
 * Times are set to now. */
int  ntp_log_parse(const uint8_t *msg, int len,
                   const char *src_ip, const char *dst_ip,
                   ntp_log_entry_t *out);

void ntp_log_record(const ntp_log_entry_t *e);
void ntp_log_snapshot(sloth_state_t *s);
void ntp_log_clear(void);

#endif /* NTP_LOG_H */
