#ifndef ICMP_LOG_H
#define ICMP_LOG_H

#include <stdint.h>
#include "sloth.h"

/* Parse an ICMP message body (after the IP header).
 *   is_v6 = 0 for ICMPv4 (IP proto 1), 1 for ICMPv6 (IP proto 58).
 * Returns 1 on success, 0 if too short.
 */
int  icmp_log_parse(const uint8_t *msg, int len,
                    const char *src_ip, const char *dst_ip,
                    int is_v6, icmp_log_entry_t *out);

void icmp_log_record(const icmp_log_entry_t *e);
void icmp_log_snapshot(sloth_state_t *s);
void icmp_log_clear(void);

#endif /* ICMP_LOG_H */
