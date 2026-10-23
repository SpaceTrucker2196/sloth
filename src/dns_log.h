#ifndef DNS_LOG_H
#define DNS_LOG_H

#include <stdint.h>
#include <string.h>
#include "sloth.h"

/* A PTR question's answer is a host name (#165), never an address:
 * the consumers that read answer as an IP — the host cache, the IP
 * index, the captive-portal DNS check, the dashboard's IP colouring —
 * skip these rows. dns_log_parse() decodes PTR RDATA for a PTR
 * question only, so every other qtype's answer stays an address,
 * "NXDOMAIN" or empty. */
static inline int dns_log_is_ptr(const dns_log_entry_t *e) {
    return strcmp(e->qtype, "PTR") == 0;
}

int  dns_log_parse(const uint8_t *msg, int len,
                   const char *src_ip,
                   dns_log_entry_t *out);

void dns_log_record(const dns_log_entry_t *e);
void dns_log_snapshot(sloth_state_t *s);
void dns_log_clear(void);

#endif /* DNS_LOG_H */
