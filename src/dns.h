#ifndef DNS_H
#define DNS_H

#include <stdint.h>

/* Start/stop the background resolver thread. */
void dns_init(void);
void dns_cleanup(void);

/* Non-blocking lookup. Returns the cached hostname, or the original IP
   string if resolution is pending/failed. Safe to call only from the
   main thread. The returned pointer is valid until the next dns_lookup call. */
const char *dns_lookup(const char *ip);

/* Format "host:port" or "ip:port" into buf (always NUL-terminated). */
void dns_fmt_addr(const char *ip, uint16_t port, char *buf, int sz);

/* Reset all cache and queue state (for testing). */
void dns_reset(void);

/* Inject a resolved entry directly (for testing). */
void dns_set_resolved(const char *ip, const char *host);

#endif /* DNS_H */
