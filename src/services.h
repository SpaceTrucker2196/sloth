#ifndef SERVICES_H
#define SERVICES_H
#include <stdint.h>

/* Returns the IANA service name for a well-known port, or NULL. */
const char *svc_name(uint16_t port);

/* Formats addr:svcname or addr:portnum into buf[sz]. */
void svc_fmt_addr(char *buf, int sz, const char *addr, uint16_t port);

#endif /* SERVICES_H */
