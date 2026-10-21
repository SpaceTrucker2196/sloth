/* slothweb allowed-peer list (#157).
 *
 * Every accepted connection is checked against this list before a byte
 * is read from it. The default is loopback only; anything wider is an
 * explicit --web-allow entry, and a non-loopback entry needs
 * --web-allow-remote as well (web_config.c). Addresses are literals
 * parsed with inet_pton(): nothing here resolves a name. */
#ifndef SLOTHWEB_ACL_H
#define SLOTHWEB_ACL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define WEB_ACL_MAX 32

typedef struct {
    int     family;      /* AF_INET or AF_INET6 */
    uint8_t addr[16];    /* network order; first 4 bytes for AF_INET */
    int     prefix;      /* 0..32 or 0..128 */
} web_acl_entry_t;

typedef struct {
    web_acl_entry_t e[WEB_ACL_MAX];
    int             n;
} web_acl_t;

/* 127.0.0.0/8 and ::1/128. */
void web_acl_init_loopback(web_acl_t *a);

/* "ADDR" or "ADDR/PREFIX". A v4-mapped IPv6 entry (::ffff:a.b.c.d/N,
 * N >= 96) is stored as its IPv4 form, so it matches the same peers a
 * dual-stack listener reports either way. Host bits beyond the prefix
 * must be zero: "10.0.0.1/8" is refused rather than guessed at.
 * Returns 0, or -1 with a reason in err. */
int  web_acl_parse_entry(const char *s, web_acl_entry_t *out,
                         char *err, size_t errsz);

/* 0, or -1 when the list is full. */
int  web_acl_add(web_acl_t *a, const web_acl_entry_t *e);

/* 1 when the peer falls inside an entry. A v4-mapped IPv6 peer is
 * matched as IPv4. Any other family is refused. */
int  web_acl_permits(const web_acl_t *a, const struct sockaddr *sa,
                     socklen_t len);

/* 1 for 127.0.0.0/8, ::1 and ::ffff:127.0.0.0/104. */
int  web_addr_is_loopback(int family, const uint8_t *addr);

/* 1 when every address the entry covers is loopback. */
int  web_acl_entry_is_loopback(const web_acl_entry_t *e);

/* "ADDR/PREFIX". */
void web_acl_entry_format(const web_acl_entry_t *e, char *buf, size_t sz);

#endif
