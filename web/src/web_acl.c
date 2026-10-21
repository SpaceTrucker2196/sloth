#include "web_acl.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t v4mapped_prefix[12] =
    { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff };

static int is_v4mapped(const uint8_t *a6) {
    return memcmp(a6, v4mapped_prefix, sizeof(v4mapped_prefix)) == 0;
}

static void set_err(char *err, size_t errsz, const char *msg, const char *s) {
    if (err && errsz) snprintf(err, errsz, "%s: %s", msg, s ? s : "");
}

void web_acl_init_loopback(web_acl_t *a) {
    memset(a, 0, sizeof(*a));
    a->e[0].family  = AF_INET;
    a->e[0].addr[0] = 127;
    a->e[0].prefix  = 8;
    a->e[1].family   = AF_INET6;
    a->e[1].addr[15] = 1;
    a->e[1].prefix   = 128;
    a->n = 2;
}

/* The mask byte for byte index i under a prefix of `prefix` bits. */
static uint8_t mask_byte(int i, int prefix) {
    int lo = i * 8;
    if (prefix >= lo + 8) return 0xff;
    if (prefix <= lo)     return 0x00;
    return (uint8_t)(0xff << (8 - (prefix - lo)));
}

static int host_bits_clear(const uint8_t *a, int nbytes, int prefix) {
    for (int i = 0; i < nbytes; i++)
        if (a[i] & (uint8_t)~mask_byte(i, prefix)) return 0;
    return 1;
}

static int prefix_match(const uint8_t *a, const uint8_t *b, int nbytes,
                        int prefix) {
    for (int i = 0; i < nbytes; i++) {
        uint8_t m = mask_byte(i, prefix);
        if ((a[i] & m) != (b[i] & m)) return 0;
    }
    return 1;
}

int web_acl_parse_entry(const char *s, web_acl_entry_t *out,
                        char *err, size_t errsz) {
    char host[INET6_ADDRSTRLEN + 1];
    if (!s || !*s) { set_err(err, errsz, "empty address", s); return -1; }

    const char *slash = strchr(s, '/');
    size_t hl = slash ? (size_t)(slash - s) : strlen(s);
    if (hl == 0 || hl >= sizeof(host)) {
        set_err(err, errsz, "bad address", s);
        return -1;
    }
    memcpy(host, s, hl);
    host[hl] = '\0';

    web_acl_entry_t e;
    memset(&e, 0, sizeof(e));
    if (inet_pton(AF_INET, host, e.addr) == 1) {
        e.family = AF_INET;
        e.prefix = 32;
    } else if (inet_pton(AF_INET6, host, e.addr) == 1) {
        e.family = AF_INET6;
        e.prefix = 128;
    } else {
        set_err(err, errsz, "not a literal IPv4 or IPv6 address", s);
        return -1;
    }

    if (slash) {
        const char *p = slash + 1;
        size_t pl = strlen(p);
        if (pl == 0 || pl > 3) { set_err(err, errsz, "bad prefix", s); return -1; }
        for (size_t i = 0; i < pl; i++)
            if (p[i] < '0' || p[i] > '9') {
                set_err(err, errsz, "bad prefix", s);
                return -1;
            }
        int v = atoi(p);
        if (v > e.prefix) { set_err(err, errsz, "prefix too long", s); return -1; }
        e.prefix = v;
    }

    if (!host_bits_clear(e.addr, e.family == AF_INET ? 4 : 16, e.prefix)) {
        set_err(err, errsz, "host bits set past the prefix", s);
        return -1;
    }

    if (e.family == AF_INET6 && e.prefix >= 96 && is_v4mapped(e.addr)) {
        uint8_t v4[4];
        memcpy(v4, e.addr + 12, 4);
        memset(e.addr, 0, sizeof(e.addr));
        memcpy(e.addr, v4, 4);
        e.family = AF_INET;
        e.prefix -= 96;
    }

    *out = e;
    return 0;
}

int web_acl_add(web_acl_t *a, const web_acl_entry_t *e) {
    if (a->n >= WEB_ACL_MAX) return -1;
    a->e[a->n++] = *e;
    return 0;
}

int web_acl_permits(const web_acl_t *a, const struct sockaddr *sa,
                    socklen_t len) {
    uint8_t addr[16];
    int family;
    memset(addr, 0, sizeof(addr));

    if (!sa) return 0;
    if (sa->sa_family == AF_INET &&
        len >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *s4 = (const void *)sa;
        memcpy(addr, &s4->sin_addr, 4);
        family = AF_INET;
    } else if (sa->sa_family == AF_INET6 &&
               len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *s6 = (const void *)sa;
        memcpy(addr, &s6->sin6_addr, 16);
        family = AF_INET6;
        if (is_v4mapped(addr)) {
            memmove(addr, addr + 12, 4);
            memset(addr + 4, 0, 12);
            family = AF_INET;
        }
    } else {
        return 0;
    }

    for (int i = 0; i < a->n; i++) {
        if (a->e[i].family != family) continue;
        if (prefix_match(a->e[i].addr, addr, family == AF_INET ? 4 : 16,
                         a->e[i].prefix))
            return 1;
    }
    return 0;
}

int web_addr_is_loopback(int family, const uint8_t *addr) {
    static const uint8_t v6_lo[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1 };
    if (family == AF_INET) return addr[0] == 127;
    if (family == AF_INET6) {
        if (memcmp(addr, v6_lo, 16) == 0) return 1;
        return is_v4mapped(addr) && addr[12] == 127;
    }
    return 0;
}

int web_acl_entry_is_loopback(const web_acl_entry_t *e) {
    /* Parsing already folded v4-mapped entries into AF_INET, so the
     * only loopback IPv6 entry is ::1/128 itself. */
    if (e->family == AF_INET)  return e->prefix >= 8 && e->addr[0] == 127;
    if (e->family == AF_INET6) return e->prefix == 128 &&
                                      web_addr_is_loopback(AF_INET6, e->addr);
    return 0;
}

void web_acl_entry_format(const web_acl_entry_t *e, char *buf, size_t sz) {
    char host[INET6_ADDRSTRLEN];
    if (!inet_ntop(e->family, e->addr, host, sizeof(host)))
        snprintf(host, sizeof(host), "?");
    snprintf(buf, sz, "%s/%d", host, e->prefix);
}
