#include "web_config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

void web_config_defaults(web_config_t *c) {
    memset(c, 0, sizeof(*c));
    c->bind_family  = AF_INET;
    c->bind_addr[0] = 127;
    c->bind_addr[3] = 1;
    c->bind_port    = WEB_DEFAULT_PORT;
    web_acl_init_loopback(&c->acl);
    c->timeout_ms   = WEB_DEFAULT_TIMEOUT_MS;
    c->linger_ms    = WEB_DEFAULT_LINGER_MS;
    c->tick_ms      = WEB_DEFAULT_TICK_MS;
    c->ping_ms      = WEB_DEFAULT_PING_MS;
    char err[128];
    if (web_sockspec_parse(WEB_DEFAULT_SOCKET, &c->sock, err, sizeof(err)) != 0)
        c->sock.kind = 0;   /* not reachable: the default is a constant */
    c->sock_backoff_min_ms = WEB_SOCK_BACKOFF_MIN_MS;
    c->sock_backoff_max_ms = WEB_SOCK_BACKOFF_MAX_MS;
    snprintf(c->store_path, sizeof(c->store_path), "%s", WEB_DEFAULT_STORE);
    c->max_keys    = WEB_DEFAULT_MAX_KEYS;
    c->max_mb      = WEB_DEFAULT_MAX_MB;
    c->retain_days = WEB_DEFAULT_RETAIN_DAYS;
}

/* A decimal in [lo, hi], digits only. */
static int parse_count(const char *p, int lo, int hi, int *out) {
    size_t n = strlen(p);
    if (n == 0 || n > 9) return -1;
    for (size_t i = 0; i < n; i++) if (p[i] < '0' || p[i] > '9') return -1;
    long v = strtol(p, NULL, 10);
    if (v < lo || v > hi) return -1;
    *out = (int)v;
    return 0;
}

static int parse_port(const char *p, uint16_t *port, int allow_zero) {
    size_t n = strlen(p);
    if (n == 0 || n > 5) return -1;
    for (size_t i = 0; i < n; i++) if (p[i] < '0' || p[i] > '9') return -1;
    long v = strtol(p, NULL, 10);
    if (v > 65535 || (v == 0 && !allow_zero)) return -1;
    *port = (uint16_t)v;
    return 0;
}

int web_parse_bind(const char *s, int *family, uint8_t addr[16],
                   uint16_t *port, int allow_zero_port,
                   char *err, size_t errsz) {
    char host[INET6_ADDRSTRLEN + 1];
    const char *hs, *colon;
    size_t hl;

    if (!s || !*s) { snprintf(err, errsz, "empty --web-bind"); return -1; }
    if (s[0] == '[') {
        const char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':') {
            snprintf(err, errsz, "bad --web-bind %s (want [V6]:PORT)", s);
            return -1;
        }
        hs = s + 1;
        hl = (size_t)(rb - hs);
        colon = rb + 1;
    } else {
        colon = strchr(s, ':');
        if (!colon || strchr(colon + 1, ':')) {
            snprintf(err, errsz, "bad --web-bind %s (want A.B.C.D:PORT or "
                                 "[V6]:PORT)", s);
            return -1;
        }
        hs = s;
        hl = (size_t)(colon - s);
    }
    if (hl == 0 || hl >= sizeof(host)) {
        snprintf(err, errsz, "bad --web-bind address in %s", s);
        return -1;
    }
    memcpy(host, hs, hl);
    host[hl] = '\0';

    uint8_t a[16];
    memset(a, 0, sizeof(a));
    int fam;
    if (s[0] != '[' && inet_pton(AF_INET, host, a) == 1)       fam = AF_INET;
    else if (s[0] == '[' && inet_pton(AF_INET6, host, a) == 1) fam = AF_INET6;
    else {
        /* No getaddrinfo(): slothweb never resolves a name, including
         * its own bind address. */
        snprintf(err, errsz, "--web-bind %s: not a literal %s address "
                             "(names are not resolved)",
                 s, s[0] == '[' ? "IPv6" : "IPv4");
        return -1;
    }
    if (parse_port(colon + 1, port, allow_zero_port) != 0) {
        snprintf(err, errsz, "--web-bind %s: bad port", s);
        return -1;
    }
    *family = fam;
    memcpy(addr, a, 16);
    return 0;
}

void web_format_bind(int family, const uint8_t *addr, uint16_t port,
                     char *buf, size_t sz) {
    char host[INET6_ADDRSTRLEN];
    if (!inet_ntop(family, addr, host, sizeof(host)))
        snprintf(host, sizeof(host), "?");
    if (family == AF_INET6) snprintf(buf, sz, "[%s]:%u", host, (unsigned)port);
    else                    snprintf(buf, sz, "%s:%u",   host, (unsigned)port);
}

int web_config_check(const web_config_t *c, char *err, size_t errsz) {
    char where[INET6_ADDRSTRLEN + 16];
    web_format_bind(c->bind_family, c->bind_addr, c->bind_port,
                    where, sizeof(where));

    if (!web_addr_is_loopback(c->bind_family, c->bind_addr)) {
        if (c->strict) {
            snprintf(err, errsz,
                "slothweb: --strict refuses a non-loopback --web-bind (%s).\n"
                "  --web-allow-remote does not override --strict. Bind "
                "loopback, or drop --strict.\n", where);
            return -1;
        }
        if (!c->allow_remote) {
            snprintf(err, errsz,
                "slothweb: refusing to bind %s: not a loopback address.\n"
                "  slothweb has no authentication and no TLS. Keep it local "
                "and forward it:\n"
                "      ssh -L %u:127.0.0.1:%u user@this-host\n"
                "  To expose it anyway, add --web-allow-remote and name the "
                "peers with --web-allow.\n",
                where, (unsigned)c->bind_port, (unsigned)c->bind_port);
            return -1;
        }
    }

    if (c->strict && c->sock.kind && !web_sockspec_is_local(&c->sock)) {
        char sp[INET6_ADDRSTRLEN + 16];
        web_sockspec_format(&c->sock, sp, sizeof(sp));
        snprintf(err, errsz,
            "slothweb: --strict refuses a non-loopback --socket (%s).\n"
            "  The stream has no TLS and no authentication. Read it on the "
            "sensor, or\n  forward it: ssh -L 8765:127.0.0.1:8765 "
            "user@sensor\n", sp);
        return -1;
    }

    for (int i = 0; i < c->acl.n; i++) {
        const web_acl_entry_t *e = &c->acl.e[i];
        if (web_acl_entry_is_loopback(e)) continue;
        char cidr[INET6_ADDRSTRLEN + 8];
        web_acl_entry_format(e, cidr, sizeof(cidr));
        if (c->strict) {
            snprintf(err, errsz,
                "slothweb: --strict refuses a non-loopback --web-allow "
                "(%s).\n", cidr);
            return -1;
        }
        if (!c->allow_remote) {
            snprintf(err, errsz,
                "slothweb: --web-allow %s admits non-loopback peers; that "
                "needs --web-allow-remote.\n", cidr);
            return -1;
        }
    }
    return 0;
}

void web_usage(FILE *out) {
    fprintf(out,
        "usage: slothweb [--socket SPEC] [--web-bind ADDR:PORT]\n"
        "                [--web-allow CIDR]... [--web-allow-remote] [--strict]\n"
        "                [--store PATH] [--web-max-keys N] [--web-max-mb N]\n"
        "                [--web-retain-days N] [--help]\n"
        "\n"
        "  --socket SPEC         sloth's data socket to read: unix:PATH or\n"
        "                        tcp:A.B.C.D:PORT / tcp:[V6]:PORT, literal\n"
        "                        addresses only (default " WEB_DEFAULT_SOCKET ").\n"
        "                        Reconnects on its own; read-only.\n"
        "  --web-bind ADDR:PORT  listen address, a literal A.B.C.D:PORT or\n"
        "                        [V6]:PORT (default " WEB_DEFAULT_BIND ").\n"
        "                        A non-loopback address is refused unless\n"
        "                        --web-allow-remote is given.\n"
        "  --web-allow CIDR      admit peers in CIDR as well as loopback\n"
        "                        (repeatable). Loopback is always admitted;\n"
        "                        a non-loopback CIDR needs --web-allow-remote.\n"
        "                        Every other peer is closed at accept().\n"
        "  --web-allow-remote    authorise a non-loopback bind and non-loopback\n"
        "                        --web-allow entries; announced on stderr.\n"
        "  --strict              refuse any non-loopback bind or allow entry,\n"
        "                        even with --web-allow-remote.\n"
        "  --store PATH          slothweb's own SQLite file for the time series\n"
        "                        (default " WEB_DEFAULT_STORE "); never sloth.db, which\n"
        "                        is refused. Created 0600. Needs a WITH_SQLITE\n"
        "                        build; without one only the last hours of\n"
        "                        10 s buckets are kept, in memory.\n"
        "  --web-max-keys N      device keys tracked (default 512; hosts get N/2,\n"
        "                        range 16..8192). Least recently seen out first.\n"
        "  --web-max-mb N        store ceiling in MB (default 256); the oldest\n"
        "                        10 s rows go first.\n"
        "  --web-retain-days N   days of 1 min buckets kept (default 30, 1..400).\n"
        "  --help                this text.\n"
        "\n"
        "Routes (GET and HEAD): / (the page), /api/health, /api/live,\n"
        "/api/series, /api/keys and /api/metrics (JSON), /events (Server-Sent\n"
        "Events). Any other path is 404; any\n"
        "other method is 405; a Host that is not localhost or an IP\n"
        "literal is 421; a header block over 8 KB is 431.\n");
}

int web_config_parse(web_config_t *c, int argc, char **argv,
                     FILE *out, FILE *err) {
    char msg[512];
    web_config_defaults(c);

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            web_usage(out);
            return 1;
        } else if (!strcmp(a, "--web-allow-remote")) {
            c->allow_remote = 1;
        } else if (!strcmp(a, "--strict")) {
            c->strict = 1;
        } else if (!strcmp(a, "--socket")) {
            if (i + 1 >= argc) {
                fprintf(err, "slothweb: %s needs an argument\n", a);
                return -1;
            }
            if (web_sockspec_parse(argv[++i], &c->sock, msg, sizeof(msg)) != 0) {
                fprintf(err, "slothweb: %s\n", msg);
                return -1;
            }
        } else if (!strcmp(a, "--store")) {
            if (i + 1 >= argc) {
                fprintf(err, "slothweb: %s needs an argument\n", a);
                return -1;
            }
            const char *v = argv[++i];
            if (!v[0] || strlen(v) >= sizeof(c->store_path) - 16) {
                fprintf(err, "slothweb: --store: empty or too long a path\n");
                return -1;
            }
            if (!web_store_available()) {
                fprintf(err, "slothweb: --store needs SQLite; this slothweb "
                             "was built with WITH_SQLITE=0\n");
                return -1;
            }
            snprintf(c->store_path, sizeof(c->store_path), "%s", v);
            c->store_given = 1;
        } else if (!strcmp(a, "--web-max-keys") || !strcmp(a, "--web-max-mb") ||
                   !strcmp(a, "--web-retain-days")) {
            if (i + 1 >= argc) {
                fprintf(err, "slothweb: %s needs an argument\n", a);
                return -1;
            }
            const char *v = argv[++i];
            int lo, hi, *dst;
            if (!strcmp(a, "--web-max-keys")) {
                lo = WEB_MAX_KEYS_MIN; hi = WEB_MAX_KEYS_MAX; dst = &c->max_keys;
            } else if (!strcmp(a, "--web-max-mb")) {
                lo = 1; hi = WEB_MAX_MB_MAX; dst = &c->max_mb;
            } else {
                lo = 1; hi = WEB_RETAIN_DAYS_MAX; dst = &c->retain_days;
            }
            if (parse_count(v, lo, hi, dst) != 0) {
                fprintf(err, "slothweb: %s %s: want a whole number from %d "
                             "to %d\n", a, v, lo, hi);
                return -1;
            }
        } else if (!strcmp(a, "--web-bind") || !strcmp(a, "--web-allow")) {
            if (i + 1 >= argc) {
                fprintf(err, "slothweb: %s needs an argument\n", a);
                return -1;
            }
            const char *v = argv[++i];
            if (!strcmp(a, "--web-bind")) {
                if (web_parse_bind(v, &c->bind_family, c->bind_addr,
                                   &c->bind_port, 0, msg, sizeof(msg)) != 0) {
                    fprintf(err, "slothweb: %s\n", msg);
                    return -1;
                }
            } else {
                web_acl_entry_t e;
                if (web_acl_parse_entry(v, &e, msg, sizeof(msg)) != 0) {
                    fprintf(err, "slothweb: --web-allow %s\n", msg);
                    return -1;
                }
                if (web_acl_add(&c->acl, &e) != 0) {
                    fprintf(err, "slothweb: too many --web-allow entries "
                                 "(max %d)\n", WEB_ACL_MAX - 2);
                    return -1;
                }
            }
        } else {
            fprintf(err, "slothweb: unknown option %s (see --help)\n", a);
            return -1;
        }
    }

    if (web_config_check(c, msg, sizeof(msg)) != 0) {
        fputs(msg, err);
        return -1;
    }
    return 0;
}

void web_config_announce(const web_config_t *c, FILE *err) {
    if (!web_addr_is_loopback(c->bind_family, c->bind_addr)) {
        char where[INET6_ADDRSTRLEN + 16];
        web_format_bind(c->bind_family, c->bind_addr, c->bind_port,
                        where, sizeof(where));
        fprintf(err,
            "slothweb: WARNING: listening on %s, which is not a loopback "
            "address.\n"
            "  slothweb has NO authentication and NO TLS. Peers outside the "
            "allow list\n"
            "  are closed at accept(); every peer inside it reads whatever "
            "slothweb serves.\n"
            "  Authorised by --web-allow-remote.\n", where);
    }
    for (int i = 0; i < c->acl.n; i++) {
        const web_acl_entry_t *e = &c->acl.e[i];
        if (web_acl_entry_is_loopback(e)) continue;
        char cidr[INET6_ADDRSTRLEN + 8];
        web_acl_entry_format(e, cidr, sizeof(cidr));
        fprintf(err, "slothweb: WARNING: admitting non-loopback peers in %s "
                     "(--web-allow, authorised by --web-allow-remote).\n",
                cidr);
    }
    if (c->sock.kind && !web_sockspec_is_local(&c->sock)) {
        char sp[INET6_ADDRSTRLEN + 16];
        web_sockspec_format(&c->sock, sp, sizeof(sp));
        fprintf(err, "slothweb: WARNING: reading the data stream from %s, "
                     "which is not loopback.\n"
                     "  It travels with no TLS and no authentication.\n", sp);
    }
}
