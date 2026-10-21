/* slothweb command line and bind policy (#157). */
#ifndef SLOTHWEB_CONFIG_H
#define SLOTHWEB_CONFIG_H

#include <stdint.h>
#include <stdio.h>

#include "web_acl.h"

#define WEB_DEFAULT_BIND        "127.0.0.1:8770"
#define WEB_DEFAULT_PORT        8770
/* Absolute budget, from accept(), for a client to deliver a complete
 * header block; and, separately, for it to take the response. Absolute
 * rather than reset per byte, so a client trickling one byte at a time
 * is cut off on the same schedule as one that sends nothing. */
#define WEB_DEFAULT_TIMEOUT_MS  10000
/* After the response, how long a client may keep sending (a request
 * body nobody will read) before the socket is closed. */
#define WEB_DEFAULT_LINGER_MS   1000
/* Event-stream cadence (spec §7.1, §10.2): a tick every second and a
 * keep-alive comment every 15 s. Not command-line flags; tests shorten
 * them. */
#define WEB_DEFAULT_TICK_MS     1000
#define WEB_DEFAULT_PING_MS     15000

typedef struct {
    int      bind_family;          /* AF_INET or AF_INET6 */
    uint8_t  bind_addr[16];
    uint16_t bind_port;            /* 0 only from code, never the CLI */
    int      allow_remote;         /* --web-allow-remote */
    int      strict;               /* --strict */
    web_acl_t acl;                 /* loopback plus every --web-allow */
    int      timeout_ms;
    int      linger_ms;
    int      tick_ms;
    int      ping_ms;
} web_config_t;

void web_config_defaults(web_config_t *c);

/* "A.B.C.D:PORT" or "[V6]:PORT", literal addresses only. allow_zero_port
 * is for tests that want an ephemeral port. 0, or -1 with err. */
int  web_parse_bind(const char *s, int *family, uint8_t addr[16],
                    uint16_t *port, int allow_zero_port,
                    char *err, size_t errsz);

/* The remote-exposure policy, applied to a complete config:
 *   - a non-loopback bind needs allow_remote;
 *   - a non-loopback --web-allow entry needs allow_remote;
 *   - strict refuses both, whatever allow_remote says.
 * Pure: no output, no socket. 0, or -1 with the refusal in err. */
int  web_config_check(const web_config_t *c, char *err, size_t errsz);

/* Parse argv (argv[0] is the program). Returns 0 to run, 1 when --help
 * printed usage to out, -1 on a usage error or a policy refusal (the
 * reason is printed to err). */
int  web_config_parse(web_config_t *c, int argc, char **argv,
                      FILE *out, FILE *err);

/* Print the stderr announcement every authorised remote exposure gets:
 * one for a non-loopback bind, one per non-loopback allow entry. Prints
 * nothing for a loopback-only configuration. */
void web_config_announce(const web_config_t *c, FILE *err);

/* "127.0.0.1:8770" / "[::1]:8770". */
void web_format_bind(int family, const uint8_t *addr, uint16_t port,
                     char *buf, size_t sz);

void web_usage(FILE *out);

#endif
