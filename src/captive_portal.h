#ifndef CAPTIVE_PORTAL_H
#define CAPTIVE_PORTAL_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* Captive-portal MITM detection — issue #69.
 *
 * Every modern OS probes a known URL to decide whether it is behind a
 * captive portal, and expects a specific, byte-exact answer. Apple asks
 * captive.apple.com for a page saying "Success"; Microsoft asks for the
 * string "Microsoft Connect Test"; Google expects an empty 204.
 *
 * A rogue AP intercepts that probe and answers with something else,
 * which is precisely what makes the victim's OS pop a browser at the
 * attacker's page. The check is deliberately unauthenticated and
 * deliberately plaintext — that is what makes it work, and what makes
 * it hijackable.
 *
 * So the detection is not a heuristic. The expected answer is published
 * and fixed, and anything else on that host and path is an
 * interception. The difficulty is entirely in knowing whether we saw
 * the *whole* answer — which is what #71's body_complete exists for.
 *
 * ── Three independent signals ──
 *
 *   body   the sentinel URL returned something other than the sentinel
 *   dns    the sentinel host resolved into private or CGNAT space
 *   tls    a TLS ClientHello for a sentinel host went to a private IP
 *
 * They are independent on purpose: a portal that chunks its response to
 * evade the body check still has to answer the DNS query, and a portal
 * that proxies DNS correctly still has to terminate the TLS. */

/* cp_kind_t, cp_event_t and CP_MAX_EVENTS live in sloth.h, beside the
 * state array that holds them — the same place every other snapshot
 * type is declared. */

/* True when `host` is a known connectivity-check sentinel. */
int  cp_is_sentinel_host(const char *host);

/* Check a completed HTTP response against the sentinel for its
 * host+path. Returns a cp_kind_t bit, or 0.
 *
 * **Only ever fires on a complete body.** sloth does not reassemble
 * TCP (#71), so a truncated body that differs from the sentinel is not
 * evidence of anything — and a chunked response is never complete. A
 * rogue that chunks its answer therefore evades *this* check; it does
 * not evade the DNS or TLS ones, which is why there are three. */
int  cp_check_response(const http_log_entry_t *resp);

/* Check a DNS answer for a sentinel host. `answer` is the A/AAAA
 * address as text. Returns CP_KIND_DNS_SPOOF for private or CGNAT
 * space, CP_KIND_DNS_UNEXPECTED for a public address outside the
 * ranges the sentinel is known to live in, or 0. */
int  cp_check_dns(const char *qname, const char *answer);

/* Check a TLS ClientHello: a sentinel host being reached over TLS at a
 * private address is a portal terminating the connection. */
int  cp_check_tls(const char *sni, const char *dst_ip);

/* Record an event. `evidence` may be NULL. */
void cp_record(uint8_t kind, const char *host, const char *src,
               const char *evidence, time_t now);

void cp_snapshot(sloth_state_t *s);
int  cp_event_count(void);
void cp_clear(void);

/* Human label for one kind bit; "" for anything else. */
const char *cp_kind_label(uint8_t kind);

#endif /* CAPTIVE_PORTAL_H */
