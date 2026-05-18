#ifndef IP_OWNER_H
#define IP_OWNER_H

#include <stdint.h>

/* Compile-time IPv4 prefix → owner mapping for well-known orgs
 * (Cloudflare, Google, AWS, Akamai, Microsoft, Apple, Meta, GitHub, …).
 *
 * The table covers a few dozen of the most-trafficked public networks. It's
 * intentionally not exhaustive — the goal is to put a recognisable label on
 * common alert destinations, not to be a whois clone. */

const char *ip_owner_lookup    (uint32_t ip_host);    /* host byte order */
const char *ip_owner_lookup_str(const char *ip);      /* dotted-decimal v4 */

#endif /* IP_OWNER_H */
