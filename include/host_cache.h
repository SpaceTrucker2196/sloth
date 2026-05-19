#ifndef SLOTH_HOST_CACHE_H
#define SLOTH_HOST_CACHE_H

/* IP -> hostname cache populated from observed DNS answers.
 *
 * The capture thread feeds this via host_cache_add() each time a DNS
 * A/AAAA answer is recorded. Drawing code (packets band, etc.) reads
 * via host_cache_lookup() to enrich IPs with the most-recent qname we
 * saw resolving to them.
 *
 * The cache is bounded; once full we overwrite the oldest entry. All
 * operations are mutex-protected so callers from either thread are
 * safe. Returned strings from host_cache_lookup() are copied into the
 * caller's buffer so they can be used without holding the lock. */

#define HOST_CACHE_CAP    1024
#define HOST_CACHE_IPLEN  46     /* INET6_ADDRSTRLEN */
#define HOST_CACHE_HOSTLEN 96

/* Record an observation. Both arguments are NUL-terminated. Empty
 * ip, empty host, or host == "NXDOMAIN" are dropped silently. */
void        host_cache_add(const char *ip, const char *host);

/* Look up ip; copy hostname into out (NUL-terminated). Returns 1 on
 * hit, 0 if the IP isn't cached (out[0] = 0 in that case). */
int         host_cache_lookup(const char *ip, char *out, int out_sz);

/* Current number of entries (capped at HOST_CACHE_CAP). */
int         host_cache_count(void);

/* Drop all entries — used by tests. */
void        host_cache_clear(void);

#endif /* SLOTH_HOST_CACHE_H */
