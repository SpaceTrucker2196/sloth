#ifndef THREAT_INTEL_H
#define THREAT_INTEL_H

/* Compile-time IOC lists. Synthetic test indicators only — see threat_intel.c.
 *
 * Each match function returns 1 if `needle` matches an IOC, 0 otherwise.
 * When matched, *matched is set to a pointer to the canonical IOC string in
 * the embedded list (caller must not free it). */

int ti_match_domain(const char *domain, const char **matched);
int ti_match_ip    (const char *ip,     const char **matched);

#endif /* THREAT_INTEL_H */
