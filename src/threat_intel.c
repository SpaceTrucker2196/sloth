#include <string.h>
#include <strings.h>
#include "threat_intel.h"

/* Embedded IOC list.
 *
 * These are all synthetic/test indicators (RFC 5737 documentation IPs and
 * .testing/.example sentinel names). They exist so that the alerts pipeline
 * can be exercised in unit tests and so users have a clear template to
 * extend — they are NOT meant as a real threat feed. */

static const char *bad_domains[] = {
    "malware.testing.com",
    "phishing.testing.com",
    "c2.example-bad.com",
    "evilcorp.example",
    "badactor.test",
    "drive-by.testing.com",
    NULL,
};

static const char *bad_ips[] = {
    /* RFC 5737 documentation prefixes — safe synthetic addresses. */
    "192.0.2.66",
    "192.0.2.99",
    "198.51.100.7",
    "203.0.113.13",
    NULL,
};

/* Suffix match: returns 1 if `domain` ends with `ioc` (case-insensitive),
 * optionally separated by '.' so "evilcorp.example" matches both itself
 * and "x.evilcorp.example". */
static int domain_suffix_match(const char *domain, const char *ioc) {
    size_t dn = strlen(domain);
    size_t in = strlen(ioc);
    if (in == 0 || dn < in) return 0;
    const char *tail = domain + (dn - in);
    if (strcasecmp(tail, ioc) != 0) return 0;
    if (dn == in) return 1;
    /* require the byte before the suffix to be '.' so "notevilcorp.example"
     * doesn't get flagged via the "evilcorp.example" rule. */
    return (tail[-1] == '.');
}

int ti_match_domain(const char *domain, const char **matched) {
    if (!domain || !domain[0]) return 0;
    for (int i = 0; bad_domains[i]; i++) {
        if (domain_suffix_match(domain, bad_domains[i])) {
            if (matched) *matched = bad_domains[i];
            return 1;
        }
    }
    return 0;
}

int ti_match_ip(const char *ip, const char **matched) {
    if (!ip || !ip[0]) return 0;
    for (int i = 0; bad_ips[i]; i++) {
        if (strcmp(ip, bad_ips[i]) == 0) {
            if (matched) *matched = bad_ips[i];
            return 1;
        }
    }
    return 0;
}
