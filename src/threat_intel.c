#include <string.h>
#include <strings.h>
#include "threat_intel.h"

/* Embedded IOC list — SYNTHETIC DEMO DATA, NOT A THREAT FEED.
 *
 * Every entry is a sentinel chosen so it cannot plausibly appear in real
 * traffic: the IPs are RFC 5737 documentation addresses, the domains are
 * obvious fakes (two under the RFC 2606 reserved TLDs .example / .test,
 * the rest under testing.com / example-bad.com labels). They exist so
 * the alerts pipeline can be exercised in unit tests and so an operator
 * has a template to extend. In practice they match nothing, which means
 * THREAT_DOMAIN and THREAT_IP detect nothing in production until this
 * list is replaced.
 *
 * Sloth ships no feed and fetches none — fetching one would be a network
 * write, which MISSION.md §2 forbids. The synthetic status is stated in
 * three operator-visible places and all three must stay in sync (#96):
 * this comment, the "demo IOC" marker in the alert detail written by
 * rule_threat_domain / rule_threat_ip in src/alerts.c, and the
 * "Embedded data" section of the help view (src/views/help.c). Docs:
 * docs/wiki/threat-intel.md. */

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
