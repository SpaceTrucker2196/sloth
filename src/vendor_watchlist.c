#include <stddef.h>
#include <string.h>
#include <strings.h>
#include "vendor_watchlist.h"

/* See vendor_watchlist.h for why this is compiled in rather than read
 * at run time; the rows themselves come from the pinned intel pack.
 *
 * Deliberately short. #105's scope-extension comment lists two dozen
 * more vendors, all of them at "confidence: low" by the issue's own
 * admission — "no vendor on this list publishes its on-air
 * fingerprint". A row whose domain nobody publishes is a guess with a
 * vendor name attached, which is the evidence-overstatement defect #90
 * is open about. So only domains a primary vendor source names are
 * here, and the rest wait for sources.
 *
 * The bar for a new row (#145 ruling 2): the vendor publishes its own
 * network-requirements or firewall allow-list document naming the
 * domain; one row per document, cited with URL and retrieval date in
 * research/papers/surveillance-vendor-endpoints.md. A vendor whose
 * public trace is a product name, a marketing site, or a ports-only
 * page stays out — test_unsourced_domains_are_absent pins the ones
 * that were checked and failed the bar.
 *
 * Suffix semantics: each entry matches itself and any subdomain, so
 * "evidence.com" covers "ab4-upload.evidence.com" without the table
 * having to enumerate upload hostnames it cannot know. */
static const struct {
    const char *domain;
    const char *vendor;
    const char *family;
} kEndpoints[] = {
    /* intel/surveillance-endpoints/surveillance_endpoints.csv (#231);
     * the per-row sources that stood here are that pack's SOURCE.md and
     * research/papers/surveillance-vendor-endpoints.md. Two the alert
     * text depends on: axon.com is also Axon's marketing site, so a
     * browser tab fires the rule and the detail says it cannot tell
     * them apart; a Flock ALPR camera uplinks over cellular, so a
     * flocksafety.com hit is a host using the platform, never a camera
     * on this network. */
#include "surveillance_endpoints.inc"
};

/* Label-boundary suffix match, identical semantics to
 * domain_suffix_match in src/threat_intel.c: "evidence.com" matches
 * itself and "x.evidence.com", but not "notevidence.com" (no label
 * boundary) and not "evidence.com.attacker.example" (not a suffix). */
static int domain_suffix_match(const char *domain, const char *entry) {
    size_t dn = strlen(domain);
    size_t en = strlen(entry);
    if (en == 0 || dn < en) return 0;
    const char *tail = domain + (dn - en);
    if (strcasecmp(tail, entry) != 0) return 0;
    if (dn == en) return 1;
    return (tail[-1] == '.');
}

int vendor_watchlist_match_domain(const char *host,
                                  const char **vendor,
                                  const char **family) {
    if (!host || !host[0]) return 0;
    for (size_t i = 0; i < sizeof(kEndpoints) / sizeof(kEndpoints[0]); i++) {
        if (!domain_suffix_match(host, kEndpoints[i].domain)) continue;
        if (vendor) *vendor = kEndpoints[i].vendor;
        if (family) *family = kEndpoints[i].family;
        return 1;
    }
    return 0;
}

int vendor_watchlist_count(void) {
    return (int)(sizeof(kEndpoints) / sizeof(kEndpoints[0]));
}
