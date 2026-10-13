#include <stddef.h>
#include <string.h>
#include <strings.h>
#include "vendor_watchlist.h"

/* See vendor_watchlist.h for why this is embedded and not a CSV.
 *
 * Deliberately short. #105's scope-extension comment lists two dozen
 * more vendors, all of them at "confidence: low" by the issue's own
 * admission — "no vendor on this list publishes its on-air
 * fingerprint". A row whose domain nobody publishes is a guess with a
 * vendor name attached, which is the evidence-overstatement defect #90
 * is open about. So only domains a primary vendor source names are
 * here, and the rest wait for sources.
 *
 * Suffix semantics: each entry matches itself and any subdomain, so
 * "evidence.com" covers "ab4-upload.evidence.com" without the table
 * having to enumerate upload hostnames it cannot know. */
static const struct {
    const char *domain;
    const char *vendor;
    const char *family;
} kEndpoints[] = {
    /* Axon's evidence-management cloud. The legacy domain: Axon's VR
     * network-allowlist page instructs agencies to allowlist
     * "vr.evidence.com/nlu" and "vr.evidence.com/g2p", and the Axon
     * Cloud customer FAQ points at "status.evidence.com/status/network"
     * as its own connectivity test. */
    { "evidence.com",   "axon",          "evidence-cloud" },
    /* The migration destination for the same platform. The Axon Cloud
     * customer FAQ: "Access to Axon Evidence services will begin
     * transitioning from evidence.com to a new address under
     * axon.com", and tells agencies with allowlists, DNS filtering or
     * proxies to permit axon.com before migration reaches them. Broad
     * on purpose and broad in consequence: this is also Axon's
     * marketing site, so a browser tab on axon.com fires the rule. The
     * alert text says it cannot tell those apart rather than implying
     * a device was found. */
    { "axon.com",       "axon",          "evidence-cloud" },
    /* Flock Safety's service domain — agency transparency portals live
     * at transparency.flocksafety.com (published by Flock and linked
     * from many municipal sites). Note what this does NOT detect: a
     * Flock ALPR camera uplinks over cellular, so the camera's own
     * traffic never crosses a monitored segment. A hit here is a host
     * on this network using the platform, not a camera on it. */
    { "flocksafety.com", "flock-safety", "alpr-cloud" },
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
