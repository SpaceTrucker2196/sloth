#include <string.h>
#include "runner.h"
#include "vendor_watchlist.h"

/* Surveillance-vendor endpoint watchlist (#105 family B).
 *
 * No fixtures and nothing protocol-shaped to build: the input is a
 * hostname string, so the tests are the hostname cases the suffix
 * matcher has to get right. The negative cases are the point — a
 * watchlist that matches too much attaches a vendor's name to
 * unrelated traffic. */

static void test_exact_domain_matches(void) {
    const char *vendor = NULL, *family = NULL;
    ASSERT(vendor_watchlist_match_domain("evidence.com", &vendor, &family));
    ASSERT(vendor != NULL);
    ASSERT_STR(vendor, "axon");
    ASSERT_STR(family, "evidence-cloud");
}

static void test_subdomain_matches(void) {
    /* The reason the table holds domains and not hostnames: a dock's
       upload host is not something this repo can enumerate. */
    const char *vendor = NULL, *family = NULL;
    ASSERT(vendor_watchlist_match_domain("ab4-upload.evidence.com",
                                         &vendor, &family));
    ASSERT_STR(vendor, "axon");
}

static void test_deep_subdomain_matches(void) {
    const char *vendor = NULL;
    ASSERT(vendor_watchlist_match_domain("a.b.c.evidence.com", &vendor, NULL));
    ASSERT_STR(vendor, "axon");
}

static void test_case_insensitive(void) {
    /* SNI is not required to be lowercase, and sloth stores whatever
       the ClientHello carried. */
    const char *vendor = NULL;
    ASSERT(vendor_watchlist_match_domain("EVIDENCE.COM", &vendor, NULL));
    ASSERT_STR(vendor, "axon");
    ASSERT(vendor_watchlist_match_domain("Upload.Evidence.Com", &vendor, NULL));
    ASSERT_STR(vendor, "axon");
}

static void test_no_label_boundary_does_not_match(void) {
    /* "notevidence.com" ends with the table string but is a different
       domain. Without the label-boundary check this would fire. */
    ASSERT(!vendor_watchlist_match_domain("notevidence.com", NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("myaxon.com", NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("notflocksafety.com", NULL, NULL));
}

static void test_prefix_is_not_a_suffix(void) {
    /* The classic watchlist evasion in the other direction: an
       attacker-controlled domain with the vendor's name on the left. */
    ASSERT(!vendor_watchlist_match_domain("evidence.com.attacker.example",
                                          NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("evidence.com.evil", NULL, NULL));
}

static void test_unrelated_host_does_not_match(void) {
    ASSERT(!vendor_watchlist_match_domain("news.example", NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("com", NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("evidence", NULL, NULL));
}

static void test_flock_and_axon_are_distinct_vendors(void) {
    const char *vendor = NULL, *family = NULL;
    ASSERT(vendor_watchlist_match_domain("transparency.flocksafety.com",
                                         &vendor, &family));
    ASSERT_STR(vendor, "flock-safety");
    ASSERT_STR(family, "alpr-cloud");
    ASSERT(vendor_watchlist_match_domain("my.axon.com", &vendor, &family));
    ASSERT_STR(vendor, "axon");
    ASSERT_STR(family, "evidence-cloud");
}

static void test_unsourced_domains_are_absent(void) {
    /* axondocs.com is named in #105's design and is deliberately NOT
       in the table: no Axon-operated service by that name could be
       sourced, and an unverifiable row still labels whatever it hits.
       Asserted so a later "completeness" pass has to read the
       reasoning in research/papers/surveillance-vendor-endpoints.md
       before adding it back. */
    ASSERT(!vendor_watchlist_match_domain("axondocs.com", NULL, NULL));
    /* Ring was checked against the bar and failed it: Ring's support
       article on the protocols and ports its devices use names ports
       and no domains, so there is no Ring row to cite (retrieved
       2026-10-20, see the research document). */
    ASSERT(!vendor_watchlist_match_domain("ring.com", NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("fw.ring.com", NULL, NULL));
    /* #105's scope extension proposes *.rekor.ai and *.rekorsystems.com
       as SNI globs. No Rekor network-requirements document was found,
       so they are a proposal, not a row. */
    ASSERT(!vendor_watchlist_match_domain("rekor.ai", NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("api.rekorsystems.com", NULL, NULL));
}

static void test_verkada_control_plane_matches(void) {
    /* Hostnames copied from Verkada's "Camera Network Settings"
       allowlist tables (US, EU and AU regions). */
    static const char *const hosts[] = {
        "api.control.verkada.com",
        "relay.prod-us-ohio.control.verkada.com",
        "index.prod.ap.syd.control.verkada.com",
        "x1.vstream.vnetcap.control.verkada.com",
        "firmware.control.verkada.com",
    };
    for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        const char *vendor = NULL, *family = NULL;
        ASSERT(vendor_watchlist_match_domain(hosts[i], &vendor, &family));
        ASSERT_STR(vendor, "verkada");
        ASSERT_STR(family, "camera-cloud");
    }
}

static void test_verkada_marketing_site_does_not_match(void) {
    /* The row is control.verkada.com and not verkada.com on purpose:
       the document's coarse "*.verkada.com" rule would also cover
       Verkada's marketing site, and the narrower row is what every
       Verkada-operated camera FQDN on that page falls under except
       the vconductor.*.command.verkada.com hosts, which are left out
       rather than given a second row from the same document. */
    ASSERT(!vendor_watchlist_match_domain("verkada.com", NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("www.verkada.com", NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("command.verkada.com", NULL, NULL));
    /* Label boundary on a multi-label row: "xcontrol.verkada.com" ends
       with the row string but is a different name. */
    ASSERT(!vendor_watchlist_match_domain("xcontrol.verkada.com", NULL, NULL));
}

static void test_null_and_empty(void) {
    /* NULL is the load-bearing half: deleting the guard in
       vendor_watchlist_match_domain() segfaults the suite here, in
       strlen. The empty string is belt-and-braces — `dn < en` would
       reject it anyway — so this half asserts the contract, not a
       guard that could silently rot. */
    ASSERT(!vendor_watchlist_match_domain(NULL, NULL, NULL));
    ASSERT(!vendor_watchlist_match_domain("",   NULL, NULL));
}

static void test_match_without_out_ptrs(void) {
    /* Callers that only want the yes/no must not be made to pass
       scratch pointers. */
    ASSERT(vendor_watchlist_match_domain("evidence.com", NULL, NULL));
}

static void test_out_ptrs_untouched_on_miss(void) {
    const char *vendor = (const char *)0x1;
    const char *family = (const char *)0x1;
    ASSERT(!vendor_watchlist_match_domain("news.example", &vendor, &family));
    ASSERT(vendor == (const char *)0x1);
    ASSERT(family == (const char *)0x1);
}

void run_vendor_watchlist_tests(void) {
    TEST_SUITE("vendor watchlist: matches");
    RUN_TEST(test_exact_domain_matches);
    RUN_TEST(test_subdomain_matches);
    RUN_TEST(test_deep_subdomain_matches);
    RUN_TEST(test_case_insensitive);
    RUN_TEST(test_flock_and_axon_are_distinct_vendors);
    RUN_TEST(test_verkada_control_plane_matches);

    TEST_SUITE("vendor watchlist: non-matches");
    RUN_TEST(test_no_label_boundary_does_not_match);
    RUN_TEST(test_prefix_is_not_a_suffix);
    RUN_TEST(test_unrelated_host_does_not_match);
    RUN_TEST(test_unsourced_domains_are_absent);
    RUN_TEST(test_verkada_marketing_site_does_not_match);
    RUN_TEST(test_null_and_empty);

    TEST_SUITE("vendor watchlist: output contract");
    RUN_TEST(test_match_without_out_ptrs);
    RUN_TEST(test_out_ptrs_untouched_on_miss);
}
