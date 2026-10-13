#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "karma_detect.h"
#include "views/karma.h"

/* State-driven only: karma_update reads the beacon table, client PNLs,
 * and the deauth ring, and writes s->karma_aps[]. */

static void seed(sloth_state_t *s) { memset(s, 0, sizeof(*s)); }

/* A BSSID beaconing `n` distinct SSIDs (via ssid_history). */
static void add_multi_ssid_ap(sloth_state_t *s, const uint8_t bssid[6],
                              const char *const *ssids, int n) {
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count++];
    memset(b, 0, sizeof(*b));
    memcpy(b->bssid, bssid, 6);
    int cap = n < MAX_AP_SSID_HISTORY ? n : MAX_AP_SSID_HISTORY;
    for (int i = 0; i < cap; i++)
        snprintf(b->ssid_history[i], 33, "%s", ssids[i]);
    b->ssid_history_n = cap;
    if (cap > 0) snprintf(b->ssid, sizeof(b->ssid), "%s", ssids[cap - 1]);
    b->last_seen = time(NULL);
}

static void add_pnl_client(sloth_state_t *s, const uint8_t mac[6],
                           const char *const *ssids, int n) {
    pnl_client_t *c = &s->pnl_clients[s->pnl_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac, mac, 6);
    int cap = n < MAX_PNL_SSIDS_PER_CLI ? n : MAX_PNL_SSIDS_PER_CLI;
    for (int i = 0; i < cap; i++)
        snprintf(c->ssids[i], 33, "%s", ssids[i]);
    c->ssid_count = cap;
}

/* An empty state produces an empty karma table — and the view renders it
 * without crashing. */
static void test_empty_state(void) {
    sloth_state_t s; seed(&s);
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 0);
    view_karma_draw(&s);   /* must not crash on empty */
}

/* A BSSID beaconing >= threshold distinct SSIDs becomes a candidate;
 * one below threshold does not. */
static void test_threshold(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t benign[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    const char *few[]  = { "office", "office-guest" };
    add_multi_ssid_ap(&s, lure, many, 3);
    add_multi_ssid_ap(&s, benign, few, 2);
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 1);
    ASSERT_EQ(s.karma_aps[0].ssid_count, 3);
    ASSERT_EQ(memcmp(s.karma_aps[0].bssid, lure, 6), 0);
}

/* PNL overlap is counted, and two names in ONE station's list raise
 * the score (#90 — see test_pnl_hits_spread_across_clients_* for why
 * the union does not). */
static void test_pnl_overlap_and_score(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    add_multi_ssid_ap(&s, lure, many, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl[] = { "homewifi", "ACME-Corp" };
    add_pnl_client(&s, cli, pnl, 2);
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 1);
    ASSERT_EQ(s.karma_aps[0].pnl_overlap, 2);
    ASSERT_EQ(s.karma_aps[0].pnl_best,    2);   /* both on one station */
    ASSERT_EQ(s.karma_aps[0].score, 1 + 2);   /* base + overlap */
}

/* The union is not the measure (#90). Two clients that each remember a
 * different single one of the advertised SSIDs produce pnl_overlap 2 —
 * the number the operator is shown — but no station asked for more
 * than one, so nothing corroborates and the score stays at base.
 *
 * This is the issue's third problem bullet: one SSID of a benign
 * multi-VAP AP landing in one passer-by's remembered list used to be
 * enough, and common names land there constantly. */
static void test_pnl_hits_spread_across_clients_no_score_credit(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    add_multi_ssid_ap(&s, lure, many, 3);
    uint8_t cli_a[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0x01};
    uint8_t cli_b[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0x02};
    const char *pnl_a[] = { "homewifi" };
    const char *pnl_b[] = { "Starbucks" };
    add_pnl_client(&s, cli_a, pnl_a, 1);
    add_pnl_client(&s, cli_b, pnl_b, 1);
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 1);
    ASSERT_EQ(s.karma_aps[0].pnl_overlap, 2);   /* union, reported */
    ASSERT_EQ(s.karma_aps[0].pnl_best,    1);   /* best single station */
    ASSERT_EQ(s.karma_aps[0].score,       1);   /* base only */
}

/* One station remembering exactly one of the advertised names is the
 * same coincidence with one client instead of two. */
static void test_pnl_single_hit_no_score_credit(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    add_multi_ssid_ap(&s, lure, many, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl[] = { "Starbucks" };
    add_pnl_client(&s, cli, pnl, 1);
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].pnl_overlap, 1);
    ASSERT_EQ(s.karma_aps[0].pnl_best,    1);
    ASSERT_EQ(s.karma_aps[0].score,       1);
}

/* Jaccard(advertised, PNL-union) in ppm. AP advertises {a,b,c} (|A|=3),
 * the PNL union is {a,b} (|B|=2), intersection {a,b} (2). Union = 3, so
 * Jaccard = 2/3 = 666666 ppm. A full-overlap lure trends toward 1e6. */
static void test_jaccard_ppm(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, lure, adv, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl[] = { "a", "b" };
    add_pnl_client(&s, cli, pnl, 2);
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].pnl_jaccard_ppm, 666666);
}

static void test_jaccard_full_overlap(void) {
    /* AP advertises exactly the PNL union → Jaccard = 1.0 (1e6). */
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, lure, adv, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl[] = { "a", "b", "c" };
    add_pnl_client(&s, cli, pnl, 3);
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].pnl_jaccard_ppm, 1000000);
}

/* IE-uniformity: all SSIDs from one BSSID carry an identical IE
 * fingerprint (the PineAP tell) -> ie_uniform set, +1 to score. */
static void test_ie_uniform(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, lure, adv, 3);
    /* Same non-zero fingerprint across every SSID. */
    for (int i = 0; i < 3; i++) s.beacon_aps[0].ssid_history_fp[i] = 0xABCD1234u;
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].ie_uniform, 1);
    ASSERT_EQ(s.karma_aps[0].score, 1 + 1);   /* base + ie_uniform */
}

static void test_ie_varied_not_uniform(void) {
    /* A legit multi-VAP AP varies its per-VAP IE tuple -> not uniform. */
    sloth_state_t s; seed(&s);
    uint8_t ap[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, ap, adv, 3);
    s.beacon_aps[0].ssid_history_fp[0] = 0x11111111u;
    s.beacon_aps[0].ssid_history_fp[1] = 0x22222222u;
    s.beacon_aps[0].ssid_history_fp[2] = 0x33333333u;
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].ie_uniform, 0);
}

static void test_ie_unknown_fp_not_uniform(void) {
    /* All-zero (unknown) fingerprints must not read as "uniform". */
    sloth_state_t s; seed(&s);
    uint8_t ap[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, ap, adv, 3);   /* fp left 0 */
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].ie_uniform, 0);
}

/* A deauth flood only sets the chain flag when it names a *shared
 * victim* of this candidate (#90) — someone deauthed off a different
 * BSSID whose PNL already asks for one of the candidate's advertised
 * SSIDs. An unrelated flood elsewhere in range must not credit every
 * KARMA candidate with someone else's bad luck. */
static void test_deauth_chain(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6]  = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t real[6]  = {0x99,0x88,0x77,0x66,0x55,0x44};   /* different BSSID */
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    add_multi_ssid_ap(&s, lure, many, 3);
    uint8_t victim[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    deauth_victim_t *v = &s.deauth_victims[s.deauth_victim_count++];
    memset(v, 0, sizeof(*v));
    memcpy(v->victim, victim, 6);
    memcpy(v->bssid,  real,   6);
    v->flood      = 1;
    v->flood_last = time(NULL);
    /* The victim's PNL already asks for one of the lure's SSIDs — the
     * PineAP Beacon-Response setup. */
    add_pnl_client(&s, victim, many, 1);
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].deauth_chain, 1);
    /* One PNL hit is enough for the chain and deliberately not enough
     * for the standalone PNL bonus (#90): the flood already ties this
     * station to this candidate, so the PNL entry only has to name a
     * network the candidate is answering. The two rules are
     * independent and this pins the asymmetry — base + chain(3), no
     * overlap bonus. */
    ASSERT_EQ(s.karma_aps[0].pnl_overlap, 1);
    ASSERT_EQ(s.karma_aps[0].pnl_best,    1);
    ASSERT_EQ(s.karma_aps[0].score, 1 + 3);
}

/* An unrelated deauth flood — no shared victim — must not set the
 * chain flag, even though a flood is concurrently active somewhere. */
static void test_deauth_chain_unrelated_victim_no_credit(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t real[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    add_multi_ssid_ap(&s, lure, many, 3);
    uint8_t victim[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    deauth_victim_t *v = &s.deauth_victims[s.deauth_victim_count++];
    memset(v, 0, sizeof(*v));
    memcpy(v->victim, victim, 6);
    memcpy(v->bssid,  real,   6);
    v->flood      = 1;
    v->flood_last = time(NULL);
    /* No PNL entry and no association tying this victim to the lure. */
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].deauth_chain, 0);
    ASSERT_EQ(s.karma_aps[0].score, 1);   /* base only */
}

/* Candidates are ranked strongest-first. */
/* #90: the [y] view says a tool attribution is provisional in words,
 * using the same text as the KARMA_AP alert detail. TPRINT is printf in
 * the test build, so the draw is captured and asserted on. */
static void capture_karma(const sloth_state_t *s, char *buf, int sz) {
    fflush(stdout);
    int saved = dup(fileno(stdout));
    FILE *tmp = tmpfile();
    dup2(fileno(tmp), fileno(stdout));
    view_karma_draw(s);
    fflush(stdout);
    dup2(saved, fileno(stdout));
    close(saved);
    rewind(tmp);
    int n = (int)fread(buf, 1, sz - 1, tmp);
    buf[n < 0 ? 0 : n] = '\0';
    fclose(tmp);
}

static void test_tool_attribution_marked_provisional(void) {
    sloth_state_t s; seed(&s);
    uint8_t esp[6] = {0x24,0x6f,0x28,0x33,0x44,0x55};    /* Espressif */
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    add_multi_ssid_ap(&s, esp, many, 3);
    beacon_ap_t *b = &s.beacon_aps[s.beacon_count - 1];
    b->beacon_ms = 102;                        /* 100 TU */
    b->fp.flags  = AP_FP_FLAG_ESPRESSIF_OUI;   /* and no HT */
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 1);
    ASSERT_STR(s.karma_aps[0].tool, "ESP32 Marauder/med? provisional");
    /* Display only: an UNVERIFIED guess is not corroboration, so it
     * must not move the ranking score. */
    ASSERT_EQ(s.karma_aps[0].score, 1);

    char out[8192];
    capture_karma(&s, out, sizeof(out));
    ASSERT(strstr(out, "[ESP32 Marauder/med? provisional]") != NULL);
    ASSERT(strstr(out, "UNVERIFIED signature") != NULL);

    /* No match, no attribution — and nothing provisional on the row. */
    b->fp.flags |= AP_FP_FLAG_HT_PRESENT;
    karma_update(&s);
    ASSERT_STR(s.karma_aps[0].tool, "");
    capture_karma(&s, out, sizeof(out));
    ASSERT(strstr(out, "[ESP32") == NULL);
}

/* The [y] view has to say what earns the PNL credit, or a row showing
 * PNL 2 and score 1 looks like a bug (#90). The legend quotes
 * KARMA_PNL_CORROB_MIN rather than a literal, and the column keeps
 * showing the union so the reading is not hidden. */
/* Narrowing the gate must not hide the reading: the PNL column still
 * prints the *union* count, so a row whose score lost its +2 still
 * shows what was seen. Both states here render the same digit — one
 * station remembering two of the advertised names versus two stations
 * remembering one each — and differ only in pnl_best.
 *
 * NOT asserted here, and deliberately not claimed: that the column
 * goes bright on pnl_best >= KARMA_PNL_CORROB_MIN rather than on the
 * union. `tests/null_tui.c` stubs tui_bright()/tui_dim() to no-ops for
 * the whole test binary, so no view's colour decision is observable
 * from a captured draw. Reverting that one condition in
 * src/views/karma.c leaves this suite green; it is covered by review
 * and by the legend line below, not by an assertion. */
static void test_view_pnl_column_still_shows_the_union(void) {
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    char out[8192];

    sloth_state_t spread; seed(&spread);
    add_multi_ssid_ap(&spread, lure, many, 3);
    uint8_t cli_a[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0x01};
    uint8_t cli_b[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0x02};
    const char *pnl_a[] = { "homewifi" };
    const char *pnl_b[] = { "Starbucks" };
    add_pnl_client(&spread, cli_a, pnl_a, 1);
    add_pnl_client(&spread, cli_b, pnl_b, 1);
    karma_update(&spread);
    ASSERT_EQ(spread.karma_aps[0].pnl_overlap, 2);
    ASSERT_EQ(spread.karma_aps[0].pnl_best,    1);
    ASSERT_EQ(spread.karma_aps[0].score,       1);
    capture_karma(&spread, out, sizeof(out));
    /* BSSID, SSIDs 3, PNL 2 — the union, printed despite no credit. */
    ASSERT(strstr(out, "00:11:22:33:44:55      3     2") != NULL);

    sloth_state_t one; seed(&one);
    add_multi_ssid_ap(&one, lure, many, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl_both[] = { "homewifi", "Starbucks" };
    add_pnl_client(&one, cli, pnl_both, 2);
    karma_update(&one);
    ASSERT_EQ(one.karma_aps[0].pnl_best, 2);
    ASSERT_EQ(one.karma_aps[0].score,    1 + 2);
    capture_karma(&one, out, sizeof(out));
    ASSERT(strstr(out, "00:11:22:33:44:55      3     2") != NULL);
}

static void test_view_legend_states_the_corroboration_rule(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    add_multi_ssid_ap(&s, lure, many, 3);
    uint8_t cli_a[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0x01};
    uint8_t cli_b[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0x02};
    const char *pnl_a[] = { "homewifi" };
    const char *pnl_b[] = { "Starbucks" };
    add_pnl_client(&s, cli_a, pnl_a, 1);
    add_pnl_client(&s, cli_b, pnl_b, 1);
    karma_update(&s);

    char out[8192];
    capture_karma(&s, out, sizeof(out));
    ASSERT(strstr(out, ">=2 on one station") != NULL);
    ASSERT(strstr(out, "deauth-then-lure on shared victim") != NULL);
    /* Legend must fit the documented 100-column minimum terminal. */
    const char *leg = strstr(out, " PNL = SSIDs");
    ASSERT(leg != NULL);
    if (leg) {
        const char *nl = strchr(leg, '\n');
        ASSERT(nl != NULL);
        if (nl) ASSERT(nl - leg <= 100);
    }
}

static void test_ranking(void) {
    sloth_state_t s; seed(&s);
    uint8_t weak[6]   = {0x00,0x11,0x22,0x33,0x44,0x01};
    uint8_t strong[6] = {0x00,0x11,0x22,0x33,0x44,0x02};
    const char *weak_ssids[]   = { "x", "y", "z" };   /* not in any PNL */
    const char *strong_ssids[] = { "a", "b", "c" };   /* a,b probed for */
    add_multi_ssid_ap(&s, weak, weak_ssids, 3);
    add_multi_ssid_ap(&s, strong, strong_ssids, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl[] = { "a", "b" };
    add_pnl_client(&s, cli, pnl, 2);
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 2);
    /* strong (one station asks for 2 of its SSIDs, so the PNL bonus
     * applies) must sort ahead of weak (no PNL hit at all). */
    ASSERT(s.karma_aps[0].score >= s.karma_aps[1].score);
    ASSERT_EQ(memcmp(s.karma_aps[0].bssid, strong, 6), 0);
}

/* Selection stays in bounds when the table shrinks between polls. */
static void test_sel_clamps(void) {
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0x00,0x11,0x22,0x33,0x44,0x01};
    uint8_t b[6] = {0x00,0x11,0x22,0x33,0x44,0x02};
    const char *many[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, a, many, 3);
    add_multi_ssid_ap(&s, b, many, 3);
    karma_update(&s);
    s.karma_sel = 1;
    view_karma_key(&s, SLOTH_KEY_DOWN);   /* already at last */
    ASSERT_EQ(s.karma_sel, 1);
    /* Next poll only one candidate — sel must clamp. */
    s.beacon_count = 1;
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 1);
    ASSERT_EQ(s.karma_sel, 0);
    view_karma_draw(&s);
}

/* ── The alert key the dashboard badge looks up (#90) ──────
 *
 * The beacon panel badges an active lure by finding the KARMA_AP alert
 * for a BSSID and reading its SEVERITY, rather than comparing
 * karma_ap_t.score against a hardcoded threshold as it used to. That
 * change is the point: the score is a confidence number whose formula
 * moves whenever detection improves, and #90's own PNL work silently
 * dropped a deauth-chain candidate below the old threshold of 5 —
 * nobody decided that, it fell out of arithmetic in another file.
 *
 * What CANNOT be tested here, stated rather than implied:
 * karma_badge_hot() lives in src/views/dashboard_grid.c, which is
 * compiled only under WITH_NCURSES. TEST_CFLAGS does not define it, so
 * that function is not linked into sloth_test and no assertion can
 * reach it. Reviewers proved the same thing about this issue's other
 * view tests, which exercised the `#else` printf branch instead.
 *
 * So the contract is moved to where it CAN be tested: both surfaces
 * build the key through karma_alert_key(), and these cases pin that
 * function plus the fact that a fired alert actually carries what it
 * produces. A divergence between the two would not error — it would
 * quietly stop badging and read as a quiet night. */
static void test_karma_alert_key_format(void) {
    const uint8_t b[6] = {0x00,0x11,0x22,0xaa,0xbb,0xcc};
    char k[ALERT_KEY_LEN];
    karma_alert_key(b, k, sizeof(k));
    /* Lower-case hex, colon-separated, "karma:" prefix — the literal the
       alert engine dedupes on. Written out rather than rebuilt with the
       same snprintf, which would only prove snprintf is deterministic. */
    ASSERT_STR(k, "karma:00:11:22:aa:bb:cc");

    /* High bytes are not sign-extended or upper-cased. */
    const uint8_t hi[6] = {0xff,0xfe,0x80,0x7f,0x01,0x00};
    karma_alert_key(hi, k, sizeof(k));
    ASSERT_STR(k, "karma:ff:fe:80:7f:01:00");

    /* Defensive arms: neither writes out of bounds, and a NULL bssid
       yields an empty string rather than garbage a lookup might match. */
    karma_alert_key(b, k, 1);
    ASSERT_EQ((int)k[0], 0);
    karma_alert_key(NULL, k, sizeof(k));
    ASSERT_EQ((int)k[0], 0);
    karma_alert_key(b, NULL, 0);      /* ASan is the assertion */
    ASSERT(1);
}

void run_karma_tests(void) {
    TEST_SUITE("KARMA/PineAP view (#30)");
    RUN_TEST(test_karma_alert_key_format);
    RUN_TEST(test_empty_state);
    RUN_TEST(test_threshold);
    RUN_TEST(test_pnl_overlap_and_score);
    RUN_TEST(test_pnl_hits_spread_across_clients_no_score_credit);
    RUN_TEST(test_pnl_single_hit_no_score_credit);
    RUN_TEST(test_jaccard_ppm);
    RUN_TEST(test_jaccard_full_overlap);
    RUN_TEST(test_ie_uniform);
    RUN_TEST(test_ie_varied_not_uniform);
    RUN_TEST(test_ie_unknown_fp_not_uniform);
    RUN_TEST(test_deauth_chain);
    RUN_TEST(test_deauth_chain_unrelated_victim_no_credit);
    RUN_TEST(test_tool_attribution_marked_provisional);
    RUN_TEST(test_view_legend_states_the_corroboration_rule);
    RUN_TEST(test_view_pnl_column_still_shows_the_union);
    RUN_TEST(test_ranking);
    RUN_TEST(test_sel_clamps);
}
