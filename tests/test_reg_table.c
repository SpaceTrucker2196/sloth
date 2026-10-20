#include <string.h>
#include "runner.h"
#include "reg_table.h"

/*
 * The compiled-in 5 GHz channel table — issue #101 slice A.
 *
 * Every expectation below is written out from the sources, not derived
 * from the table under test: the channel sets from 47 CFR 15.407(a)
 * and EN 301 893's two sub-bands, the DFS flags from 15.407(h)(2) and
 * EN 301 893 §4.2.6, the CACs from KDB 905462 D02 (60 s) and §4.2.6
 * (600 s on 5600-5650 MHz). docs/wiki/regulatory-table.md states the
 * same values, so an edit to src/reg_table.c that the page does not
 * describe goes red here.
 */

typedef struct { int ch; int dfs; int cac; } want_row_t;

static const want_row_t k_fcc[] = {
    { 36, 0, 0 }, { 40, 0, 0 }, { 44, 0, 0 }, { 48, 0, 0 },
    { 52, 1, 60 }, { 56, 1, 60 }, { 60, 1, 60 }, { 64, 1, 60 },
    { 100, 1, 60 }, { 104, 1, 60 }, { 108, 1, 60 }, { 112, 1, 60 },
    { 116, 1, 60 }, { 120, 1, 60 }, { 124, 1, 60 }, { 128, 1, 60 },
    { 132, 1, 60 }, { 136, 1, 60 }, { 140, 1, 60 }, { 144, 1, 60 },
    { 149, 0, 0 }, { 153, 0, 0 }, { 157, 0, 0 }, { 161, 0, 0 },
    { 165, 0, 0 },
};

static const want_row_t k_etsi[] = {
    { 36, 0, 0 }, { 40, 0, 0 }, { 44, 0, 0 }, { 48, 0, 0 },
    { 52, 1, 60 }, { 56, 1, 60 }, { 60, 1, 60 }, { 64, 1, 60 },
    { 100, 1, 60 }, { 104, 1, 60 }, { 108, 1, 60 }, { 112, 1, 60 },
    { 116, 1, 60 }, { 120, 1, 600 }, { 124, 1, 600 }, { 128, 1, 600 },
    { 132, 1, 60 }, { 136, 1, 60 }, { 140, 1, 60 },
};

static void check_table(reg_jurisdiction_t j, const want_row_t *w, int n) {
    const reg_table_t *t = reg_table_get(j);
    ASSERT(t != NULL);
    if (!t) return;
    /* Exactly these rows: no extra channel, none missing. */
    ASSERT_EQ(t->n_rows, n);
    for (int i = 0; i < n; i++) {
        const reg_chan_row_t *r = reg_table_lookup(j, w[i].ch);
        ASSERT(r != NULL);
        if (!r) continue;
        ASSERT_EQ((int)r->channel, w[i].ch);
        ASSERT_EQ((int)r->centre_mhz, 5000 + 5 * w[i].ch);
        ASSERT_EQ(!!(r->flags & REG_CH_DFS), w[i].dfs);
        ASSERT_EQ((int)r->cac_s, w[i].cac);
        /* A row with no primary source is not a row (#145 ruling 2). */
        ASSERT(r->clause && r->clause[0]);
    }
}

static void test_fcc_rows_match_15_407(void) {
    check_table(REG_JUR_FCC, k_fcc, (int)(sizeof(k_fcc) / sizeof(k_fcc[0])));
    const reg_table_t *t = reg_table_get(REG_JUR_FCC);
    ASSERT(t && strstr(t->source, "15.407") != NULL);
    /* U-NII-4 was not verified for the table, so it is not in it. */
    ASSERT(reg_table_lookup(REG_JUR_FCC, 169) == NULL);
    ASSERT(reg_table_lookup(REG_JUR_FCC, 177) == NULL);
}

static void test_etsi_rows_match_en_301_893(void) {
    check_table(REG_JUR_ETSI, k_etsi,
                (int)(sizeof(k_etsi) / sizeof(k_etsi[0])));
    const reg_table_t *t = reg_table_get(REG_JUR_ETSI);
    ASSERT(t && strstr(t->source, "EN 301 893") != NULL);
    /* 5710-5730 MHz runs past the 5725 MHz edge of the standard. */
    ASSERT(reg_table_lookup(REG_JUR_ETSI, 144) == NULL);
    /* 5725-5850 MHz is outside EN 301 893 entirely: "not in this
     * source", which the table must not turn into a row. */
    ASSERT(reg_table_lookup(REG_JUR_ETSI, 149) == NULL);
    ASSERT(reg_table_lookup(REG_JUR_ETSI, 165) == NULL);
    /* The weather-radar flag is on exactly the three 600 s rows. */
    const reg_chan_row_t *r = reg_table_lookup(REG_JUR_ETSI, 124);
    ASSERT(r && (r->flags & REG_CH_WEATHER));
    r = reg_table_lookup(REG_JUR_ETSI, 116);
    ASSERT(r && !(r->flags & REG_CH_WEATHER));
    r = reg_table_lookup(REG_JUR_ETSI, 132);
    ASSERT(r && !(r->flags & REG_CH_WEATHER));
}

static void test_table_get_refuses_out_of_range(void) {
    ASSERT(reg_table_get(REG_JUR_NONE) == NULL);
    ASSERT(reg_table_get(REG_JUR_COUNT) == NULL);
    ASSERT(reg_table_get((reg_jurisdiction_t)-1) == NULL);
    ASSERT(reg_table_lookup(REG_JUR_NONE, 52) == NULL);
    /* A 2.4 GHz number is in neither table. */
    ASSERT(reg_table_lookup(REG_JUR_FCC, 6) == NULL);
    ASSERT(reg_table_lookup(REG_JUR_ETSI, 6) == NULL);
}

static void test_country_mapping(void) {
    ASSERT_EQ((int)reg_jurisdiction_for_country("US"), (int)REG_JUR_FCC);
    ASSERT_EQ((int)reg_jurisdiction_for_country("DE"), (int)REG_JUR_ETSI);
    ASSERT_EQ((int)reg_jurisdiction_for_country("FR"), (int)REG_JUR_ETSI);
    ASSERT_EQ((int)reg_jurisdiction_for_country("SE"), (int)REG_JUR_ETSI);
    /* ISO 3166-1 for Greece, not the EU's own "EL". */
    ASSERT_EQ((int)reg_jurisdiction_for_country("GR"), (int)REG_JUR_ETSI);
    ASSERT_EQ((int)reg_jurisdiction_for_country("EL"), (int)REG_JUR_NONE);
    /* Countries with no source read: mapped to nothing, not guessed. */
    ASSERT_EQ((int)reg_jurisdiction_for_country("GB"), (int)REG_JUR_NONE);
    ASSERT_EQ((int)reg_jurisdiction_for_country("NO"), (int)REG_JUR_NONE);
    ASSERT_EQ((int)reg_jurisdiction_for_country("JP"), (int)REG_JUR_NONE);
    ASSERT_EQ((int)reg_jurisdiction_for_country("XX"), (int)REG_JUR_NONE);
    /* The element carries upper case; anything else named no country. */
    ASSERT_EQ((int)reg_jurisdiction_for_country("us"), (int)REG_JUR_NONE);
    ASSERT_EQ((int)reg_jurisdiction_for_country(""), (int)REG_JUR_NONE);
    ASSERT_EQ((int)reg_jurisdiction_for_country(NULL), (int)REG_JUR_NONE);
    ASSERT_EQ((int)reg_jurisdiction_for_country("U"), (int)REG_JUR_NONE);
    ASSERT_EQ((int)reg_jurisdiction_for_country("USA"), (int)REG_JUR_NONE);
}

static void test_dfs_by_named_country(void) {
    reg_jurisdiction_t w = REG_JUR_COUNT;
    int cac = -1;
    ASSERT_EQ(reg_channel_is_dfs("US", 100, &w, &cac), 1);
    ASSERT_EQ((int)w, (int)REG_JUR_FCC);
    ASSERT_EQ(cac, 60);
    /* FCC has no weather-radar extension: 120 is a plain 60 s CAC. */
    ASSERT_EQ(reg_channel_is_dfs("US", 120, &w, &cac), 1);
    ASSERT_EQ(cac, 60);
    ASSERT_EQ(reg_channel_is_dfs("DE", 120, &w, &cac), 1);
    ASSERT_EQ((int)w, (int)REG_JUR_ETSI);
    ASSERT_EQ(cac, 600);
    /* A named country's table answers alone: 144 is DFS under the FCC
     * and absent from EN 301 893, so for "DE" it is not a DFS channel
     * in this table. */
    ASSERT_EQ(reg_channel_is_dfs("DE", 144, &w, &cac), 0);
    ASSERT_EQ(cac, 0);
    ASSERT_EQ(reg_channel_is_dfs("US", 36, &w, &cac), 0);
    ASSERT_EQ(reg_channel_is_dfs("US", 149, &w, &cac), 0);
    ASSERT_EQ(cac, 0);
}

static void test_dfs_union_when_no_country(void) {
    reg_jurisdiction_t w = REG_JUR_COUNT;
    int cac = -1;
    /* No country, or one with no table: the union. */
    ASSERT_EQ(reg_channel_is_dfs(NULL, 144, &w, &cac), 1);
    ASSERT_EQ((int)w, (int)REG_JUR_NONE);
    ASSERT_EQ(cac, 60);
    ASSERT_EQ(reg_channel_is_dfs("JP", 144, &w, &cac), 1);
    ASSERT_EQ((int)w, (int)REG_JUR_NONE);
    /* Longest CAC either source would impose. */
    ASSERT_EQ(reg_channel_is_dfs(NULL, 128, &w, &cac), 1);
    ASSERT_EQ(cac, 600);
    ASSERT_EQ(reg_channel_is_dfs(NULL, 52, &w, &cac), 1);
    ASSERT_EQ(cac, 60);
    ASSERT_EQ(reg_channel_is_dfs(NULL, 48, &w, &cac), 0);
    ASSERT_EQ(cac, 0);
    ASSERT_EQ(reg_channel_is_dfs(NULL, 165, &w, &cac), 0);
    ASSERT_EQ(reg_channel_is_dfs(NULL, 6, NULL, NULL), 0);
    ASSERT_EQ(reg_channel_is_dfs(NULL, 0, NULL, NULL), 0);
    /* The out-params are optional. */
    ASSERT_EQ(reg_channel_is_dfs("US", 64, NULL, NULL), 1);
}

static void test_table_is_dated(void) {
    /* The date is part of the claim; the alert detail prints it. */
    ASSERT_STR(REG_TABLE_AS_OF, "2026-10-20");
    const reg_table_t *t = reg_table_get(REG_JUR_FCC);
    ASSERT(t && strstr(t->source, REG_TABLE_AS_OF) != NULL);
}

void run_reg_table_tests(void) {
    TEST_SUITE("regulatory channel table (#101 slice A)");
    RUN_TEST(test_fcc_rows_match_15_407);
    RUN_TEST(test_etsi_rows_match_en_301_893);
    RUN_TEST(test_table_get_refuses_out_of_range);
    RUN_TEST(test_country_mapping);
    RUN_TEST(test_dfs_by_named_country);
    RUN_TEST(test_dfs_union_when_no_country);
    RUN_TEST(test_table_is_dated);
}
