#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "tui.h"
#include "questions_live.h"
#include "rule_coverage_live.h"
#include "views/questions.h"

/* [!] Questions view (#244), rendered through the test screen. The
 * answers come from q_live_answers() over a hand-built alert snapshot;
 * before any status sample, so coverage reads not assessed. */

static char g_buf[32768];
TEST_STATE(g_s);

static const char *render(void) {
    tui_test_erase();
    view_questions_draw(&g_s);
    tui_test_screen(g_buf, sizeof(g_buf));
    return g_buf;
}

static void seed(alert_type_t t, const char *id) {
    alert_t *a = &g_s.alerts[g_s.alert_count++];
    memset(a, 0, sizeof(*a));
    a->type = t;
    a->sev = ALERT_SEV_WARN;
    snprintf(a->key, sizeof(a->key), "twin:02:11:22:33:44:55");
    snprintf(a->title, sizeof(a->title), "HomeNet");
    snprintf(a->incident_id, sizeof(a->incident_id), "%s", id);
}

static void test_empty_state(void) {
    memset(&g_s, 0, sizeof(g_s));
    view_questions_reset();
    render();
    ASSERT_LINE_HAS(0, "Site questions: 7");
    ASSERT_LINE_HAS(0, "with a finding: 0");
    ASSERT_LINE_HAS(0, "defaults");
    ASSERT_SCREEN_HAS("coverage not assessed: no status sample has been taken yet");
    ASSERT_SCREEN_HAS(" Q1       1   not_assessed");
    ASSERT_SCREEN_HAS("Is the sensor able to see what it must see?");
    /* The first row (Q1) is selected and its decision shown. */
    ASSERT_SCREEN_HAS(" Decision: Warn users off the network and find the transmitter.");
    ASSERT_SCREEN_HAS(" Indicators: 16, not assessed");
    ASSERT_SCREEN_LACKS("Findings:");
}

static void test_populated_and_nav(void) {
    memset(&g_s, 0, sizeof(g_s));
    view_questions_reset();
    seed(ALERT_TYPE_EVIL_TWIN, "00000000000000e1");
    render();
    ASSERT_LINE_HAS(0, "with a finding: 1");
    ASSERT_SCREEN_HAS(" Q1       1   finding           EVIL_TWIN");
    ASSERT_SCREEN_HAS(" Findings: 1 (EVIL_TWIN); incidents 00000000000000e1");
    /* Nothing of the finding but its kind and incident id. */
    ASSERT_SCREEN_LACKS("02:11:22");
    ASSERT_SCREEN_LACKS("HomeNet");
    /* Rows are most urgent first: Q1, Q2, Q3, Q7, then Q4, Q6, Q5. */
    view_questions_key(&g_s, SLOTH_KEY_DOWN);
    view_questions_key(&g_s, SLOTH_KEY_DOWN);
    view_questions_key(&g_s, SLOTH_KEY_DOWN);
    ASSERT_EQ(view_questions_sel(), 3);
    render();
    ASSERT_SCREEN_HAS(" Q7: Is the sensor able to see what it must see?");
    for (int i = 0; i < 10; i++) view_questions_key(&g_s, SLOTH_KEY_DOWN);
    ASSERT_EQ(view_questions_sel(), 6);
    render();
    ASSERT_SCREEN_HAS(" Q5: Is my site revealing information?");
    for (int i = 0; i < 10; i++) view_questions_key(&g_s, SLOTH_KEY_UP);
    ASSERT_EQ(view_questions_sel(), 0);
    ASSERT_EQ(view_for_key('!'), (int)VIEW_QUESTIONS);
}

void run_questions_view_tests(void) {
    TEST_SUITE("questions view (#244)");
    RUN_TEST(test_empty_state);
    RUN_TEST(test_populated_and_nav);
}
