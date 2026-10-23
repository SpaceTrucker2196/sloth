/* What slothweb repeats of sloth's own tables (#163, M5), held to
 * sloth's: the AKM suite names (src/rsn_ie.c rsn_akm_name(), linked
 * into slothweb_test alone), the downgrade bits (include/sloth.h
 * WPA_DG_*) and DEAUTH_FLOOD's alert type (include/sloth_alerts.def).
 * slothweb compiles no src/ file; this suite is where the copies are
 * kept honest. Its own file, because it is the one place web/ includes
 * sloth.h. */
#include <stdint.h>
#include <string.h>

#include "sloth.h"
#include "web_slothdb.h"
#include "web_wifi.h"
#include "wtest.h"

const char *rsn_akm_name(uint8_t t);

/* Seen red with web_akm_name(19) answering "?". */
static void test_akm_names_are_sloths(void) {
    for (int t = 0; t < 32; t++) {
        const char *a = web_akm_name(t), *b = rsn_akm_name((uint8_t)t);
        if (strcmp(a, b)) fprintf(stderr, "    AKM %d: %s, sloth %s\n", t, a, b);
        WT_ASSERT(!strcmp(a, b));
    }
}

static void test_downgrade_bits_are_sloths(void) {
    static const struct { int bit; const char *word; } D[] = {
        { WPA_DG_TRANSITION_SAE_PSK, "SAE/PSK" }, { WPA_DG_OWE_TRANSITION, "OWE" },
        { WPA_DG_MFP_OPTIONAL, "MFP" }, { WPA_DG_WPA1_ALONGSIDE, "WPA1" },
    };
    for (size_t i = 0; i < sizeof(D) / sizeof(D[0]); i++) {
        int b = 0;
        while (b < 8 && D[i].bit != (1 << b)) b++;
        WT_ASSERT(b < 8);
        const char *nm = web_downgrade_name(b);
        WT_ASSERT(nm && strstr(nm, D[i].word));
    }
    WT_ASSERT(web_downgrade_name(4) == NULL);
    WT_EQ(WEB_ALERT_DEAUTH_FLOOD, ALERT_TYPE_DEAUTH_FLOOD);
}

void run_parity_tests(void) {
    WT_RUN(test_akm_names_are_sloths);
    WT_RUN(test_downgrade_bits_are_sloths);
}
