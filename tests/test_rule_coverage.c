#include <string.h>
#include "runner.h"
#include "rule_coverage.h"

/*
 * Coverage assessment (#242): the per-kind input declarations
 * (include/sloth_alert_inputs.def) and the status cov_rule_status()
 * derives from them. Expectations are written out from the rule
 * functions under src/alerts/ and the trigger column of
 * docs/views/alerts.md, not read back from the table.
 */

/* A sensor with everything: every input up, one radio per channel,
 * every band, every piece of operator configuration. */
static cov_env_t env_full(void) {
    cov_env_t e;
    memset(&e, 0, sizeof(e));
    for (int i = 0; i < COV_IN_COUNT; i++) e.input[i] = COV_AV_UP;
    e.bands = COV_B_ALL;
    e.radios = 3;
    e.channels = 3;
    e.hopping = 1;
    e.config = COV_N_ALL;
    return e;
}

static const char *const k_alert_ids[] = {
#define X(id, technique) #id,
#include "sloth_alerts.def"
#undef X
};
static const char *const k_input_ids[] = {
#define X(id, in, frames, bands, shape, needs) #id,
#include "sloth_alert_inputs.def"
#undef X
};

static void test_def_matches_alert_list(void) {
    /* Same kinds, same order: a kind appended to sloth_alerts.def with
     * no declaration, or a declaration under a misspelt name, is red
     * here before it is a zero-filled row that reads "dot11, no
     * frames". */
    int na = (int)(sizeof(k_alert_ids) / sizeof(*k_alert_ids));
    int ni = (int)(sizeof(k_input_ids) / sizeof(*k_input_ids));
    ASSERT_EQ(na, (int)ALERT_TYPE_COUNT);
    ASSERT_EQ(ni, na);
    for (int i = 0; i < na && i < ni; i++)
        ASSERT_STR(k_input_ids[i], k_alert_ids[i]);
}

static void test_every_declaration_is_well_formed(void) {
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        const cov_inputs_t *d = cov_inputs((alert_type_t)t);
        ASSERT(d != NULL);
        if (!d) continue;
        ASSERT((int)d->input >= 0 && d->input < COV_IN_COUNT);
        ASSERT_EQ(d->frames & ~COV_F_ALL, 0u);
        ASSERT_EQ(d->bands & ~COV_B_ALL, 0u);
        ASSERT_EQ(d->needs & ~COV_N_ALL, 0u);
        if (d->input == COV_IN_DOT11) {
            /* An 802.11 rule says which frames and what shape. */
            ASSERT(d->frames != 0);
            ASSERT(d->shape != COV_SHAPE_NA);
        } else {
            ASSERT_EQ(d->frames, 0u);
            ASSERT_EQ(d->bands, COV_B_ANY);
            ASSERT_EQ((int)d->shape, (int)COV_SHAPE_NA);
        }
    }
    ASSERT(cov_inputs(ALERT_TYPE_COUNT) == NULL);
    ASSERT(cov_inputs((alert_type_t)-1) == NULL);
}

static int count_input(cov_input_t in) {
    int n = 0;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++)
        if (cov_inputs((alert_type_t)t)->input == in) n++;
    return n;
}

static void test_input_census(void) {
    /* How many kinds read each input. Pinned so that moving a kind from
     * one input to another is a deliberate edit of two files; the
     * figures are counted from the rule files, by the state each rule
     * function reads. */
    ASSERT_EQ(count_input(COV_IN_DOT11), 58);
    ASSERT_EQ(count_input(COV_IN_IP), 26);
    ASSERT_EQ(count_input(COV_IN_HOST), 5);
    ASSERT_EQ(count_input(COV_IN_BLE_ADV), 3);
    ASSERT_EQ(count_input(COV_IN_BLE_HCI), 1);
    ASSERT_EQ(count_input(COV_IN_GNSS), 4);
    ASSERT_EQ(count_input(COV_IN_ADSB), 1);
    ASSERT_EQ(count_input(COV_IN_SYS), 3);
}

static void test_named_declarations(void) {
    /* One of each kind of row, from its rule. */
    const cov_inputs_t *d;

    /* rule_handshake_harvest: deauthentications, then the 4-way
     * handshake that follows them. */
    d = cov_inputs(ALERT_TYPE_HANDSHAKE_HARVEST);
    ASSERT_EQ((int)d->input, (int)COV_IN_DOT11);
    ASSERT_EQ(d->frames, COV_F_DEAUTH | COV_F_EAPOL);
    ASSERT_EQ((int)d->shape, (int)COV_SHAPE_EXCHANGE);

    /* rule_evil_twin reads s->beacon_aps. */
    d = cov_inputs(ALERT_TYPE_EVIL_TWIN);
    ASSERT_EQ(d->frames, COV_F_BEACON);
    ASSERT_EQ((int)d->shape, (int)COV_SHAPE_STATE);

    /* rule_dfs_masking: first heard on channels 52-64 or 100-144. */
    d = cov_inputs(ALERT_TYPE_DFS_MASKING);
    ASSERT_EQ(d->bands, COV_B_5DFS);
    /* rule_country_absent: any 5 GHz AP, on a DFS channel or not. */
    ASSERT_EQ(cov_inputs(ALERT_TYPE_COUNTRY_ABSENT)->bands, COV_B_5 | COV_B_5DFS);
    ASSERT_EQ(cov_inputs(ALERT_TYPE_TPC_ABSENT_HIGH_BAND)->bands, COV_B_5 | COV_B_5DFS);

    /* rule_unknown_device: "Requires both" a designation and a roster. */
    d = cov_inputs(ALERT_TYPE_UNKNOWN_DEVICE);
    ASSERT_EQ(d->needs, COV_N_OWN_NET | COV_N_ROSTER);

    /* rule_sae_psk_regression reads db_akm_regressions(). */
    ASSERT_EQ(cov_inputs(ALERT_TYPE_SAE_PSK_REGRESSION)->needs, COV_N_DB);

    /* rule_port_scan and rule_threat_ip read s->conns, the host's own
     * socket table, not the capture. */
    ASSERT_EQ((int)cov_inputs(ALERT_TYPE_PORT_SCAN)->input, (int)COV_IN_HOST);
    ASSERT_EQ((int)cov_inputs(ALERT_TYPE_THREAT_IP)->input, (int)COV_IN_HOST);
    ASSERT_EQ((int)cov_inputs(ALERT_TYPE_THREAT_DOMAIN)->input, (int)COV_IN_IP);

    /* The HCI commands exist on the monitor channel only; an Ubertooth
     * stream carries advertising and no host command. */
    ASSERT_EQ((int)cov_inputs(ALERT_TYPE_BT_OWN_TRANSMIT)->input, (int)COV_IN_BLE_HCI);
    ASSERT_EQ((int)cov_inputs(ALERT_TYPE_BLE_WATCHLIST)->input, (int)COV_IN_BLE_ADV);
}

static void test_rf_daemon_kinds(void) {
    /* sloth-rf's table (src/alerts/rules_table_rf.c) raises exactly
     * these beside SENSOR_SOURCE_DOWN, and they are the only kinds that
     * read the GNSS receiver or the ADS-B decoder. */
    static const alert_type_t rf[] = {
        ALERT_TYPE_GNSS_JAMMING, ALERT_TYPE_GNSS_TIME_JUMP,
        ALERT_TYPE_GNSS_POSITION_JUMP, ALERT_TYPE_GNSS_SPOOF_SUSPECT,
        ALERT_TYPE_ADSB_EMERGENCY,
    };
    int n = 0;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        cov_input_t in = cov_inputs((alert_type_t)t)->input;
        if (in != COV_IN_GNSS && in != COV_IN_ADSB) continue;
        n++;
        int listed = 0;
        for (size_t i = 0; i < sizeof(rf) / sizeof(*rf); i++)
            if (rf[i] == (alert_type_t)t) listed = 1;
        ASSERT(listed);
    }
    ASSERT_EQ(n, (int)(sizeof(rf) / sizeof(*rf)));
}

static void test_daemon_split(void) {
    /* The counts docs-counts prints from the two rule tables: 96 kinds
     * in sloth-wifi's, 6 in sloth-rf's, SENSOR_SOURCE_DOWN in both. */
    int wifi = 0, rf = 0, both = 0;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        int w = cov_daemon_raises(COV_DAEMON_WIFI, (alert_type_t)t);
        int r = cov_daemon_raises(COV_DAEMON_RF, (alert_type_t)t);
        ASSERT(w || r);
        wifi += w; rf += r;
        if (w && r) { both++; ASSERT_EQ(t, (int)ALERT_TYPE_SENSOR_SOURCE_DOWN); }
    }
    ASSERT_EQ(wifi, 96);
    ASSERT_EQ(rf, 6);
    ASSERT_EQ(both, 1);
    /* The host has one supply; the daemon with the capture reports it. */
    ASSERT_EQ(cov_daemon_raises(COV_DAEMON_RF, ALERT_TYPE_SENSOR_UNDERVOLT), 0);
    ASSERT_EQ(cov_daemon_raises(COV_DAEMON_WIFI, ALERT_TYPE_COUNT), 0);
}

static void test_full_sensor_sees_everything(void) {
    cov_env_t e = env_full();
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        cov_reason_t why = COV_R_HOP;
        ASSERT_EQ((int)cov_rule_status((alert_type_t)t, &e, &why), (int)COV_OBSERVABLE);
        ASSERT_EQ((int)why, (int)COV_R_NONE);
    }
}

static void test_no_monitor_radio_blinds_every_wifi_rule(void) {
    /* Acceptance 1 of #242: with no monitor radio, each Wi-Fi rule
     * reads blind with the reason; nothing else changes. */
    cov_env_t e = env_full();
    e.input[COV_IN_DOT11] = COV_AV_NONE;
    e.radios = 0; e.channels = 0; e.bands = 0; e.hopping = 0;
    int wifi = 0, other = 0;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        cov_reason_t why = COV_R_NONE;
        cov_status_t st = cov_rule_status((alert_type_t)t, &e, &why);
        if (cov_inputs((alert_type_t)t)->input == COV_IN_DOT11) {
            wifi++;
            ASSERT_EQ((int)st, (int)COV_BLIND);
            ASSERT_EQ((int)why, (int)COV_R_NO_SOURCE);
        } else {
            other++;
            ASSERT_EQ((int)st, (int)COV_OBSERVABLE);
        }
    }
    ASSERT_EQ(wifi, 58);
    ASSERT_EQ(wifi + other, (int)ALERT_TYPE_COUNT);

    /* Configured and gone is a different word from never configured. */
    e.input[COV_IN_DOT11] = COV_AV_DOWN;
    cov_reason_t why = COV_R_NONE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_SOURCE_DOWN);
}

static void test_hop_makes_an_exchange_partly(void) {
    /* Acceptance 2 of #242: one radio hopping 3 of the 14 2.4 GHz
     * channels. A rule that needs a whole handshake is partly; a rule
     * that reads a beacon's content is not affected. */
    cov_env_t e = env_full();
    e.radios = 1; e.channels = 3; e.hopping = 1; e.bands = COV_B_24;
    cov_reason_t why = COV_R_NONE;

    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_HANDSHAKE_HARVEST, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_HOP);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_DEAUTH_FLOOD, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_HOP);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_UNKNOWN_DEVICE, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_HOP);

    why = COV_R_HOP;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_OBSERVABLE);
    ASSERT_EQ((int)why, (int)COV_R_NONE);

    /* Three radios for the three channels: nothing is left. */
    e.radios = 3;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_HANDSHAKE_HARVEST, &e, &why), (int)COV_OBSERVABLE);

    /* Hop does not reach a rule that reads no radio. */
    e.radios = 1;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_THREAT_DOMAIN, &e, &why), (int)COV_OBSERVABLE);
}

static void test_fixed_channel_is_partly_for_every_wifi_rule(void) {
    cov_env_t e = env_full();
    e.hopping = 0; e.radios = 1; e.channels = 1; e.bands = COV_B_24;
    cov_reason_t why = COV_R_NONE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_FIXED_CHANNEL);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_HANDSHAKE_HARVEST, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_FIXED_CHANNEL);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_BLE_ADV_FLOOD, &e, &why), (int)COV_OBSERVABLE);
}

static void test_band(void) {
    /* The default --hop list (1 6 11 36-48 149-161) has no DFS channel:
     * DFS_MASKING cannot fire under it, and the 5 GHz posture rules
     * can. */
    cov_env_t e = env_full();
    e.radios = 1; e.channels = 11; e.bands = COV_B_24 | COV_B_5;
    cov_reason_t why = COV_R_NONE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_DFS_MASKING, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_BAND);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_COUNTRY_ABSENT, &e, &why), (int)COV_OBSERVABLE);

    e.bands = COV_B_24;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_COUNTRY_ABSENT, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_BAND);
    /* A rule about every band is not judged by band. */
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_OBSERVABLE);

    /* Bands not known yet (no frame, no plan): no claim either way. */
    e.bands = 0;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_DFS_MASKING, &e, &why), (int)COV_OBSERVABLE);
}

static void test_needs(void) {
    cov_env_t e = env_full();
    cov_reason_t why = COV_R_NONE;

    e.config = 0;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_MY_NETWORK_RECON, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_NO_OWN_NET);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_UNKNOWN_DEVICE, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_NO_OWN_NET);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_SAE_PSK_REGRESSION, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_NO_DB);
    /* A rule with no need is untouched. */
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_OBSERVABLE);

    e.config = COV_N_OWN_NET;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_MY_NETWORK_RECON, &e, &why), (int)COV_OBSERVABLE);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_UNKNOWN_DEVICE, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_NO_ROSTER);

    e.config = COV_N_OWN_NET | COV_N_ROSTER;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_UNKNOWN_DEVICE, &e, &why), (int)COV_OBSERVABLE);
}

static void test_reason_precedence(void) {
    /* The first thing to fix is the one named: a missing source before
     * missing configuration, blind before partly. */
    cov_env_t e = env_full();
    cov_reason_t why = COV_R_NONE;

    e.config = 0;
    e.input[COV_IN_DOT11] = COV_AV_NONE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_UNKNOWN_DEVICE, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_NO_SOURCE);

    e = env_full();
    e.input[COV_IN_DOT11] = COV_AV_STALE;
    e.bands = COV_B_24;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_DFS_MASKING, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_BAND);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_SOURCE_STALE);

    /* Stale reaches the other inputs too. */
    e = env_full();
    e.input[COV_IN_GNSS] = COV_AV_STALE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_GNSS_JAMMING, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_SOURCE_STALE);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_ADSB_EMERGENCY, &e, &why), (int)COV_OBSERVABLE);

    /* btmon gone, btcap up: advertising still arrives, the host
     * controller's commands do not. */
    e = env_full();
    e.input[COV_IN_BLE_HCI] = COV_AV_NONE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_BT_OWN_TRANSMIT, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_BLE_ADV_FLOOD, &e, &why), (int)COV_OBSERVABLE);
}

static void test_suppressed(void) {
    /* #242 item 4: what SENSOR_SUPPRESSED holds open reads `partly`,
     * `suppressed`, on the inputs and frame classes it names and
     * nowhere else. */
    cov_env_t e = env_full();
    cov_reason_t why = COV_R_NONE;

    /* An input's bit: every kind on it, none on another. */
    e.suppressed = 1u << COV_IN_DOT11;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_SUPPRESSED);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_HANDSHAKE_HARVEST, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_SUPPRESSED);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_THREAT_DOMAIN, &e, &why), (int)COV_OBSERVABLE);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_BLE_ADV_FLOOD, &e, &why), (int)COV_OBSERVABLE);
    /* The own-state kinds read the sampler, which nothing suppresses. */
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_SENSOR_SUPPRESSED, &e, &why), (int)COV_OBSERVABLE);

    e.suppressed = 1u << COV_IN_IP;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_THREAT_DOMAIN, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_SUPPRESSED);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_OBSERVABLE);

    /* A frame class: the 802.11 kinds whose evidence includes it.
     * PROBE_FLOOD reads probe requests, EVIL_TWIN beacons only,
     * HANDSHAKE_HARVEST deauths and EAPOL. A frame mask reaches no
     * kind of another input. */
    e = env_full();
    e.suppressed_frames = COV_F_PROBE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_PROBE_FLOOD, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_SUPPRESSED);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_OBSERVABLE);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_HANDSHAKE_HARVEST, &e, &why), (int)COV_OBSERVABLE);
    e.suppressed_frames = COV_F_ALL;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_THREAT_DOMAIN, &e, &why), (int)COV_OBSERVABLE);
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_BLE_ADV_FLOOD, &e, &why), (int)COV_OBSERVABLE);

    /* Precedence: blind first, then stale, then suppressed, then what
     * the radio plan costs. */
    e = env_full();
    e.suppressed = 1u << COV_IN_DOT11;
    e.bands = COV_B_24;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_DFS_MASKING, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_BAND);
    e.input[COV_IN_DOT11] = COV_AV_STALE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_SOURCE_STALE);
    e.input[COV_IN_DOT11] = COV_AV_UP;
    e.hopping = 0;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_SUPPRESSED);
    e.hopping = 1; e.radios = 1; e.channels = 11;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_HANDSHAKE_HARVEST, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_SUPPRESSED);
    e.suppressed = 0;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_HANDSHAKE_HARVEST, &e, &why), (int)COV_PARTLY);
    ASSERT_EQ((int)why, (int)COV_R_HOP);
    ASSERT_STR(cov_reason_name(COV_R_SUPPRESSED), "suppressed");
}

static void test_refuses_bad_arguments(void) {
    cov_env_t e = env_full();
    cov_reason_t why = COV_R_NONE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_COUNT, &e, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_NO_SOURCE);
    why = COV_R_NONE;
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, NULL, &why), (int)COV_BLIND);
    ASSERT_EQ((int)why, (int)COV_R_NO_SOURCE);
    /* `why` is optional. */
    ASSERT_EQ((int)cov_rule_status(ALERT_TYPE_EVIL_TWIN, &e, NULL), (int)COV_OBSERVABLE);
}

static void test_names(void) {
    /* Every word that reaches the stream exists and is its own. */
    for (int i = 0; i < COV_IN_COUNT; i++) {
        ASSERT(cov_input_name((cov_input_t)i)[0] != '\0');
        for (int j = 0; j < i; j++)
            ASSERT(strcmp(cov_input_name((cov_input_t)i), cov_input_name((cov_input_t)j)) != 0);
    }
    ASSERT_STR(cov_input_name(COV_IN_COUNT), "");
    ASSERT_STR(cov_reason_name(COV_R_NONE), "");
    for (int i = 1; i < COV_R_COUNT; i++) {
        ASSERT(cov_reason_name((cov_reason_t)i)[0] != '\0');
        for (int j = 1; j < i; j++)
            ASSERT(strcmp(cov_reason_name((cov_reason_t)i), cov_reason_name((cov_reason_t)j)) != 0);
    }
    ASSERT_STR(cov_reason_name(COV_R_COUNT), "");
    ASSERT_STR(cov_status_name(COV_BLIND), "blind");
    ASSERT_STR(cov_status_name(COV_PARTLY), "partly");
    ASSERT_STR(cov_status_name(COV_OBSERVABLE), "observable");
    ASSERT_STR(cov_shape_name(COV_SHAPE_NA), "");
    ASSERT_STR(cov_shape_name(COV_SHAPE_EXCHANGE), "exchange");
}

static void test_mask_strings(void) {
    char b[64];
    ASSERT_EQ(cov_frames_str(0, b, sizeof(b)), 0);
    ASSERT_STR(b, "");
    cov_frames_str(COV_F_DEAUTH | COV_F_EAPOL, b, sizeof(b));
    ASSERT_STR(b, "deauth,eapol");
    ASSERT_EQ(cov_frames_str(COV_F_ALL, b, sizeof(b)),
              (int)strlen("beacon,probe,auth,assoc,deauth,action,ctrl,data,eapol"));
    cov_bands_str(COV_B_5 | COV_B_5DFS, b, sizeof(b));
    ASSERT_STR(b, "5,5dfs");
    cov_needs_str(COV_N_OWN_NET | COV_N_ROSTER, b, sizeof(b));
    ASSERT_STR(b, "own_net,roster");

    /* A short buffer is terminated inside its size. */
    char s[8];
    memset(s, 'x', sizeof(s));
    int n = cov_frames_str(COV_F_ALL, s, sizeof(s));
    ASSERT(n <= 7);
    ASSERT_EQ((int)strlen(s), n);
    ASSERT_EQ(cov_frames_str(COV_F_ALL, NULL, 8), 0);
    ASSERT_EQ(cov_frames_str(COV_F_ALL, s, 0), 0);
}

static void test_band_of_mhz(void) {
    /* Centre frequencies, 5000 + 5 * channel in 5 GHz. */
    ASSERT_EQ(cov_band_of_mhz(2412), COV_B_24);   /* ch 1 */
    ASSERT_EQ(cov_band_of_mhz(2484), COV_B_24);   /* ch 14 */
    ASSERT_EQ(cov_band_of_mhz(5180), COV_B_5);    /* ch 36 */
    ASSERT_EQ(cov_band_of_mhz(5240), COV_B_5);    /* ch 48 */
    ASSERT_EQ(cov_band_of_mhz(5260), COV_B_5DFS); /* ch 52 */
    ASSERT_EQ(cov_band_of_mhz(5320), COV_B_5DFS); /* ch 64 */
    ASSERT_EQ(cov_band_of_mhz(5500), COV_B_5DFS); /* ch 100 */
    ASSERT_EQ(cov_band_of_mhz(5720), COV_B_5DFS); /* ch 144 */
    ASSERT_EQ(cov_band_of_mhz(5745), COV_B_5);    /* ch 149 */
    ASSERT_EQ(cov_band_of_mhz(5825), COV_B_5);    /* ch 165 */
    ASSERT_EQ(cov_band_of_mhz(5955), COV_B_6);    /* 6 GHz ch 1 */
    ASSERT_EQ(cov_band_of_mhz(7115), COV_B_6);    /* 6 GHz ch 233 */
    ASSERT_EQ(cov_band_of_mhz(0), 0u);
    ASSERT_EQ(cov_band_of_mhz(915), 0u);
    ASSERT_EQ(cov_band_of_mhz(5900), 0u);
}

void run_rule_coverage_tests(void) {
    TEST_SUITE("coverage assessment (#242)");
    RUN_TEST(test_def_matches_alert_list);
    RUN_TEST(test_every_declaration_is_well_formed);
    RUN_TEST(test_input_census);
    RUN_TEST(test_named_declarations);
    RUN_TEST(test_rf_daemon_kinds);
    RUN_TEST(test_daemon_split);
    RUN_TEST(test_full_sensor_sees_everything);
    RUN_TEST(test_no_monitor_radio_blinds_every_wifi_rule);
    RUN_TEST(test_hop_makes_an_exchange_partly);
    RUN_TEST(test_fixed_channel_is_partly_for_every_wifi_rule);
    RUN_TEST(test_band);
    RUN_TEST(test_needs);
    RUN_TEST(test_reason_precedence);
    RUN_TEST(test_suppressed);
    RUN_TEST(test_refuses_bad_arguments);
    RUN_TEST(test_names);
    RUN_TEST(test_mask_strings);
    RUN_TEST(test_band_of_mhz);
}
