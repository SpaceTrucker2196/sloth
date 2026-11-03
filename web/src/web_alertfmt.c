#include "web_alertfmt.h"

#include <string.h>

#include "web_alertkb.h"

/* The audited types (web_alertfmt.h). A type is added here only after
 * reading every fire() site's detail format in src/alerts/; the test
 * re-reads them on every run. Types left off are withheld, which is the
 * safe answer for one nobody audited. */
const web_adf_t web_alert_detail_audited[] = {
    { "PORT_SCAN", "", "" },
    { "DEAUTH_FLOOD", "rsn",
      "rsn is snprintf'd from the reason code (%u) or one of the literals"
      " \"encrypted\" / \"unknown\" just above the detail" },
    { "NXDOMAIN_BURST", "", "" },
    { "BEACONING", "d sep",
      "d is beacon_dest()'s address:port of one track, sep the literal"
      " \", \" or \" \"" },
    { "ARP_SPOOF", "", "" },
    { "ROGUE_DHCP", "", "" },
    { "ROGUE_RA", "", "" },
    { "SMB1_USE", "cb", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h)" },
    { "KERB_PREAUTH_BURST", "", "" },
    { "LDAP_SEARCH_FLOOD", "", "" },
    { "BGP_NOTIFICATION_BURST", "", "" },
    { "EVIL_TWIN_PROXIMITY", "", "" },
    { "PROBE_FLOOD", "", "" },
    { "NO_MONITOR_MODE", "", "" },
    { "BEACON_FLOOD", "", "" },
    { "AUTH_FLOOD", "", "" },
    { "MGMT_FUZZ", "kinds band",
      "kinds is joined from the literals \"IE overrun\", \"oversize SSID\" and \"truncated RSN\" with \", \";"
      " band is mgmt_fuzz_rate_band()'s literal (\"under 1\", \"1-9\", \"10-49\", \"50 or more\")" },
    { "ICMP_TUNNEL", "", "" },
    { "RECURRING_TRANSIT", "", "" },
    { "UNKNOWN_DEVICE", "", "" },
    { "RF_DEGRADED", "", "" },
    { "ASSOC_FLOOD", "", "" },
    { "PEAP_NO_SERVER_CERT", "", "" },
    { "CSA_ABUSE", "", "" },
    { "RRM_SURVEY_ABUSE", "", "" },
    { "RTS_FLOOD", "", "" },
    { "BLOCKACK_ATTACK", "", "" },
    { "FRAG_PLAINTEXT", "cb sib", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h); sib is frag_sibling_note()'s text: empty, or the literal \"; N more withheld as the AP MLD (mld-sibling heuristic)\" with N a %u (src/fragattack.c)" },
    { "FRAG_BCAST", "cb sib", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h); sib is frag_sibling_note()'s text: empty, or the literal \"; N more withheld as the AP MLD (mld-sibling heuristic)\" with N a %u (src/fragattack.c)" },
    { "FRAG_CACHE", "cb sib", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h); sib is frag_sibling_note()'s text: empty, or the literal \"; N more withheld as the AP MLD (mld-sibling heuristic)\" with N a %u (src/fragattack.c)" },
    { "FRAG_MIXED", "cb sib", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h); sib is frag_sibling_note()'s text: empty, or the literal \"; N more withheld as the AP MLD (mld-sibling heuristic)\" with N a %u (src/fragattack.c)" },
    { "SAE_PSK_SPLIT", "", "" },
    { "SAE_PSK_REGRESSION", "", "" },
    { "FRAG_AMSDU", "cb sib", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h); sib is frag_sibling_note()'s text: empty, or the literal \"; N more withheld as the AP MLD (mld-sibling heuristic)\" with N a %u (src/fragattack.c)" },
    { "FRAG_AMSDU_EAPOL", "cb sib", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h); sib is frag_sibling_note()'s text: empty, or the literal \"; N more withheld as the AP MLD (mld-sibling heuristic)\" with N a %u (src/fragattack.c)" },
    { "FRAG_MIXKEY", "cb sib", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h); sib is frag_sibling_note()'s text: empty, or the literal \"; N more withheld as the AP MLD (mld-sibling heuristic)\" with N a %u (src/fragattack.c)" },
    { "FRAG_PN_GAP", "cb sib", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h); sib is frag_sibling_note()'s text: empty, or the literal \"; N more withheld as the AP MLD (mld-sibling heuristic)\" with N a %u (src/fragattack.c)" },
    { "FRAG_EAPOL_RELAY", "cb sib", "cb is count_bucket()'s text of a frame count: its digits below ten, else its decade as \"10+\", \"100+\" (src/alerts/engine_internal.h); sib is frag_sibling_note()'s text: empty, or the literal \"; N more withheld as the AP MLD (mld-sibling heuristic)\" with N a %u (src/fragattack.c)" },
    { "SA_QUERY_FLOOD", "", "" },
    { "MFP_UNPROTECTED", "", "" },
    { "WPS_LOCKOUT_CYCLING", "", "" },
    { "WPS_PBC_RACE", "", "" },
    { "MLE_INVALID_LINK_ID", "", "" },
    { "MLE_COMMON_INFO_LEN_BAD", "", "" },
    { "MLE_SUBELEM_OVERRUN", "", "" },
    { "MLD_MAC_COLLISION", "", "" },
    { "PM_FORGE", "", "" },
    { "MLE_RECONFIG_NO_MLO", "", "" },
    { "WPS_PIXIE_PROBE", "", "" },
    { "WPS_PIXIE_LIKELY_SUCCESS", "", "" },
};
const size_t web_alert_detail_audited_n =
    sizeof(web_alert_detail_audited) / sizeof(web_alert_detail_audited[0]);

const char *const web_alert_fmt_names[] = {
    /* addresses */
    "ip", "src", "dst", "src_ip", "dst_ip", "client_ip", "server_ip",
    "peer_a", "peer_b", "remote_ip", "servers", "routers",
    /* MACs and BSSIDs, as mac_to_str() writes them */
    "mac", "mac_buf", "new_mac", "old_mac", "coll", "bssid", "bssid_str",
    "bss", "a_bssid", "b_bssid", "w_bssid", "s_bssid", "sta", "stastr",
    "psta", "tgt", "tx", "rx", "sa", "da", "ta",
    /* network names */
    "ssid", "last_ssid",
    NULL
};

const char *const web_alert_fmt_banned[] = {
    "user", "cred", "communit", "cookie", "pass", "identit", "secret",
    "token", "banner", "host", "qname", "path", "agent", "url", "uri",
    "sni", "query", "xaddr", "vendor", "label", "note", NULL
};

int web_alert_detail_ok(long long type) {
    const web_akb_t *k = web_akb_get(type);
    if (!k) return 0;
    for (size_t i = 0; i < web_alert_detail_audited_n; i++)
        if (!strcmp(web_alert_detail_audited[i].type, k->name)) return 1;
    return 0;
}

/* The verdict phrases (web_alertfmt.h), as src/alerts/rules_twin.c
 * writes them. No phrase of a type is a prefix of another at the same
 * position, so the first match is the only one. */
const web_ar_t web_alert_reasons[] = {
    { "EVIL_TWIN", "vendor OUI differs", WEB_AR_AFTER },
    { "EVIL_TWIN", "same vendor OUI", WEB_AR_AFTER },
    { "EVIL_TWIN", "vendor-IE fingerprint differs", WEB_AR_AFTER },
    { "EVIL_TWIN", "attacker-tool OUI present", WEB_AR_AFTER },
    { "EVIL_TWIN", "BSSID not in the approved inventory", WEB_AR_AFTER },
    { "EVIL_TWIN", "suspected impersonation", WEB_AR_BEFORE },
    { "EVIL_TWIN", "inventory-approved pair, weak/strong split", WEB_AR_BEFORE },
    { "EVIL_TWIN", "attack-in-progress", WEB_AR_LEAD },
    { "KARMA_AP", "candidate, uncorroborated", WEB_AR_TAIL },
};
const size_t web_alert_reasons_n = sizeof(web_alert_reasons) / sizeof(web_alert_reasons[0]);

/* At s[0..n): "conf ", one to three digits and '%'; the length, or 0. */
static size_t conf_at(const char *s, size_t n) {
    if (n < 7 || memcmp(s, "conf ", 5) != 0) return 0;
    size_t i = 5;
    while (i < n && i < 8 && s[i] >= '0' && s[i] <= '9') i++;
    if (i == 5 || i >= n || s[i] != '%') return 0;
    return i + 1;
}

static int starts(const char *s, size_t n, const char *w) {
    size_t k = strlen(w);
    return n >= k && memcmp(s, w, k) == 0;
}

int web_alert_reason_of(long long type, const char *detail, size_t n) {
    const web_akb_t *k = web_akb_get(type);
    if (!k || !detail) return 0;
    /* The rule's own text: what follows the last quote. */
    size_t at = 0, len = 0;
    for (; len < n && detail[len]; len++)
        if (detail[len] == '\'') at = len + 1;
    const char *t = detail + at;
    size_t tn = len - at, c = 0, cl = 0;
    /* Its last "conf N%". */
    for (size_t i = tn; i-- > 0;)
        if ((cl = conf_at(t + i, tn - i)) != 0) { c = i; break; }
    for (size_t r = 0; r < web_alert_reasons_n; r++) {
        const web_ar_t *a = &web_alert_reasons[r];
        if (strcmp(a->type, k->name) != 0) continue;
        size_t wl = strlen(a->word);
        if (a->pos == WEB_AR_LEAD) {
            if (!cl && tn > wl + 1 && t[0] == ' ' && memcmp(t + 1, a->word, wl) == 0 &&
                t[wl + 1] == ':')
                return (int)r + 1;
            continue;
        }
        if (!cl) continue;
        const char *e = t + c + cl;
        size_t en = tn - c - cl;
        if (a->pos == WEB_AR_AFTER) {
            if (starts(e, en, " - ") && starts(e + 3, en - 3, a->word) &&
                (en == 3 + wl || e[3 + wl] == ' '))
                return (int)r + 1;
        } else if (a->pos == WEB_AR_TAIL) {
            if (en == 3 + wl && starts(e, en, " - ") && memcmp(e + 3, a->word, wl) == 0)
                return (int)r + 1;
        } else if (a->pos == WEB_AR_BEFORE) {
            if (c >= wl + 5 && memcmp(t + c - 2, ", ", 2) == 0 &&
                memcmp(t + c - 2 - wl, a->word, wl) == 0 &&
                memcmp(t + c - 5 - wl, " - ", 3) == 0)
                return (int)r + 1;
        }
    }
    return 0;
}

const char *web_alert_reason_word(int r) {
    return r >= 1 && (size_t)r <= web_alert_reasons_n ? web_alert_reasons[r - 1].word : NULL;
}
