#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "probe_pnl.h"
#include "sensor_health.h"
#include "bytes.h"
#include "dot11_ie.h"

static pnl_client_t    g_tbl[MAX_PNL_CLIENTS];
static int             g_n   = 0;
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

/* Strong-signal OS fingerprint from probe-request vendor IEs. Returns
 * a stable string (caller does not own it) or NULL. The matches are
 * conservative — only return a label when a single vendor IE points
 * at a specific OS / platform. Anything else stays empty so the view
 * doesn't lie.
 *
 * The OUI → vendor map is dot11_oui_vendor() (#127); what a vendor's
 * IE implies about the client OS is this function's own knowledge. */
const char *probe_pnl_fingerprint_ies(const uint8_t *ies, int ielen)
{
    if (!ies || ielen < 2) return NULL;
    const char *guess = NULL;
    tlv_it_t it;
    uint16_t tag; int len; const uint8_t *body;
    tlv_init(&it, ies, ielen);
    while (tlv_next(&it, &tag, &len, &body) == TLV_OK) {
        if (tag != 221 || len < 4) continue;
        const char *v  = dot11_oui_vendor(body);
        uint8_t     ty = body[3];
        if (!v) continue;
        /* Apple — strongest signal we have. */
        if (strcmp(v, "Apple") == 0) { guess = "Apple"; break; }
        /* Microsoft Provisioning IE (type 8). The other MS sub-types
         * (1=WPA, 2=WMM, 4=WPS) are emitted by everyone — only type 8
         * indicates Windows. */
        if (strcmp(v, "Microsoft") == 0 && ty == 0x08) {
            guess = "Windows";
            break;
        }
        /* Espressif silicon (ESP32 / ESP8266). */
        if (strcmp(v, "Espressif") == 0) { guess = "ESP32"; break; }
        /* Wi-Fi Alliance — P2P / Wi-Fi Direct IEs. Mostly Android
         * devices include this; a later Apple/MS IE would override. */
        if (strcmp(v, "Wi-Fi Alliance") == 0 && !guess) guess = "Android";
    }
    /* An early break on a decisive vendor IE leaves the walk unfinished
     * but not faulted; only a stop on a bad element is counted. */
    if (it.status == TLV_OVERRUN) sh_parse_fault_note(SH_PF_IE_OVERRUN);
    return guess;
}

/* Max PHY tier from the capability elements. The classifier is
 * dot11_ie_phy() (#127), shared with beacon_parse_ies(); this wrapper
 * keeps the NULL-for-no-elements contract the PNL view relies on.
 *
 * Until #127 this file read Element ID Extension 81 as Multi-Link and
 * did not look at 106 or 107; Multi-Link is 107 (mle.h, IEEE 802.11be),
 * so a client advertising only a Multi-Link element was not Wi-Fi 7
 * here while it was in the beacon path. */
const char *probe_pnl_phy_ies(const uint8_t *ies, int ielen)
{
    if (!ies || ielen < 2) return NULL;
    dot11_phy_t p;
    dot11_ie_phy(ies, ielen, &p);
    return dot11_phy_tier(&p);
}

/* Rank PHY tiers so we can upgrade-only on observe(). */
static int phy_rank(const char *p) {
    if (!p || !p[0])              return 0;
    if (strcmp(p, "legacy") == 0) return 1;
    if (strcmp(p, "Wi-Fi 4") == 0) return 2;
    if (strcmp(p, "Wi-Fi 5") == 0) return 3;
    if (strcmp(p, "Wi-Fi 6") == 0) return 4;
    if (strcmp(p, "Wi-Fi 7") == 0) return 5;
    return 0;
}

int probe_pnl_note_assoc_phy(const uint8_t mac[6], const char *phy) {
    if (!phy || !phy[0]) return 0;
    int hit = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_n; i++) {
        if (!mac_eq(g_tbl[i].mac, mac)) continue;
        if (phy_rank(phy) > phy_rank(g_tbl[i].phy))
            snprintf(g_tbl[i].phy, sizeof(g_tbl[i].phy), "%s", phy);
        /* Confirmed even when the tier does not move: the point is that
         * an association request corroborated it, not that it improved. */
        g_tbl[i].phy_confirmed = 1;
        hit = 1;
        break;
    }
    pthread_mutex_unlock(&g_mu);
    return hit;
}

void probe_pnl_observe(const uint8_t mac[6], const char *ssid,
                        const char *os_fp, const char *phy)
{
    if (!ssid || !ssid[0]) return;   /* wildcard probes carry no PNL info */
    time_t now = time(NULL);

    pthread_mutex_lock(&g_mu);

    /* Find or insert the client. */
    int idx = -1;
    for (int i = 0; i < g_n; i++) {
        if (mac_eq(g_tbl[i].mac, mac)) { idx = i; break; }
    }
    if (idx < 0) {
        if (g_n >= MAX_PNL_CLIENTS) {
            /* Evict the entry with the lowest last_seen — keeps the most
             * recently active devices. */
            idx = 0;
            for (int i = 1; i < g_n; i++)
                if (g_tbl[i].last_seen < g_tbl[idx].last_seen) idx = i;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
            sh_evict_note(SH_EVICT_PNL_CLIENT);   /* #91 slice 3 */
        } else {
            idx = g_n++;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        }
        memcpy(g_tbl[idx].mac, mac, 6);
        g_tbl[idx].mac_random = (mac[0] & 0x02) ? 1 : 0;
        g_tbl[idx].first_seen = now;
    }
    g_tbl[idx].last_seen = now;
    g_tbl[idx].probe_count++;
    /* Sticky OS fingerprint: first strong signal wins. Weaker later
     * probes don't overwrite. */
    if (os_fp && os_fp[0] && !g_tbl[idx].os_fp[0])
        snprintf(g_tbl[idx].os_fp, sizeof(g_tbl[idx].os_fp), "%s", os_fp);
    /* PHY tier: upgrade-only. A device might send a stripped-down
     * probe variant later that omits VHT/HE — keep the strongest
     * tier we've ever seen for it. */
    if (phy && phy[0] && phy_rank(phy) > phy_rank(g_tbl[idx].phy))
        snprintf(g_tbl[idx].phy, sizeof(g_tbl[idx].phy), "%s", phy);

    /* Dedupe — skip if this SSID is already in this client's list. */
    for (int j = 0; j < g_tbl[idx].ssid_count; j++) {
        if (strncmp(g_tbl[idx].ssids[j], ssid, 32) == 0) {
            pthread_mutex_unlock(&g_mu);
            return;
        }
    }
    /* Append. When the per-client list is full, evict the first entry
     * (oldest in insertion order) and shift down. Bounded at 16. */
    if (g_tbl[idx].ssid_count >= MAX_PNL_SSIDS_PER_CLI) {
        for (int j = 1; j < MAX_PNL_SSIDS_PER_CLI; j++)
            memcpy(g_tbl[idx].ssids[j - 1], g_tbl[idx].ssids[j], 33);
        g_tbl[idx].ssid_count = MAX_PNL_SSIDS_PER_CLI - 1;
        sh_evict_note(SH_EVICT_PNL_SSID);   /* #91 slice 3 */
    }
    int s = g_tbl[idx].ssid_count++;
    snprintf(g_tbl[idx].ssids[s], 33, "%s", ssid);

    pthread_mutex_unlock(&g_mu);
}

void probe_pnl_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_PNL_CLIENTS ? g_n : MAX_PNL_CLIENTS;
    /* Copy sorted by last_seen DESC so newest activity is at top. */
    int order[MAX_PNL_CLIENTS];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (g_tbl[order[j]].last_seen > g_tbl[order[best]].last_seen)
                best = j;
        if (best != i) { int t = order[i]; order[i] = order[best]; order[best] = t; }
    }
    for (int i = 0; i < n; i++) s->pnl_clients[i] = g_tbl[order[i]];
    s->pnl_count = n;
    if (s->pnl_sel >= n && n > 0) s->pnl_sel = n - 1;
    pthread_mutex_unlock(&g_mu);
}

void probe_pnl_clear(void)
{
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}

int probe_pnl_count(void)
{
    pthread_mutex_lock(&g_mu);
    int n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int probe_pnl_ssid_count(const uint8_t mac[6])
{
    pthread_mutex_lock(&g_mu);
    int out = 0;
    for (int i = 0; i < g_n; i++) {
        if (mac_eq(g_tbl[i].mac, mac)) { out = g_tbl[i].ssid_count; break; }
    }
    pthread_mutex_unlock(&g_mu);
    return out;
}
