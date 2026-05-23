#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "probe_pnl.h"

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
 * doesn't lie. */
const char *probe_pnl_fingerprint_ies(const uint8_t *ies, int ielen)
{
    if (!ies || ielen < 2) return NULL;
    const uint8_t *p = ies;
    int rem = ielen;
    const char *guess = NULL;
    while (rem >= 2) {
        uint8_t tag = p[0];
        uint8_t len = p[1];
        if (2 + (int)len > rem) break;
        if (tag == 221 && len >= 4) {
            uint8_t o0 = p[2], o1 = p[3], o2 = p[4];
            uint8_t ty = (len >= 4) ? p[5] : 0;
            /* Apple — OUI 00:17:F2. Strongest signal we have. */
            if (o0 == 0x00 && o1 == 0x17 && o2 == 0xf2) {
                guess = "Apple";
                break;
            }
            /* Microsoft Provisioning IE (OUI 00:50:F2 type 8). The
             * other MS sub-types (1=WPA, 2=WMM, 4=WPS) are emitted by
             * everyone — only type 8 indicates Windows. */
            if (o0 == 0x00 && o1 == 0x50 && o2 == 0xf2 && ty == 0x08) {
                guess = "Windows";
                break;
            }
            /* Espressif (ESP32 / ESP8266) — OUI 24:0A:C4. */
            if (o0 == 0x24 && o1 == 0x0a && o2 == 0xc4) {
                guess = "ESP32";
                break;
            }
            /* Wi-Fi Alliance OUI 50:6F:9A — used by P2P / Wi-Fi Direct
             * IEs. Mostly Android devices include this. */
            if (o0 == 0x50 && o1 == 0x6f && o2 == 0x9a && !guess) {
                guess = "Android";
                /* don't break — a later Apple/MS IE would override */
            }
        }
        p   += 2 + len;
        rem -= 2 + len;
    }
    return guess;
}

/* Max PHY tier from HT (45) / VHT (191) / HE+EHT (255 ext id 35 / 108).
 * We classify "Wi-Fi 7" via the EHT Capabilities extension and via the
 * Multi-Link IE (ext 81) which is required for EHT operation; the
 * latter alone is enough since pre-EHT chips don't emit it. */
const char *probe_pnl_phy_ies(const uint8_t *ies, int ielen)
{
    if (!ies || ielen < 2) return NULL;
    int has_ht = 0, has_vht = 0, has_he = 0, has_eht = 0;
    const uint8_t *p = ies;
    int rem = ielen;
    while (rem >= 2) {
        uint8_t tag = p[0];
        uint8_t len = p[1];
        if (2 + (int)len > rem) break;
        if (tag == 45)  has_ht  = 1;
        if (tag == 191) has_vht = 1;
        if (tag == 255 && len >= 1) {
            uint8_t ext = p[2];
            if (ext == 35)               has_he  = 1;   /* HE Capabilities */
            if (ext == 81 || ext == 108) has_eht = 1;   /* Multi-Link / EHT */
        }
        p   += 2 + len;
        rem -= 2 + len;
    }
    if (has_eht) return "Wi-Fi 7";
    if (has_he)  return "Wi-Fi 6";
    if (has_vht) return "Wi-Fi 5";
    if (has_ht)  return "Wi-Fi 4";
    return "legacy";
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
