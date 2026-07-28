/* Operator-designated networks. Contract in ownership.h (#52). */

#include <stdio.h>
#include <string.h>

#include "ownership.h"

/* SSIDs are 32 octets max on the air, +1 for our NUL. */
static char    g_ssids[MAX_MY_SSIDS][33];
static int     g_ssid_n;
static uint8_t g_bssids[MAX_MY_BSSIDS][6];
static int     g_bssid_n;

int ownership_add_ssid(const char *ssid) {
    if (!ssid || !ssid[0]) {
        fprintf(stderr, "sloth: --my-ssid needs a non-empty SSID\n");
        return 0;
    }
    if (strlen(ssid) > 32) {
        fprintf(stderr, "sloth: --my-ssid '%s' exceeds 32 octets\n", ssid);
        return 0;
    }
    for (int i = 0; i < g_ssid_n; i++)
        if (strcmp(g_ssids[i], ssid) == 0) return 1;   /* idempotent */
    if (g_ssid_n >= MAX_MY_SSIDS) {
        fprintf(stderr, "sloth: too many --my-ssid designations (max %d)\n",
                MAX_MY_SSIDS);
        return 0;
    }
    snprintf(g_ssids[g_ssid_n++], sizeof(g_ssids[0]), "%s", ssid);
    return 1;
}

/* One hex digit → 0..15, or -1. */
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Strict "xx:xx:xx:xx:xx:xx" (or '-' separated). Deliberately strict:
 * a typo'd BSSID would silently designate nothing, and the operator
 * would conclude their own AP wasn't being recognised. */
static int parse_mac(const char *str, uint8_t out[6]) {
    if (!str) return 0;
    if (strlen(str) != 17) return 0;
    for (int i = 0; i < 6; i++) {
        int hi = hexval(str[i * 3]);
        int lo = hexval(str[i * 3 + 1]);
        if (hi < 0 || lo < 0) return 0;
        if (i < 5) {
            char sep = str[i * 3 + 2];
            if (sep != ':' && sep != '-') return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

int ownership_add_bssid(const char *str) {
    uint8_t mac[6];
    if (!parse_mac(str, mac)) {
        fprintf(stderr, "sloth: --my-bssid '%s' is not aa:bb:cc:dd:ee:ff\n",
                str ? str : "(null)");
        return 0;
    }
    for (int i = 0; i < g_bssid_n; i++)
        if (memcmp(g_bssids[i], mac, 6) == 0) return 1;   /* idempotent */
    if (g_bssid_n >= MAX_MY_BSSIDS) {
        fprintf(stderr, "sloth: too many --my-bssid designations (max %d)\n",
                MAX_MY_BSSIDS);
        return 0;
    }
    memcpy(g_bssids[g_bssid_n++], mac, 6);
    return 1;
}

int ownership_is_my_ssid(const char *ssid) {
    if (!ssid || !ssid[0]) return 0;
    for (int i = 0; i < g_ssid_n; i++)
        if (strcmp(g_ssids[i], ssid) == 0) return 1;
    return 0;
}

int ownership_is_my_bssid(const uint8_t bssid[6]) {
    if (!bssid) return 0;
    for (int i = 0; i < g_bssid_n; i++)
        if (memcmp(g_bssids[i], bssid, 6) == 0) return 1;
    return 0;
}

int ownership_any(void)         { return g_ssid_n > 0 || g_bssid_n > 0; }
int ownership_ssid_count(void)  { return g_ssid_n; }
int ownership_bssid_count(void) { return g_bssid_n; }

void ownership_clear(void) {
    g_ssid_n  = 0;
    g_bssid_n = 0;
    memset(g_ssids,  0, sizeof(g_ssids));
    memset(g_bssids, 0, sizeof(g_bssids));
}
