#include <string.h>
#include <stdio.h>
#include "sloth.h"
#include "fake_platform.h"

fake_net_t g_fake_net;

void fake_net_reset(void) {
    memset(&g_fake_net, 0, sizeof(g_fake_net));
}

static int fake_get_ifaces(iface_stat_t *out, int max) {
    int n = g_fake_net.iface_count < max ? g_fake_net.iface_count : max;
    memcpy(out, g_fake_net.ifaces, (size_t)n * sizeof(iface_stat_t));
    return n;
}

static int fake_get_conns(conn_t *out, int max) {
    int n = g_fake_net.conn_count < max ? g_fake_net.conn_count : max;
    memcpy(out, g_fake_net.conns, (size_t)n * sizeof(conn_t));
    return n;
}

static int fake_wifi_scan(wifi_ap_t *out, int max) {
    int n = g_fake_net.ap_count < max ? g_fake_net.ap_count : max;
    memcpy(out, g_fake_net.aps, (size_t)n * sizeof(wifi_ap_t));
    return n;
}

static int fake_get_wifi_stations(wifi_sta_t *out, int max) {
    int n = g_fake_net.wifi_sta_count < max ? g_fake_net.wifi_sta_count : max;
    memcpy(out, g_fake_net.wifi_stas, (size_t)n * sizeof(wifi_sta_t));
    return n;
}

void fake_net_apply_probe(sloth_state_t *s) {
    int n = g_fake_net.probe_count < MAX_PROBE_CLIENTS
          ? g_fake_net.probe_count : MAX_PROBE_CLIENTS;
    memcpy(s->probe_clients, g_fake_net.probe_clients,
           (size_t)n * sizeof(probe_client_t));
    s->probe_count = n;
    snprintf(s->probe_iface, sizeof(s->probe_iface), "%s", g_fake_net.probe_iface);
}

static int fake_get_arp(arp_entry_t *out, int max) {
    (void)out; (void)max; return 0;
}

static int fake_get_dhcp(dhcp_lease_t *out, int max) {
    (void)out; (void)max; return 0;
}

static int fake_set_channel(const char *iface, int freq_mhz) {
    g_fake_net.set_channel_calls++;
    g_fake_net.set_channel_last_freq = freq_mhz;
    snprintf(g_fake_net.set_channel_last_iface,
             sizeof(g_fake_net.set_channel_last_iface), "%s", iface ? iface : "");
    if (g_fake_net.refuse_freq_mhz && freq_mhz == g_fake_net.refuse_freq_mhz)
        return g_fake_net.refuse_rc;
    return g_fake_net.set_channel_rc;
}

/* ── /proc and /sys as text ──────────────────────────────── */

static int fake_sys_find(const char *path) {
    for (int i = 0; i < g_fake_net.sys_file_count; i++)
        if (strcmp(g_fake_net.sys_files[i].path, path) == 0) return i;
    return -1;
}

int fake_sys_put_n(const char *path, const char *bytes, int len) {
    if (!path || len < 0 || len > (int)sizeof(g_fake_net.sys_files[0].text) ||
        strlen(path) >= sizeof(g_fake_net.sys_files[0].path))
        return -1;
    int i = fake_sys_find(path);
    if (i < 0) {
        if (g_fake_net.sys_file_count >= FAKE_SYS_FILES) return -1;
        i = g_fake_net.sys_file_count++;
        snprintf(g_fake_net.sys_files[i].path, sizeof(g_fake_net.sys_files[i].path),
                 "%s", path);
    }
    if (len) memcpy(g_fake_net.sys_files[i].text, bytes, (size_t)len);
    g_fake_net.sys_files[i].len = len;
    return 0;
}

int fake_sys_put(const char *path, const char *text) {
    return fake_sys_put_n(path, text, (int)strlen(text));
}

void fake_sys_del(const char *path) {
    int i = fake_sys_find(path);
    if (i < 0) return;
    g_fake_net.sys_files[i] = g_fake_net.sys_files[--g_fake_net.sys_file_count];
}

static void fake_sys_note(const char *path) {
    snprintf(g_fake_net.sys_last_path, sizeof(g_fake_net.sys_last_path), "%s",
             path ? path : "");
    if (!path || (strncmp(path, "/proc/", 6) != 0 && strncmp(path, "/sys/", 5) != 0) ||
        strstr(path, "/../") || (strlen(path) >= 3 && !strcmp(path + strlen(path) - 3, "/..")))
        g_fake_net.sys_outside_calls++;
    if (path && g_fake_net.sys_watch[0] && strstr(path, g_fake_net.sys_watch))
        g_fake_net.sys_watch_hits++;
}

static int fake_sys_read(const char *path, char *buf, int cap) {
    g_fake_net.sys_read_calls++;
    fake_sys_note(path);
    int i = path ? fake_sys_find(path) : -1;
    if (i < 0) return -1;
    int n = g_fake_net.sys_files[i].len < cap ? g_fake_net.sys_files[i].len : cap;
    if (n > 0) memcpy(buf, g_fake_net.sys_files[i].text, (size_t)n);
    return n;
}

/* The entries of dir: the next path component of every file below it,
   once each. -1 when nothing is below it, as a missing directory. */
static int fake_sys_list(const char *dir, char *names, int name_sz, int max) {
    g_fake_net.sys_list_calls++;
    fake_sys_note(dir);
    if (!dir) return -1;
    size_t dl = strlen(dir);
    int n = 0, any = 0;
    for (int i = 0; i < g_fake_net.sys_file_count; i++) {
        const char *p = g_fake_net.sys_files[i].path;
        if (strncmp(p, dir, dl) != 0 || p[dl] != '/') continue;
        any = 1;
        const char *c = p + dl + 1;
        size_t cl = strcspn(c, "/");
        if (cl == 0 || cl >= (size_t)name_sz) continue;
        int dup = 0;
        for (int k = 0; k < n && !dup; k++)
            dup = strlen(names + (size_t)k * (size_t)name_sz) == cl &&
                  memcmp(names + (size_t)k * (size_t)name_sz, c, cl) == 0;
        if (dup || n >= max) continue;
        memcpy(names + (size_t)n * (size_t)name_sz, c, cl);
        names[(size_t)n * (size_t)name_sz + cl] = '\0';
        n++;
    }
    return any ? n : -1;
}

static void fake_init(void)    {}
static void fake_cleanup(void) {}

/* Satisfies the extern in ntop.h — only compiled in the test binary */
platform_ops_t g_platform = {
    fake_get_ifaces,
    fake_get_conns,
    fake_wifi_scan,
    fake_get_wifi_stations,
    fake_get_arp,
    fake_get_dhcp,
    fake_init,
    fake_cleanup,
    fake_set_channel,   /* #91: errno injected through g_fake_net */
    fake_sys_read,      /* src/sys_status.h: text fed by fake_sys_put() */
    fake_sys_list,
};
