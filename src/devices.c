#include <stdio.h>
#include <string.h>
#include <time.h>
#include "devices.h"
#include "oui.h"

/* ── MAC helpers ─────────────────────────────────────────── */

static int parse_mac(const char *s, uint8_t mac[6]) {
    if (!s || !s[0]) return 0;
    unsigned b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return 0;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)b[i];
    return 1;
}

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

static int mac_is_zero(const uint8_t a[6]) {
    static const uint8_t zero[6] = {0};
    return memcmp(a, zero, 6) == 0;
}

/* ── Upsert ──────────────────────────────────────────────── */

/* Find or append a device record for `mac` in dev[0..*n], expanding *n.
 * Returns NULL if the table is full and the MAC isn't already present. */
static device_t *upsert(device_t *dev, int *n, const uint8_t mac[6]) {
    if (mac_is_zero(mac)) return NULL;
    for (int i = 0; i < *n; i++) {
        if (mac_eq(dev[i].mac, mac)) return &dev[i];
    }
    if (*n >= MAX_DEVICES) return NULL;
    device_t *d = &dev[(*n)++];
    memset(d, 0, sizeof(*d));
    memcpy(d->mac, mac, 6);
    return d;
}

static void set_str(char *dst, int dstsz, const char *src) {
    if (!src || !src[0] || !dst || dstsz <= 0) return;
    if (dst[0]) return;  /* prefer first non-empty value */
    snprintf(dst, (size_t)dstsz, "%s", src);
}

static const char *short_vendor(const char *v) {
    return (v && v[0]) ? v : "";
}

/* ── Sources ─────────────────────────────────────────────── */

static void merge_arp(const sloth_state_t *s, device_t *dev, int *n, time_t now) {
    for (int i = 0; i < s->arp_count; i++) {
        const arp_entry_t *a = &s->arp_entries[i];
        device_t *d = upsert(dev, n, a->mac);
        if (!d) continue;
        set_str(d->ip,     sizeof(d->ip),     a->ip);
        set_str(d->vendor, sizeof(d->vendor), short_vendor(oui_lookup(a->mac)));
        d->sources  |= DEV_SRC_ARP;
        d->last_seen = now;
    }
}

static void merge_dhcp(const sloth_state_t *s, device_t *dev, int *n, time_t now) {
    /* DHCP leases lack the MAC, so bridge via ARP: find any device whose
       IP matches the lease, then attach the hostname. */
    (void)now;
    for (int i = 0; i < s->dhcp_count; i++) {
        const dhcp_lease_t *L = &s->dhcp_leases[i];
        if (!L->hostname[0] && !L->ip[0]) continue;
        for (int j = 0; j < *n; j++) {
            if (strcmp(dev[j].ip, L->ip) == 0) {
                set_str(dev[j].hostname, sizeof(dev[j].hostname), L->hostname);
                dev[j].sources |= DEV_SRC_DHCP;
                break;
            }
        }
    }
}

static void merge_beacons(const sloth_state_t *s, device_t *dev, int *n, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *b = &s->beacon_aps[i];
        device_t *d = upsert(dev, n, b->bssid);
        if (!d) continue;
        d->is_ap     = 1;
        d->signal_dbm = b->signal_dbm;
        set_str(d->vendor, sizeof(d->vendor), short_vendor(oui_lookup(b->bssid)));
        d->sources  |= DEV_SRC_BEACON;
        if (b->last_seen > d->last_seen) d->last_seen = b->last_seen;
        (void)now;
    }
}

static void merge_probes(const sloth_state_t *s, device_t *dev, int *n, time_t now) {
    for (int i = 0; i < s->probe_count; i++) {
        const probe_client_t *p = &s->probe_clients[i];
        device_t *d = upsert(dev, n, p->mac);
        if (!d) continue;
        d->probe_count += p->frame_count;
        if (p->ssid[0])
            snprintf(d->last_ssid, sizeof(d->last_ssid), "%s", p->ssid);
        d->signal_dbm = p->signal_dbm;
        set_str(d->vendor, sizeof(d->vendor), short_vendor(oui_lookup(p->mac)));
        d->sources  |= DEV_SRC_PROBE;
        if (p->last_seen > d->last_seen) d->last_seen = p->last_seen;
        (void)now;
    }
}

static void merge_stas(const sloth_state_t *s, device_t *dev, int *n, time_t now) {
    for (int i = 0; i < s->wifi_sta_count; i++) {
        const wifi_sta_t *st = &s->wifi_stas[i];
        uint8_t mac[6];
        if (!parse_mac(st->mac, mac)) continue;
        device_t *d = upsert(dev, n, mac);
        if (!d) continue;
        d->signal_dbm = st->signal_dbm;
        set_str(d->vendor, sizeof(d->vendor), short_vendor(oui_lookup(mac)));
        d->sources  |= DEV_SRC_STA;
        d->last_seen = now;
    }
}

/* ── Public ──────────────────────────────────────────────── */

void devices_update(sloth_state_t *s) {
    if (!s) return;
    time_t   now = time(NULL);
    device_t buf[MAX_DEVICES];
    int      n = 0;

    /* Order matters: ARP gives us IPs first, then DHCP bridges hostnames
       into matching records. */
    merge_arp   (s, buf, &n, now);
    merge_beacons(s, buf, &n, now);
    merge_probes(s, buf, &n, now);
    merge_stas  (s, buf, &n, now);
    merge_dhcp  (s, buf, &n, now);

    /* Sort newest-first by last_seen. */
    for (int i = 0; i < n - 1; i++) {
        int max = i;
        for (int j = i + 1; j < n; j++) {
            if (buf[j].last_seen > buf[max].last_seen) max = j;
        }
        if (max != i) {
            device_t tmp = buf[i];
            buf[i] = buf[max];
            buf[max] = tmp;
        }
    }

    for (int i = 0; i < n; i++) s->devices[i] = buf[i];
    s->device_count = n;
    if (s->device_sel >= n) s->device_sel = n > 0 ? n - 1 : 0;
    if (s->device_sel < 0)  s->device_sel = 0;
}
