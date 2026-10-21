/* Camera identity on the device record (#106 round 2). Contract and the
 * join-key rule are in camera_join.h; the predicates are the rules' own
 * (src/camera_vendor.c, ssid_is_public_hotspot()), so a device is never
 * marked on an input its rule stays quiet on. */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "camera_join.h"
#include "camera_vendor.h"
#include "sensor_health.h"
#include "alerts/rules.h"

static const alert_type_t g_sig_alert[CAM_SIG_COUNT] = {
    ALERT_TYPE_CAM_WS_DISCOVERY,
    ALERT_TYPE_CAM_SETUP_SSID,
    ALERT_TYPE_CAM_MDNS_SERVICE,
    ALERT_TYPE_CAM_SSDP_DEVICE,
    ALERT_TYPE_CAM_SETUP_OUI,
    ALERT_TYPE_CAM_RTSP_UNAUTH,
};

alert_type_t cam_signal_alert(int idx) {
    if (idx < 0 || idx >= CAM_SIG_COUNT) return ALERT_TYPE_COUNT;
    return g_sig_alert[idx];
}

const char *device_class_label(device_class_t c) {
    switch (c) {
    case DEV_CLASS_CAMERA:        return "camera";
    case DEV_CLASS_CAMERA_VENDOR: return "camera-vendor";
    case DEV_CLASS_UNKNOWN:       break;
    }
    return "";
}

static int sig_index(int sig) {
    for (int i = 0; i < CAM_SIG_COUNT; i++)
        if (sig == (1 << i)) return i;
    return -1;
}

static int mac_is_zero(const uint8_t m[6]) {
    static const uint8_t z[6] = {0};
    return memcmp(m, z, 6) == 0;
}

int cam_row_is_device_ip(const device_t *d, const char *ip) {
    return d && ip && ip[0] && d->ip[0] && strcmp(d->ip, ip) == 0;
}

/* Printable ASCII only: a remote side chose every byte. */
static void copy_printable(char *dst, size_t n, const char *src) {
    size_t o = 0;
    if (!n) return;
    for (; src && *src && o + 1 < n; src++)
        if ((unsigned char)*src >= 0x20 && (unsigned char)*src <= 0x7e)
            dst[o++] = *src;
    dst[o] = '\0';
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int cam_onvif_scope(const char *scopes, const char *kind, char *out,
                    size_t n) {
    static const char base[] = "onvif://www.onvif.org/";
    if (n) out[0] = '\0';
    if (!scopes || !kind || !kind[0] || !n) return 0;
    size_t blen = sizeof(base) - 1, klen = strlen(kind);
    const char *p = scopes;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (!*p) break;
        const char *tok = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
        size_t tlen = (size_t)(p - tok);
        /* RFC 3986 §3.1 / §3.2.2: scheme and host compare without case;
         * the path segment ("name") is compared as ONVIF writes it. */
        if (tlen <= blen + klen + 1) continue;
        int same = 1;
        for (size_t i = 0; i < blen && same; i++) {
            char c = tok[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            if (c != base[i]) same = 0;
        }
        if (!same || strncmp(tok + blen, kind, klen) != 0 ||
            tok[blen + klen] != '/')
            continue;
        const char *v = tok + blen + klen + 1, *end = tok + tlen;
        size_t o = 0;
        while (v < end && o + 1 < n) {
            int c = (unsigned char)*v;
            if (c == '%' && end - v >= 3 && hexval(v[1]) >= 0 &&
                hexval(v[2]) >= 0) {
                c = hexval(v[1]) * 16 + hexval(v[2]);
                v += 3;
            } else {
                v++;
            }
            if (c >= 0x20 && c <= 0x7e) out[o++] = (char)c;
        }
        out[o] = '\0';
        return 1;
    }
    return 0;
}

/* ── the join ──────────────────────────────────────────────── */

/* Vendor precedence, highest first: the device naming its maker in
 * SERVER, the setup SSID naming the brand, the IEEE assignee of the
 * address block. Kept per record so table order cannot decide it. */
enum { VP_NONE = 0, VP_OUI = 1, VP_SSID = 2, VP_SERVER = 3 };

typedef struct {
    device_t *dev;
    int      *n;
    int       vprio[MAX_DEVICES];
} join_t;

static void fold(join_t *j, int idx, int sig, time_t when) {
    device_t *d = &j->dev[idx];
    int si = sig_index(sig);
    d->cam_signal_mask |= sig;
    if (si >= 0 && when > d->cam_seen[si]) d->cam_seen[si] = when;
}

static void raise_class(device_t *d, device_class_t c) {
    if (c > d->device_class) d->device_class = c;
}

static void offer_vendor(join_t *j, int idx, const char *v, int prio) {
    if (!v || !v[0] || prio <= j->vprio[idx]) return;
    copy_printable(j->dev[idx].camera_vendor,
                   sizeof(j->dev[idx].camera_vendor), v);
    j->vprio[idx] = prio;
}

/* Every record holding `ip`, appending an IP-only one when none does
 * and `create` is set. Writes indices into out[], returns the count. */
static int by_ip(join_t *j, const char *ip, int create, time_t when,
                 int *out) {
    int k = 0;
    if (!ip || !ip[0]) return 0;
    for (int i = 0; i < *j->n; i++)
        if (strcmp(j->dev[i].ip, ip) == 0) out[k++] = i;
    if (k || !create) return k;
    if (*j->n >= MAX_DEVICES) { sh_evict_note(SH_EVICT_DEVICE); return 0; }
    device_t *d = &j->dev[(*j->n)++];
    memset(d, 0, sizeof(*d));
    snprintf(d->ip, sizeof(d->ip), "%s", ip);
    d->last_seen = when;
    j->vprio[*j->n - 1] = VP_NONE;
    out[k++] = *j->n - 1;
    return k;
}

static void lan(join_t *j, const char *ip, int create, time_t when,
                int sig, device_class_t cls, const char *vendor,
                const char *model) {
    int idx[MAX_DEVICES];
    int k = by_ip(j, ip, create, when, idx);
    for (int i = 0; i < k; i++) {
        device_t *d = &j->dev[idx[i]];
        fold(j, idx[i], sig, when);
        d->sources |= DEV_SRC_CAMERA;
        raise_class(d, cls);
        offer_vendor(j, idx[i], vendor, VP_SERVER);
        if (model && model[0] && !d->camera_model[0])
            copy_printable(d->camera_model, sizeof(d->camera_model), model);
        /* An IP-only record has no other source to age it. */
        if (mac_is_zero(d->mac) && when > d->last_seen) d->last_seen = when;
    }
}

/* "name hardware", or whichever one is present. A name that already
 * contains the hardware string is not repeated. */
static void onvif_model(const char *scopes, char *out, size_t n) {
    char name[64], hw[64], both[sizeof(name) + sizeof(hw)];
    int hn = cam_onvif_scope(scopes, "name", name, sizeof(name)) && name[0];
    int hh = cam_onvif_scope(scopes, "hardware", hw, sizeof(hw)) && hw[0];
    both[0] = '\0';
    if (hn && hh && !strstr(name, hw))
        snprintf(both, sizeof(both), "%s %s", name, hw);
    else if (hn)
        snprintf(both, sizeof(both), "%s", name);
    else if (hh)
        snprintf(both, sizeof(both), "%s", hw);
    /* Cut, not refused: the operator still wants the front of it. */
    copy_printable(out, n, both);
}

void camera_join(const sloth_state_t *s, device_t *dev, int *n) {
    join_t j;
    if (!s || !dev || !n) return;
    j.dev = dev;
    j.n   = n;
    for (int i = 0; i < *n; i++) j.vprio[i] = VP_NONE;

    /* Beacon side: BSSID == record MAC, the only key a beacon has. */
    for (int b = 0; b < s->beacon_count; b++) {
        const beacon_ap_t *a = &s->beacon_aps[b];
        const char *label = NULL, *brand = NULL, *ouiv = NULL;
        int local = 0;
        int ssid = a->ssid[0] && !ssid_is_public_hotspot(a->ssid) &&
                   cam_setup_ssid(a->ssid, &label, &brand);
        int oui = cam_vendor_oui(a->bssid, &ouiv, NULL, &local);
        if (!ssid && !oui) continue;
        for (int i = 0; i < *n; i++) {
            if (memcmp(dev[i].mac, a->bssid, 6) != 0) continue;
            if (ssid) {
                fold(&j, i, CAM_SIG_SETUP_SSID, a->last_seen);
                dev[i].setup_mode = 1;
                raise_class(&dev[i], DEV_CLASS_CAMERA);
                offer_vendor(&j, i, brand, VP_SSID);
            }
            if (oui) {
                fold(&j, i, CAM_SIG_SETUP_OUI, a->last_seen);
                raise_class(&dev[i], DEV_CLASS_CAMERA_VENDOR);
                offer_vendor(&j, i, ouiv, VP_OUI);
            }
        }
    }

    /* LAN side, class-bearing signals first: these may create an
     * IP-only record. */
    for (int i = 0; i < s->onvif_count; i++) {
        const onvif_device_t *o = &s->onvif_devices[i];
        if (!o->is_camera) continue;
        char model[48];
        onvif_model(o->scopes, model, sizeof(model));
        lan(&j, o->ip, 1, o->last_seen, CAM_SIG_WS_DISCOVERY,
            DEV_CLASS_CAMERA, NULL, model);
    }
    for (int i = 0; i < s->ssdp_count && i < MAX_SSDP_DEVICES; i++) {
        const ssdp_device_t *d = &s->ssdp_devices[i];
        int dsc = 0;
        const char *v = NULL;
        if (!cam_ssdp_row(d->type, d->nts, d->server, &dsc, &v)) continue;
        lan(&j, d->ip, 1, d->last_seen, CAM_SIG_SSDP_DEVICE,
            dsc ? DEV_CLASS_CAMERA : DEV_CLASS_CAMERA_VENDOR, v, NULL);
    }
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < s->mdns_count; i++) {
            const mdns_service_t *e = &s->mdns_services[i];
            int specific = 0;
            if (!e->instance[0] || !e->ip[0]) continue;
            if (!cam_mdns_service(e->service, NULL, &specific)) continue;
            /* Pass 0 the camera service types, which may create a
             * record; pass 1 _rtsp, which only attaches — after every
             * creating signal has run, so it finds those records. */
            if (specific != (pass == 0)) continue;
            lan(&j, e->ip, specific, e->last_seen, CAM_SIG_MDNS_SERVICE,
                specific ? DEV_CLASS_CAMERA : DEV_CLASS_UNKNOWN, NULL, NULL);
        }
        if (pass == 0) continue;
        int rn = s->rtsp_stream_count < MAX_RTSP_STREAMS
               ? s->rtsp_stream_count : MAX_RTSP_STREAMS;
        for (int i = 0; i < rn; i++) {
            const rtsp_stream_t *r = &s->rtsp_streams[i];
            if (!r->anon_ok) continue;
            lan(&j, r->server, 0, r->last_seen, CAM_SIG_RTSP_UNAUTH,
                DEV_CLASS_UNKNOWN, NULL, NULL);
        }
    }
}

/* ── the trail ─────────────────────────────────────────────── */

static void add_row(cam_trail_row_t *rows, int max, int *k,
                    int sig, time_t when, const char *what) {
    if (*k >= max) return;
    rows[*k].sig  = sig;
    rows[*k].when = when;
    snprintf(rows[*k].what, sizeof(rows[*k].what), "%s", what);
    (*k)++;
}

int camera_trail(const sloth_state_t *s, const device_t *d,
                 cam_trail_row_t *rows, int max) {
    int k = 0;
    char w[192];
    if (!s || !d || !rows || max <= 0) return 0;

    if (!mac_is_zero(d->mac)) {
        for (int b = 0; b < s->beacon_count; b++) {
            const beacon_ap_t *a = &s->beacon_aps[b];
            if (memcmp(a->bssid, d->mac, 6) != 0) continue;
            const char *label = NULL, *v = NULL, *org = NULL;
            int local = 0;
            if (a->ssid[0] && !ssid_is_public_hotspot(a->ssid) &&
                cam_setup_ssid(a->ssid, &label, NULL)) {
                snprintf(w, sizeof(w), "beacon SSID %.32s: %s setup SSID,"
                         " enc %.12s (provisioning state not observed)",
                         a->ssid, label, a->enc[0] ? a->enc : "unknown");
                add_row(rows, max, &k, CAM_SIG_SETUP_SSID,
                        a->last_seen, w);
            }
            if (cam_vendor_oui(a->bssid, &v, &org, &local)) {
                snprintf(w, sizeof(w), "BSSID OUI %02X:%02X:%02X is IEEE"
                         " MA-L \"%.48s\" (%s; device class not observed)%s",
                         (unsigned)(a->bssid[0] & ~0x02u),
                         (unsigned)a->bssid[1], (unsigned)a->bssid[2],
                         org, v, local ? "; randomized-local" : "");
                add_row(rows, max, &k, CAM_SIG_SETUP_OUI,
                        a->last_seen, w);
            }
        }
    }

    for (int i = 0; i < s->onvif_count; i++) {
        const onvif_device_t *o = &s->onvif_devices[i];
        if (!o->is_camera || !cam_row_is_device_ip(d, o->ip)) continue;
        snprintf(w, sizeof(w), "ONVIF %s, Types %.60s%s%.80s", o->kind,
                 o->types, o->xaddrs[0] ? ", XAddrs " : "", o->xaddrs);
        add_row(rows, max, &k, CAM_SIG_WS_DISCOVERY,
                o->last_seen, w);
    }
    for (int i = 0; i < s->mdns_count; i++) {
        const mdns_service_t *e = &s->mdns_services[i];
        const char *label = NULL;
        int specific = 0;
        if (!e->instance[0] || !cam_row_is_device_ip(d, e->ip)) continue;
        if (!cam_mdns_service(e->service, &label, &specific)) continue;
        snprintf(w, sizeof(w), "mDNS %.31s instance %.64s (%s%s)",
                 e->service, e->instance, label,
                 specific ? "" : "; a protocol, not a device class");
        add_row(rows, max, &k, CAM_SIG_MDNS_SERVICE,
                e->last_seen, w);
    }
    for (int i = 0; i < s->ssdp_count && i < MAX_SSDP_DEVICES; i++) {
        const ssdp_device_t *e = &s->ssdp_devices[i];
        int dsc = 0;
        const char *v = NULL;
        if (!cam_row_is_device_ip(d, e->ip)) continue;
        if (!cam_ssdp_row(e->type, e->nts, e->server, &dsc, &v)) continue;
        if (dsc)
            snprintf(w, sizeof(w), "SSDP NOTIFY %.15s DigitalSecurityCamera:1",
                     e->nts);
        else
            snprintf(w, sizeof(w), "SSDP NOTIFY %.15s Basic:1, SERVER names"
                     " camera vendor %s (the device's own claim)", e->nts, v);
        add_row(rows, max, &k, CAM_SIG_SSDP_DEVICE,
                e->last_seen, w);
    }
    int rn = s->rtsp_stream_count < MAX_RTSP_STREAMS
           ? s->rtsp_stream_count : MAX_RTSP_STREAMS;
    for (int i = 0; i < rn; i++) {
        const rtsp_stream_t *r = &s->rtsp_streams[i];
        if (!r->anon_ok || !cam_row_is_device_ip(d, r->server)) continue;
        snprintf(w, sizeof(w), "RTSP DESCRIBE answered with no challenge"
                 " on port %u path %.64s (%u time%s)", (unsigned)r->port,
                 r->path, (unsigned)r->anon_ok, r->anon_ok == 1 ? "" : "s");
        add_row(rows, max, &k, CAM_SIG_RTSP_UNAUTH,
                r->last_seen, w);
    }

    /* Newest first; ties keep the rule order above. Insertion sort:
     * stable, and k is a handful. */
    for (int i = 1; i < k; i++) {
        cam_trail_row_t t = rows[i];
        int m = i - 1;
        while (m >= 0 && rows[m].when < t.when) { rows[m + 1] = rows[m]; m--; }
        rows[m + 1] = t;
    }
    return k;
}
