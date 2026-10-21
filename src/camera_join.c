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
#include "tune.h"
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
    case DEV_CLASS_NOT_CAMERA:    return "not-camera";
    case DEV_CLASS_UNKNOWN:       break;
    }
    return "";
}

int device_class_is_camera(device_class_t c) {
    return c == DEV_CLASS_CAMERA || c == DEV_CLASS_CAMERA_VENDOR;
}

/* ── #155 evidence and veto tables ─────────────────────────────
 *
 * Weights. RTSP_SDP is the one cited class-deciding signal: a DESCRIBE
 * answered 200 with Content-Type application/sdp is the device serving
 * a media description (RFC 2326 §10.2, RFC 7826 §13.2). The mixed OUI
 * is a +1 prior. The other two are weaker and shown: they cannot reach
 * the threshold without RTSP_SDP, because the rule requires it.
 * Dropped by the fact-check (#155) and not here: an RTP-source signal
 * (an RTP v2 header test matches about a quarter of arbitrary UDP, and
 * WebRTC and VoIP send real RTP) and an uplink-ratio score (no cited
 * basis). */
static const struct {
    int bit, weight;
    const char *slug, *desc;
} g_ev[CAM_EV_COUNT] = {
    { CAM_EV_MIXED_OUI,   1, "mixed_oui",
      "mixed-vendor OUI (this vendor ships routers and APs as well as"
      " cameras)" },
    { CAM_EV_RTSP_SDP,    2, "rtsp_sdp",
      "answered RTSP DESCRIBE 200 with application/sdp (RFC 2326"
      " §10.2)" },
    { CAM_EV_RTSP_SERVER, 1, "rtsp_server",
      "answered RTSP DESCRIBE, no SDP body seen (weaker, shown only)" },
    { CAM_EV_MDNS_RTSP,   1, "mdns_rtsp",
      "advertises DNS-SD _rtsp, a protocol, not a class (weaker, shown"
      " only)" },
};

static const struct { int bit; const char *slug, *desc; }
g_veto[CAM_VETO_COUNT] = {
    { CAM_VETO_DHCP_SERVER,   "dhcp_server",
      "DHCP server (RFC 2131 §4.1, RFC 2132 §9.7)" },
    { CAM_VETO_SENDS_RA,      "sends_ra",
      "sends RAs with router lifetime > 0 (RFC 4861 §4.2)" },
    { CAM_VETO_DNS_RESPONDER, "dns_responder",
      "DNS responder to >= 2 LAN clients" },
};

const char *cam_evidence_slug(int bit) {
    for (int i = 0; i < CAM_EV_COUNT; i++)
        if (g_ev[i].bit == bit) return g_ev[i].slug;
    return "";
}

const char *cam_evidence_desc(int bit) {
    for (int i = 0; i < CAM_EV_COUNT; i++)
        if (g_ev[i].bit == bit) return g_ev[i].desc;
    return "";
}

int cam_evidence_weight(int bit) {
    for (int i = 0; i < CAM_EV_COUNT; i++)
        if (g_ev[i].bit == bit) return g_ev[i].weight;
    return 0;
}

const char *cam_veto_slug(int bit) {
    for (int i = 0; i < CAM_VETO_COUNT; i++)
        if (g_veto[i].bit == bit) return g_veto[i].slug;
    return "";
}

const char *cam_veto_desc(int bit) {
    for (int i = 0; i < CAM_VETO_COUNT; i++)
        if (g_veto[i].bit == bit) return g_veto[i].desc;
    return "";
}

static void slug_list(int mask, int veto, char *out, size_t n) {
    size_t o = 0;
    int cnt = veto ? CAM_VETO_COUNT : CAM_EV_COUNT;
    if (!n) return;
    out[0] = '\0';
    for (int i = 0; i < cnt; i++) {
        int bit = veto ? g_veto[i].bit : g_ev[i].bit;
        if (!(mask & bit)) continue;
        const char *sl = veto ? g_veto[i].slug : g_ev[i].slug;
        int k = snprintf(out + o, n - o, "%s%s", o ? "," : "", sl);
        if (k < 0 || (size_t)k >= n - o) { out[o] = '\0'; return; }
        o += (size_t)k;
    }
}

void cam_evidence_list(int mask, char *out, size_t n) { slug_list(mask, 0, out, n); }
void cam_veto_list(int mask, char *out, size_t n)     { slug_list(mask, 1, out, n); }

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

/* ── CAM_SETUP_OUI's row test ─────────────────────────────── */

int cam_setup_oui_counts(const beacon_ap_t *a, const char **vendor,
                         const char **org, int *local, int *mixed) {
    int mx = 0, lc = 0;
    const char *v = NULL, *o = NULL;
    if (!a || !cam_vendor_oui(a->bssid, &v, &o, &lc, &mx)) return 0;
    /* #155: a mixed-vendor block counts only beside a camera setup SSID
     * on the same BSSID — the SSID is the self-declaration, the block
     * the corroboration. The open-hotspot guardrail runs first, as in
     * CAM_SETUP_SSID itself. */
    if (mx && !(a->ssid[0] && !ssid_is_public_hotspot(a->ssid) &&
                cam_setup_ssid(a->ssid, NULL, NULL)))
        return 0;
    if (vendor) *vendor = v;
    if (org)    *org    = o;
    if (local)  *local  = lc;
    if (mixed)  *mixed  = mx;
    return 1;
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

static int is_fresh(time_t when, time_t now) {
    return (long long)now - (long long)when <=
           (long long)tune_val(TUNE_CAM_JOIN_FRESH_SECS);
}

cam_join_state_t cam_lan_state(const device_t *records, int n,
                               const char *ip, time_t when, time_t now) {
    if (!is_fresh(when, now)) return CAM_JOIN_STALE;
    int k = 0;
    for (int i = 0; records && ip && i < n; i++)
        if (strcmp(records[i].ip, ip) == 0) k++;
    return k > 1 ? CAM_JOIN_AMBIGUOUS : CAM_JOIN_OK;
}

/* The record holding `ip`, appending an IP-only one when none does and
 * `create` is set. -1 when the row may not join (cam_lan_state()). */
static int by_ip(join_t *j, const char *ip, int create, time_t when,
                 time_t now) {
    if (!ip || !ip[0]) return -1;
    if (cam_lan_state(j->dev, *j->n, ip, when, now) != CAM_JOIN_OK)
        return -1;
    for (int i = 0; i < *j->n; i++)
        if (strcmp(j->dev[i].ip, ip) == 0) return i;
    if (!create) return -1;
    if (*j->n >= MAX_DEVICES) { sh_evict_note(SH_EVICT_DEVICE); return -1; }
    device_t *d = &j->dev[(*j->n)++];
    memset(d, 0, sizeof(*d));
    snprintf(d->ip, sizeof(d->ip), "%s", ip);
    d->last_seen = when;
    j->vprio[*j->n - 1] = VP_NONE;
    return *j->n - 1;
}

/* A row's IPv4 and IPv6 source, each with its own time. A row written
 * before the per-family fields existed (or seeded with ip[] alone)
 * reads its one address by family. */
typedef struct { const char *ip; time_t when; } cam_addr_t;

static void row_addrs(const char *ip, time_t seen, const char *ip4,
                      time_t t4, const char *ip6, time_t t6,
                      cam_addr_t a[2]) {
    a[0].ip = ""; a[0].when = 0;
    a[1].ip = ""; a[1].when = 0;
    if (ip4[0] || ip6[0]) {
        if (ip4[0]) { a[0].ip = ip4; a[0].when = t4; }
        if (ip6[0]) { a[1].ip = ip6; a[1].when = t6; }
    } else if (ip[0]) {
        int v6 = strchr(ip, ':') != NULL;
        a[v6].ip = ip; a[v6].when = seen;
    }
}

static int addr_of(const cam_addr_t a[2], const device_t *d, time_t *when) {
    for (int f = 0; f < 2; f++)
        if (cam_row_is_device_ip(d, a[f].ip)) {
            if (when) *when = a[f].when;
            return 1;
        }
    return 0;
}

int cam_onvif_addr_of(const onvif_device_t *o, const device_t *d,
                      time_t *when) {
    cam_addr_t a[2];
    if (!o) return 0;
    row_addrs(o->ip, o->last_seen, o->ip4, o->ip4_seen, o->ip6,
              o->ip6_seen, a);
    return addr_of(a, d, when);
}

int cam_ssdp_addr_of(const ssdp_device_t *e, const device_t *d,
                     time_t *when) {
    cam_addr_t a[2];
    if (!e) return 0;
    row_addrs(e->ip, e->last_seen, e->ip4, e->ip4_seen, e->ip6,
              e->ip6_seen, a);
    return addr_of(a, d, when);
}

/* Returns 1 when the row joined (or created) a record. */
static int lan(join_t *j, const char *ip, int create, time_t when,
               time_t now, int sig, device_class_t cls, const char *vendor,
               const char *model) {
    int i = by_ip(j, ip, create, when, now);
    if (i < 0) return 0;
    device_t *d = &j->dev[i];
    fold(j, i, sig, when);
    d->sources |= DEV_SRC_CAMERA;
    raise_class(d, cls);
    offer_vendor(j, i, vendor, VP_SERVER);
    if (model && model[0] && !d->camera_model[0])
        copy_printable(d->camera_model, sizeof(d->camera_model), model);
    /* An IP-only record has no other source to age it. */
    if (mac_is_zero(d->mac) && when > d->last_seen) d->last_seen = when;
    return 1;
}

/* IPv4 first; once it joined, the IPv6 address may only attach, so a
 * dual-stack row never makes an IP-only twin of a record it already
 * marked. */
static void lan_dual(join_t *j, const cam_addr_t a[2], int create,
                     time_t now, int sig, device_class_t cls,
                     const char *vendor, const char *model) {
    int v4 = lan(j, a[0].ip, create, a[0].when, now, sig, cls, vendor, model);
    lan(j, a[1].ip, create && !v4, a[1].when, now, sig, cls, vendor, model);
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

/* ── #155: evidence, vetoes, class ─────────────────────────── */

static void fmt_mac_lc(const uint8_t m[6], char out[18]) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void add_reason(cam_reason_t *rows, int max, int *k, int bit,
                       int veto, time_t when, const char *what) {
    if (*k >= max) return;
    rows[*k].bit  = bit;
    rows[*k].veto = veto;
    rows[*k].when = when;
    snprintf(rows[*k].what, sizeof(rows[*k].what), "%s", what);
    (*k)++;
}

int camera_reasons(const sloth_state_t *s, const device_t *recs, int nrec,
                   const device_t *d, time_t now, cam_reason_t *rows,
                   int max) {
    int k = 0;
    char w[200];
    if (!s || !d || !rows || max <= 0) return 0;

    if (!mac_is_zero(d->mac)) {
        const char *org = NULL;
        int mx = 0;
        if (cam_vendor_oui(d->mac, NULL, &org, NULL, &mx) && mx) {
            snprintf(w, sizeof(w), "OUI %02X:%02X:%02X, IEEE MA-L \"%.40s\":"
                     " mixed vendor, a prior only", (unsigned)d->mac[0],
                     (unsigned)d->mac[1], (unsigned)d->mac[2], org);
            add_reason(rows, max, &k, CAM_EV_MIXED_OUI, 0, 0, w);
        }
    }

    if (d->ip[0]) {
        /* RTSP: one SDP row decides; otherwise any answered DESCRIBE is
         * the weaker "serves RTSP". Counts and the path only — never an
         * Authorization value or URL userinfo (cleartext_creds.h). */
        int rn = s->rtsp_stream_count < MAX_RTSP_STREAMS
               ? s->rtsp_stream_count : MAX_RTSP_STREAMS;
        const rtsp_stream_t *sdp = NULL, *any = NULL;
        for (int i = 0; i < rn; i++) {
            const rtsp_stream_t *r = &s->rtsp_streams[i];
            if (!cam_row_is_device_ip(d, r->server) ||
                cam_lan_state(recs, nrec, d->ip, r->last_seen, now)
                    != CAM_JOIN_OK)
                continue;
            if (r->sdp && (!sdp || r->last_seen > sdp->last_seen)) sdp = r;
            if ((r->anon_ok || r->auth_ok || r->challenged) &&
                (!any || r->last_seen > any->last_seen))
                any = r;
        }
        if (sdp) {
            snprintf(w, sizeof(w), "DESCRIBE 200 application/sdp, port %u"
                     " %.48s", (unsigned)sdp->port, sdp->path);
            add_reason(rows, max, &k, CAM_EV_RTSP_SDP, 0, sdp->last_seen, w);
        } else if (any) {
            snprintf(w, sizeof(w), "DESCRIBE answered on port %u (%u ok,"
                     " %u 401); no SDP seen",
                     (unsigned)any->port,
                     (unsigned)(any->anon_ok + any->auth_ok),
                     (unsigned)any->challenged);
            add_reason(rows, max, &k, CAM_EV_RTSP_SERVER, 0,
                       any->last_seen, w);
        }

        const mdns_service_t *m = NULL;
        for (int i = 0; i < s->mdns_count; i++) {
            const mdns_service_t *e = &s->mdns_services[i];
            int specific = 1;
            if (!e->instance[0] || !cam_row_is_device_ip(d, e->ip)) continue;
            if (!cam_mdns_service(e->service, NULL, &specific) || specific)
                continue;
            if (cam_lan_state(recs, nrec, d->ip, e->last_seen, now)
                    != CAM_JOIN_OK)
                continue;
            if (!m || e->last_seen > m->last_seen) m = e;
        }
        if (m) {
            snprintf(w, sizeof(w), "mDNS %.31s instance %.64s", m->service,
                     m->instance);
            add_reason(rows, max, &k, CAM_EV_MDNS_RTSP, 0, m->last_seen, w);
        }

        for (int i = 0; i < s->lan_role_count && i < MAX_LAN_ROLES; i++) {
            const lan_role_t *r = &s->lan_roles[i];
            if (!cam_row_is_device_ip(d, r->ip)) continue;
            if ((r->roles & (LAN_ROLE_DHCP_REPLY | LAN_ROLE_DHCP_SID)) &&
                r->dhcp_seen &&
                cam_lan_state(recs, nrec, d->ip, r->dhcp_seen, now)
                    == CAM_JOIN_OK) {
                snprintf(w, sizeof(w), "%s%s%s",
                         (r->roles & LAN_ROLE_DHCP_REPLY)
                             ? "sent a BOOTREPLY from UDP 67" : "",
                         (r->roles & LAN_ROLE_DHCP_REPLY) &&
                         (r->roles & LAN_ROLE_DHCP_SID) ? "; " : "",
                         (r->roles & LAN_ROLE_DHCP_SID)
                             ? "named in option 54 Server Identifier" : "");
                add_reason(rows, max, &k, CAM_VETO_DHCP_SERVER, 1,
                           r->dhcp_seen, w);
            }
            if ((r->roles & LAN_ROLE_DNS) && r->dns_clients >= 2 &&
                cam_lan_state(recs, nrec, d->ip, r->dns_seen, now)
                    == CAM_JOIN_OK) {
                snprintf(w, sizeof(w), "answered %s%d LAN clients from"
                         " UDP 53",
                         r->dns_clients >= LAN_ROLE_DNS_CLIENTS ? ">= " : "",
                         r->dns_clients);
                add_reason(rows, max, &k, CAM_VETO_DNS_RESPONDER, 1,
                           r->dns_seen, w);
            }
        }
    }

    /* RFC 4861 §4.2: a non-zero Router Lifetime advertises the sender as
     * a default router; 0 says it is not one, so it is no veto. Keyed on
     * the Source Link-Layer Address option when the RA carries one (the
     * record's own MAC, no lease to change hands), else on the source
     * address. Seen within camera.join_fresh_secs either way: routers
     * repeat RAs every MaxRtrAdvInterval, at most 1800 s (§6.2.1). */
    for (int i = 0; i < s->ndp_ra_count && i < MAX_NDP_RAS; i++) {
        const ndp_ra_event_t *r = &s->ndp_ras[i];
        if (r->router_lifetime == 0 || !is_fresh(r->last_seen, now)) continue;
        int by_mac = r->has_src_mac && !mac_is_zero(d->mac) &&
                     memcmp(r->src_mac, d->mac, 6) == 0;
        int by_ip  = !by_mac && cam_row_is_device_ip(d, r->src_ip) &&
                     cam_lan_state(recs, nrec, d->ip, r->last_seen, now)
                         == CAM_JOIN_OK;
        if (!by_mac && !by_ip) continue;
        snprintf(w, sizeof(w), "sends RAs, lifetime %u s, from %.46s (%s)",
                 (unsigned)r->router_lifetime, r->src_ip,
                 by_mac ? "SLLA is this MAC" : "source is this IP");
        add_reason(rows, max, &k, CAM_VETO_SENDS_RA, 1, r->last_seen, w);
        break;
    }
    return k;
}

static void classify(const sloth_state_t *s, join_t *j, int idx,
                     time_t now) {
    device_t *d = &j->dev[idx];
    cam_reason_t rows[8];
    int k = camera_reasons(s, j->dev, *j->n, d, now, rows, 8);
    int ev = 0, veto = 0, score = 0;
    for (int i = 0; i < k; i++) {
        if (rows[i].veto) veto |= rows[i].bit;
        else if (!(ev & rows[i].bit)) {
            ev |= rows[i].bit;
            score += cam_evidence_weight(rows[i].bit);
        }
    }
    d->cam_evidence = ev;
    d->cam_vetoes   = veto;
    d->cam_score    = score;
    d->cam_conflict = 0;

    if (ev & CAM_EV_MIXED_OUI) {
        const char *v = NULL;
        cam_vendor_oui(d->mac, &v, NULL, NULL, NULL);
        offer_vendor(j, idx, v, VP_OUI);
    }

    /* A self-declaration (or a vendor SERVER token) already set the
     * class and still decides it. A mixed-vendor record gets one from
     * behaviour only at CAM_CLASS_MIN_SCORE with RTSP_SDP among it. A
     * veto against either kind of camera evidence is a conflict: shown,
     * and for a scored-only record the class is left unknown rather
     * than picked. A veto with no camera evidence makes a mixed-vendor
     * record NOT_CAMERA; on any other record it is shown and decides
     * nothing, because only the mixed OUI made the question open. */
    int claim  = device_class_is_camera(d->device_class);
    int scored = (ev & CAM_EV_MIXED_OUI) && (ev & CAM_EV_RTSP_SDP) &&
                 score >= CAM_CLASS_MIN_SCORE;
    if (veto && (claim || scored)) {
        d->cam_conflict = 1;
    } else if (scored && !claim) {
        d->device_class = DEV_CLASS_CAMERA_VENDOR;
    } else if (veto && (ev & CAM_EV_MIXED_OUI) && !claim) {
        d->device_class = DEV_CLASS_NOT_CAMERA;
    }

    /* DHCP options 55 / 60, display-only, by the client's chaddr. */
    if (!mac_is_zero(d->mac)) {
        char m[18];
        fmt_mac_lc(d->mac, m);
        for (int i = 0; i < s->dhcp_event_count && i < MAX_DHCP_EVENTS; i++) {
            const dhcp_event_t *e = &s->dhcp_events[i];
            if (strcmp(e->mac, m) != 0) continue;
            copy_printable(d->dhcp_prl, sizeof(d->dhcp_prl), e->prl);
            copy_printable(d->dhcp_vci, sizeof(d->dhcp_vci), e->vci);
            break;
        }
    }
}

void camera_join(const sloth_state_t *s, device_t *dev, int *n,
                 time_t now) {
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
        /* A mixed-vendor block alone is not CAM_SETUP_OUI (#155); its
         * prior is the classifier's, below. */
        int oui = cam_setup_oui_counts(a, &ouiv, NULL, &local, NULL);
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
        cam_addr_t a[2];
        onvif_model(o->scopes, model, sizeof(model));
        row_addrs(o->ip, o->last_seen, o->ip4, o->ip4_seen, o->ip6,
                  o->ip6_seen, a);
        lan_dual(&j, a, 1, now, CAM_SIG_WS_DISCOVERY, DEV_CLASS_CAMERA,
                 NULL, model);
    }
    for (int i = 0; i < s->ssdp_count && i < MAX_SSDP_DEVICES; i++) {
        const ssdp_device_t *d = &s->ssdp_devices[i];
        int dsc = 0;
        const char *v = NULL;
        cam_addr_t a[2];
        if (!cam_ssdp_row(d->type, d->nts, d->server, &dsc, &v)) continue;
        row_addrs(d->ip, d->last_seen, d->ip4, d->ip4_seen, d->ip6,
                  d->ip6_seen, a);
        lan_dual(&j, a, 1, now, CAM_SIG_SSDP_DEVICE,
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
            lan(&j, e->ip, specific, e->last_seen, now,
                CAM_SIG_MDNS_SERVICE,
                specific ? DEV_CLASS_CAMERA : DEV_CLASS_UNKNOWN, NULL, NULL);
        }
        if (pass == 0) continue;
        int rn = s->rtsp_stream_count < MAX_RTSP_STREAMS
               ? s->rtsp_stream_count : MAX_RTSP_STREAMS;
        for (int i = 0; i < rn; i++) {
            const rtsp_stream_t *r = &s->rtsp_streams[i];
            if (!r->anon_ok) continue;
            lan(&j, r->server, 0, r->last_seen, now, CAM_SIG_RTSP_UNAUTH,
                DEV_CLASS_UNKNOWN, NULL, NULL);
        }
    }

    /* #155: score, vetoes and the mixed-vendor class, after every
     * signal has joined so a self-declaration is already on the
     * record. */
    for (int i = 0; i < *n; i++) classify(s, &j, i, now);
}

/* ── the trail ─────────────────────────────────────────────── */

static void add_row(cam_trail_row_t *rows, int max, int *k, int sig,
                    time_t when, cam_join_state_t st, const char *what) {
    static const char *const why[] = {
        "",
        "history, not joined (older than camera.join_fresh_secs): ",
        "not joined (more than one device record holds this IP): ",
    };
    if (*k >= max) return;
    rows[*k].sig   = sig;
    rows[*k].when  = when;
    rows[*k].state = st;
    snprintf(rows[*k].what, sizeof(rows[*k].what), "%s%s",
             why[st <= CAM_JOIN_AMBIGUOUS ? st : 0], what);
    (*k)++;
}

int camera_trail(const sloth_state_t *s, const device_t *d, time_t now,
                 cam_trail_row_t *rows, int max) {
    int k = 0;
    char w[160];
    time_t when = 0;
    if (!s || !d || !rows || max <= 0) return 0;
    const device_t *recs = s->devices;
    int nrec = s->device_count;

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
                add_row(rows, max, &k, CAM_SIG_SETUP_SSID, a->last_seen,
                        CAM_JOIN_OK, w);
            }
            if (cam_setup_oui_counts(a, &v, &org, &local, NULL)) {
                snprintf(w, sizeof(w), "BSSID OUI %02X:%02X:%02X is IEEE"
                         " MA-L \"%.40s\" (%s; device class not observed)%s",
                         (unsigned)(a->bssid[0] & ~0x02u),
                         (unsigned)a->bssid[1], (unsigned)a->bssid[2],
                         org, v, local ? "; randomized-local" : "");
                add_row(rows, max, &k, CAM_SIG_SETUP_OUI, a->last_seen,
                        CAM_JOIN_OK, w);
            }
        }
    }

    for (int i = 0; i < s->onvif_count; i++) {
        const onvif_device_t *o = &s->onvif_devices[i];
        if (!o->is_camera || !cam_onvif_addr_of(o, d, &when)) continue;
        snprintf(w, sizeof(w), "ONVIF %s, Types %.48s%s%.64s", o->kind,
                 o->types, o->xaddrs[0] ? ", XAddrs " : "", o->xaddrs);
        add_row(rows, max, &k, CAM_SIG_WS_DISCOVERY, when,
                cam_lan_state(recs, nrec, d->ip, when, now), w);
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
        add_row(rows, max, &k, CAM_SIG_MDNS_SERVICE, e->last_seen,
                cam_lan_state(recs, nrec, d->ip, e->last_seen, now), w);
    }
    for (int i = 0; i < s->ssdp_count && i < MAX_SSDP_DEVICES; i++) {
        const ssdp_device_t *e = &s->ssdp_devices[i];
        int dsc = 0;
        const char *v = NULL;
        if (!cam_ssdp_addr_of(e, d, &when)) continue;
        if (!cam_ssdp_row(e->type, e->nts, e->server, &dsc, &v)) continue;
        if (dsc)
            snprintf(w, sizeof(w), "SSDP NOTIFY %.15s DigitalSecurityCamera:1",
                     e->nts);
        else
            snprintf(w, sizeof(w), "SSDP NOTIFY %.15s Basic:1, SERVER names"
                     " camera vendor %s (the device's own claim)", e->nts, v);
        add_row(rows, max, &k, CAM_SIG_SSDP_DEVICE, when,
                cam_lan_state(recs, nrec, d->ip, when, now), w);
    }
    int rn = s->rtsp_stream_count < MAX_RTSP_STREAMS
           ? s->rtsp_stream_count : MAX_RTSP_STREAMS;
    for (int i = 0; i < rn; i++) {
        const rtsp_stream_t *r = &s->rtsp_streams[i];
        if (!r->anon_ok || !cam_row_is_device_ip(d, r->server)) continue;
        snprintf(w, sizeof(w), "RTSP DESCRIBE answered with no challenge"
                 " on port %u path %.48s (%u time%s)", (unsigned)r->port,
                 r->path, (unsigned)r->anon_ok, r->anon_ok == 1 ? "" : "s");
        add_row(rows, max, &k, CAM_SIG_RTSP_UNAUTH, r->last_seen,
                cam_lan_state(recs, nrec, d->ip, r->last_seen, now), w);
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
