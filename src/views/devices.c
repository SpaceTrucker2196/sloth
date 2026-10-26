#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sloth.h"
#include "tui.h"
#include "views/view_page.h"
#include "views/devices.h"
#include "filter.h"
#include "camera_join.h"
#include "sloth_clock.h"
#include "rf_distance.h"

#define DEV_PAGE 30

static int mac_zero(const uint8_t m[6]) {
    static const uint8_t z[6] = {0};
    return memcmp(m, z, 6) == 0;
}

static void mac_str(const uint8_t mac[6], char *out, int sz) {
    /* An IP-only camera record (#106 round 2) has no link-layer
     * address; printing 00:00:00:00:00:00 would read as one. */
    if (mac_zero(mac)) { snprintf(out, (size_t)sz, "-"); return; }
    snprintf(out, (size_t)sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void sources_str(int s, char out[8]) {
    /* 7 single-letter source flags, dash if unseen. M (mDNS) is
     * reserved for a hostname join; C is a camera-discovery row
     * joined by IP. */
    out[0] = (s & DEV_SRC_ARP)    ? 'A' : '-';
    out[1] = (s & DEV_SRC_DHCP)   ? 'D' : '-';
    out[2] = (s & DEV_SRC_MDNS)   ? 'M' : '-';
    out[3] = (s & DEV_SRC_BEACON) ? 'B' : '-';
    out[4] = (s & DEV_SRC_PROBE)  ? 'P' : '-';
    out[5] = (s & DEV_SRC_STA)    ? 'S' : '-';
    out[6] = (s & DEV_SRC_CAMERA) ? 'C' : '-';
    out[7] = '\0';
}

/* The row type. CAM? is the weaker form: an address block, SERVER
 * token or RTSP_SDP score names a camera, and nothing said "camera".
 * NOTCAM is a mixed-vendor block seen in a router role (#155). */
static const char *class_cell(device_class_t c) {
    switch (c) {
    case DEV_CLASS_CAMERA:        return "CAMERA";
    case DEV_CLASS_CAMERA_VENDOR: return "CAM?";
    case DEV_CLASS_NOT_CAMERA:    return "NOTCAM";
    case DEV_CLASS_UNKNOWN:       break;
    }
    return "-";
}

/* Camera evidence met a router-role veto (#155): the cell says so
 * instead of either verdict, whatever the class field holds. */
static const char *row_class_cell(const device_t *d) {
    return d->cam_conflict ? "CONFL!" : class_cell(d->device_class);
}

static int dev_cols(void) {
#ifdef WITH_NCURSES
    return COLS > 0 ? COLS : 100;
#else
    return 100;
#endif
}

/* Rows left below the cursor. The ANSI build has no screen to run out
 * of, so it is never short. */
static int rows_left(void) {
#ifdef WITH_NCURSES
    return LINES - getcury(stdscr);
#else
    return 1 << 20;
#endif
}

/* ── column plan ───────────────────────────────────────────
 *
 * Fixed: MAC, Class, Src, RSI, Risk, Hits. Flexing: IP, Vendor and
 * Name share whatever the terminal has left, so a 100-column terminal
 * gets a row that does not wrap and a wide one gets whole hostnames
 * and whole IPv6 addresses rather than the same 15 characters. */
#define DEV_FIXED (1 + 17 + 2 + 2 + 6 + 2 + 2 + 2 + 7 + 2 + 4 + 2 + 4 + 2 + 5)

typedef struct { int ip, vendor, name, dist; } dev_plan_t;

static dev_plan_t plan_cols(int cols) {
    dev_plan_t p;
    /* The distance cell is the first thing to give way: at 100 columns
     * the name column's 15 cells are worth more than a signal-strength
     * estimate the detail page also shows. Short form once the 100-column
     * plan still fits beside it, full once the name keeps 24. */
    int base = cols - 1 - DEV_FIXED;
    p.dist = base - 2 - RF_CELL_FULL >= 15 + 8 + 24 ? RF_CELL_FULL
           : base - 2 - RF_CELL_SHORT >= 15 + 9 + 15 ? RF_CELL_SHORT : 0;
    int avail = base - (p.dist ? 2 + p.dist : 0);   /* never the last column */
    if (avail < 24) avail = 24;
    p.ip = 15;
    int rest = avail - p.ip;
    p.vendor = rest * 2 / 5;
    if (p.vendor < 8)  p.vendor = 8;
    if (p.vendor > 24) p.vendor = 24;
    p.name = rest - p.vendor;
    if (p.name > 48) {                   /* room to spare: widen IP to v6 */
        int give = p.name - 48;
        if (give > 39 - p.ip) give = 39 - p.ip;
        p.ip   += give;
        p.name -= give;
    }
    return p;
}

/* The Hits cell is DEV_FIXED's 5: a sixth digit would put the row on
 * the last column and wrap it. k and M keep any int inside five. */
static void hits_cell(int h, char *out, size_t n) {
    if (h < 0) h = 0;
    if (h < 100000)        snprintf(out, n, "%d", h);
    else if (h < 10000000) snprintf(out, n, "%dk", h / 1000);
    else                   snprintf(out, n, "%dM", h / 1000000);
}

static int ascii_iprefix(const char *s, const char *p) {
    for (; *p; s++, p++) {
        char a = *s, b = *p;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return 0;   /* also stops at s's NUL */
    }
    return 1;
}

static void name_cell(const device_t *d, char *out, size_t n) {
    if (d->hostname[0])
        snprintf(out, n, "%s", d->hostname);
    else if (device_class_is_camera(d->device_class) &&
             (d->camera_vendor[0] || d->camera_model[0])) {
        /* ONVIF name scopes usually lead with the maker already. */
        int dup = d->camera_model[0] && d->camera_vendor[0] &&
                  ascii_iprefix(d->camera_model, d->camera_vendor);
        if (dup || !d->camera_vendor[0])
            snprintf(out, n, "%s", d->camera_model);
        else
            snprintf(out, n, "%s%s%s", d->camera_vendor,
                     d->camera_model[0] ? " " : "", d->camera_model);
    }
    else if (d->last_ssid[0])
        snprintf(out, n, "ssid:%s", d->last_ssid);
    else if (d->is_ap)
        snprintf(out, n, "%s", d->setup_mode ? "(camera setup AP)"
                                              : "(access point)");
    else
        snprintf(out, n, "-");
}

static const device_t *detail_device(const sloth_state_t *s) {
    for (int i = 0; i < s->device_count; i++) {
        const device_t *d = &s->devices[i];
        if (!mac_zero(s->device_detail_mac)) {
            if (memcmp(d->mac, s->device_detail_mac, 6) == 0) return d;
        } else if (mac_zero(d->mac) &&
                   strcmp(d->ip, s->device_detail_ip) == 0) {
            return d;
        }
    }
    return NULL;
}

/* ── detail ────────────────────────────────────────────────
 *
 * The screen does not scroll, so every line goes through dl(): it is
 * cut to the terminal width (a wrapped line would push the rest down
 * and off), and once one row is left the remainder is counted instead
 * of drawn and the count is the last thing on the screen. */
typedef struct { int width; int dropped; } dl_t;

static void dl_title(dl_t *b, const char *t) {
    if (rows_left() <= 2) { b->dropped++; return; }
    tui_dim();
    TPRINT(" \xe2\x94\x80\xe2\x94\x80 %s \xe2\x94\x80\xe2\x94\x80\n", t);
}

/* tone: 1 bright, 0 normal, -1 dim. */
#if defined(__GNUC__)
static void dl(dl_t *b, int tone, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
#endif
static void dl(dl_t *b, int tone, const char *fmt, ...) {
    char line[512];
    va_list ap;
    if (rows_left() <= 2) { b->dropped++; return; }
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (tone > 0)      tui_bright();
    else if (tone < 0) tui_dim();
    else               tui_normal();
    TPRINT("%.*s\n", b->width, line);
}

static void age_str(time_t now, time_t t, char *out, size_t n) {
    if (t <= 0)          { snprintf(out, n, "-"); return; }
    long a = (long)(now - t);
    if (a < 0) a = 0;
    if (a < 120)         snprintf(out, n, "%lds ago", a);
    else if (a < 7200)   snprintf(out, n, "%ldm ago", a / 60);
    else if (a < 172800) snprintf(out, n, "%ldh ago", a / 3600);
    else                 snprintf(out, n, "%ldd ago", a / 86400);
}

static int joined(const sloth_state_t *s, const device_t *d, time_t when,
                  time_t now) {
    return cam_lan_state(s->devices, s->device_count, d->ip, when, now)
           == CAM_JOIN_OK;
}

static void draw_device_detail(const sloth_state_t *s) {
    dl_t b = { dev_cols() - 1, 0 };
    if (b.width < 20) b.width = 20;
    const device_t *d = detail_device(s);
    tui_dim();
    TPRINT(" \xe2\x94\x80\xe2\x94\x80 DEVICE DETAIL \xe2\x94\x80\xe2\x94\x80"
           "  [Enter/Esc] back\n");
    if (!d) {
        tui_dim();
        TPRINT("  (device no longer in the table - press Enter to return)\n");
        tui_normal();
        return;
    }
    time_t now = sloth_wall();
    char mac[20]; mac_str(d->mac, mac, sizeof(mac));
    char src[8];  sources_str(d->sources, src);

    dl(&b, 1, "  MAC %s   IP %s   OUI vendor %s   Src %s", mac,
       d->ip[0] ? d->ip : "-", d->vendor[0] ? d->vendor : "?", src);
    if (d->device_class == DEV_CLASS_CAMERA)
        dl(&b, 1, "  Class    camera - the device named its own class;"
           " corroborated, not confirmed");
    else if (d->device_class == DEV_CLASS_CAMERA_VENDOR &&
             (d->cam_evidence & CAM_EV_RTSP_SDP) &&
             (d->cam_evidence & CAM_EV_MIXED_OUI))
        dl(&b, 1, "  Class    camera-vendor - mixed-vendor block that served"
           " an RTSP SDP; class not observed");
    else if (d->device_class == DEV_CLASS_CAMERA_VENDOR)
        dl(&b, 1, "  Class    camera-vendor - an address block or SERVER"
           " token names a camera maker; class not observed");
    else if (d->device_class == DEV_CLASS_NOT_CAMERA)
        dl(&b, 1, "  Class    not-camera - mixed-vendor block seen in a"
           " router role; not confirmed");
    else
        dl(&b, 0, "  Class    -");
    if (d->cam_conflict)
        dl(&b, 1, "  CONFLICT camera evidence and a router-role veto both"
           " stand; not resolved - see EVIDENCE");
    if (d->cam_evidence || d->cam_vetoes)
        dl(&b, 0, "  Score    %d (class from behaviour needs >= %d with"
           " rtsp_sdp, on a mixed-vendor block)", d->cam_score,
           CAM_CLASS_MIN_SCORE);
    /* A mixed-vendor block names the maker of routers and plugs as
     * much as cameras (#155), so on a record no class calls a camera
     * the name is not shown as a camera vendor. */
    if (d->camera_vendor[0] && !device_class_is_camera(d->device_class) &&
        (d->cam_evidence & CAM_EV_MIXED_OUI))
        dl(&b, 0, "  Vendor   %s (mixed-vendor block; not a camera claim)",
           d->camera_vendor);
    else if (d->camera_vendor[0] || d->camera_model[0])
        dl(&b, 0, "  Camera   vendor %s   model %s",
           d->camera_vendor[0] ? d->camera_vendor : "-",
           d->camera_model[0]  ? d->camera_model  : "-");
    if (d->setup_mode)
        dl(&b, 0, "  Setup    advertises a camera vendor's documented setup"
           " SSID (provisioning state not observed)");
    {
        static const char *const tag[CAM_SIG_COUNT] =
            { "WSD", "SSID", "MDNS", "SSDP", "OUI", "RTSP" };
        char sig[64]; int o = 0;
        for (int i = 0; i < CAM_SIG_COUNT; i++)
            o += snprintf(sig + o, sizeof(sig) - (size_t)o, "%s%s",
                          i ? " " : "",
                          (d->cam_signal_mask & (1 << i)) ? tag[i] : "-");
        dl(&b, 0, "  Signals  %s", sig);
    }
    if (mac_zero(d->mac))
        dl(&b, 0, "  Keyed by IP only: no link-layer address was seen for"
           " this camera");
    if (d->dist.valid) {
        char dd[96];
        rf_dist_describe(&d->dist, dd, sizeof(dd));
        dl(&b, 0, "  Distance %s - from signal strength, not a location", dd);
    }

    {
        cam_reason_t why[12];
        int wn = camera_reasons(s, s->devices, s->device_count, d, now,
                                why, 12);
        if (wn > 0) {
            dl_title(&b, "EVIDENCE / VETOES");
            dl(&b, -1, "  %-13s %-4s %-9s %s", "KIND", "PTS", "SEEN", "WHAT");
        }
        for (int i = 0; i < wn; i++) {
            char age[32], pts[8];
            age_str(now, why[i].when, age, sizeof(age));
            if (why[i].veto) snprintf(pts, sizeof(pts), "veto");
            else snprintf(pts, sizeof(pts), "+%d",
                          cam_evidence_weight(why[i].bit));
            dl(&b, why[i].veto ? 1 : 0, "  %-13s %-4s %-9s %s",
               why[i].veto ? cam_veto_slug(why[i].bit)
                           : cam_evidence_slug(why[i].bit),
               pts, age, why[i].what);
        }
    }
    if (d->dhcp_prl[0] || d->dhcp_vci[0]) {
        dl_title(&b, "DHCP OPTIONS (evidence only, not scored)");
        if (d->dhcp_prl[0]) dl(&b, 0, "  55 PRL  %s", d->dhcp_prl);
        if (d->dhcp_vci[0]) dl(&b, 0, "  60 VCI  %s", d->dhcp_vci);
    }

    cam_trail_row_t trail[24];
    int tn = camera_trail(s, d, now, trail, 24);
    if (tn > 0) {
        dl_title(&b, "SIGNAL TRAIL");
        dl(&b, -1, "  %-17s %-9s %s", "RULE", "SEEN", "WHAT");
        for (int i = 0; i < tn; i++) {
            int si = 0;
            while (si < CAM_SIG_COUNT && trail[i].sig != (1 << si)) si++;
            const char *rule = alert_type_name(cam_signal_alert(si));
            if (strncmp(rule, "ALERT_TYPE_", 11) == 0) rule += 11;
            char age[32]; age_str(now, trail[i].when, age, sizeof(age));
            dl(&b, 0, "  %-17s %-9s %s", rule, age, trail[i].what);
        }
    }

    /* The source sections show only rows the join counted: a stale or
     * ambiguous row is on the trail as history, and its scopes or
     * SERVER line under this record would read as this device's. */
    if (d->ip[0]) {
        int hdr = 0;
        time_t when = 0;
        for (int i = 0; i < s->onvif_count; i++) {
            const onvif_device_t *o = &s->onvif_devices[i];
            if (!o->is_camera || !cam_onvif_addr_of(o, d, &when) ||
                !joined(s, d, when, now))
                continue;
            if (!hdr++) dl_title(&b, "ONVIF SCOPES");
            const char *p = o->scopes;
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                const char *e = p;
                while (*e && *e != ' ') e++;
                dl(&b, 0, "  %.*s", (int)(e - p), p);
                p = e;
            }
            if (o->xaddrs[0]) dl(&b, 0, "  XAddrs %s", o->xaddrs);
        }

        hdr = 0;
        for (int i = 0; i < s->mdns_count; i++) {
            const mdns_service_t *e = &s->mdns_services[i];
            if (!cam_row_is_device_ip(d, e->ip) ||
                !joined(s, d, e->last_seen, now))
                continue;
            if (!hdr++) dl_title(&b, "mDNS");
            dl(&b, 0, "  instance %s   %s   host %s:%u", e->instance,
               e->service, e->host[0] ? e->host : "-", (unsigned)e->port);
        }

        hdr = 0;
        for (int i = 0; i < s->ssdp_count && i < MAX_SSDP_DEVICES; i++) {
            const ssdp_device_t *e = &s->ssdp_devices[i];
            if (!e->server[0] || !cam_ssdp_addr_of(e, d, &when) ||
                !joined(s, d, when, now))
                continue;
            int dup = 0;
            for (int j = 0; j < i && !dup; j++) {
                time_t wj = 0;
                dup = cam_ssdp_addr_of(&s->ssdp_devices[j], d, &wj) &&
                      joined(s, d, wj, now) &&
                      strcmp(s->ssdp_devices[j].server, e->server) == 0;
            }
            if (dup) continue;
            if (!hdr++) dl_title(&b, "SSDP");
            dl(&b, 0, "  SERVER %s", e->server);
        }

        hdr = 0;
        int rn = s->rtsp_stream_count < MAX_RTSP_STREAMS
               ? s->rtsp_stream_count : MAX_RTSP_STREAMS;
        for (int i = 0; i < rn; i++) {
            const rtsp_stream_t *r = &s->rtsp_streams[i];
            if (!cam_row_is_device_ip(d, r->server) ||
                !joined(s, d, r->last_seen, now))
                continue;
            if (!hdr++) {
                dl_title(&b, "RTSP EXPOSURE");
                dl(&b, -1, "  %-5s %5s %5s %5s  %-8s %s", "PORT", "ANON",
                   "AUTH", "401", "SCHEME", "PATH");
            }
            dl(&b, r->anon_ok ? 1 : 0, "  %-5u %5u %5u %5u  %-8s %s",
               (unsigned)r->port, (unsigned)r->anon_ok,
               (unsigned)r->auth_ok, (unsigned)r->challenged,
               r->auth_scheme[0] ? r->auth_scheme : "-", r->path);
        }
    }

    if (b.dropped) {
        tui_dim();
        TPRINT("  ... %d more line%s (screen full)\n", b.dropped,
               b.dropped == 1 ? "" : "s");
    }
    tui_normal();
}

/* ── list ──────────────────────────────────────────────── */

void view_devices_draw(const sloth_state_t *s) {
    if (s->device_detail) { draw_device_detail(s); return; }

    int cams = 0;
    for (int i = 0; i < s->device_count; i++)
        if (device_class_is_camera(s->devices[i].device_class)) cams++;

    tui_normal(); TPRINT(" Devices: ");
    tui_bright();  TPRINT("%d", s->device_count);
    tui_normal(); TPRINT("  cameras: ");
    if (cams) tui_heat(0.5); else tui_dim();
    TPRINT("%d", cams);
    tui_dim();     TPRINT("  [up/dn] navigate  [Enter] detail  (newest first)");
    tui_filter_status(s);
    TPRINT("\n");

    dev_plan_t w = plan_cols(dev_cols());
    tui_clip_rows(1);   /* the table only: lines above it wrap */
    tui_dim();
    TPRINT(" %-17s  %-*s  %-6s  %-*.*s  %-*.*s  %-7s  %-4s",
           "MAC", w.ip, "IP", "Class", w.vendor, w.vendor, "Vendor",
           w.name, w.name, "Hostname / SSID / Model", "Src", "RSI");
    if (w.dist)
        TPRINT("  %-*s", w.dist, w.dist >= RF_CELL_FULL ? "Dist (est)" : "~m");
    TPRINT("  %-4s  %-5s\n", "Risk", "Hits");
    tui_normal();

    if (s->device_count == 0) {
        tui_dim();
        TPRINT("  (no devices seen yet)\n");
        tui_normal();
        return;
    }

    /* Nothing is drawn under the table. This was rows_left() - 1, which
     * left the screen's last row empty under a full page (#150). */
    int page = view_page_budget(VIEW_NO_TAIL, DEV_PAGE);

    int page_top = s->device_sel - page / 2;
    if (page_top + page > s->device_count) page_top = s->device_count - page;
    if (page_top < 0) page_top = 0;
    int page_end = page_top + page;
    if (page_end > s->device_count) page_end = s->device_count;

    for (int row = page_top; row < page_end; row++) {
        const device_t *d = &s->devices[row];
        char mac[20]; mac_str(d->mac, mac, sizeof(mac));
        if (s->filter[0] &&
            !filter_match_any(s->filter, mac, d->ip, d->vendor,
                              d->hostname, d->last_ssid) &&
            !filter_match_any(s->filter, d->camera_vendor, d->camera_model,
                              row_class_cell(d),
                              device_class_label(d->device_class),
                              d->cam_conflict ? "conflict" : ""))
            continue;
        char src[8];  sources_str(d->sources, src);
        char name[96]; name_cell(d, name, sizeof(name));
        const char *vend = d->vendor[0] ? d->vendor
                         : d->camera_vendor[0] ? d->camera_vendor : "?";
        const char *cls = row_class_cell(d);

        char sig[8];
        if (d->signal_dbm < 0) snprintf(sig, sizeof(sig), "%d", d->signal_dbm);
        else                   snprintf(sig, sizeof(sig), "-");
        char dist[48] = "";
        if (w.dist) {
            dist[0] = ' '; dist[1] = ' ';
            rf_dist_cell(&d->dist, dist + 2, sizeof(dist) - 2, w.dist);
        }

        char hits_s[12]; hits_cell(d->probe_count, hits_s, sizeof(hits_s));
        int hits = d->probe_count;

        const char *risk = device_risk_label(d->risk_level);
        double      risk_heat =
            d->risk_level == DEV_RISK_CRIT ? 1.0 :
            d->risk_level == DEV_RISK_HIGH ? 0.7 :
            d->risk_level == DEV_RISK_MED  ? 0.4 : 0.0;

        if (row == s->device_sel) {
            tui_sel();
            TPRINT(" %-17s  %-*.*s  %-6s  %-*.*s  %-*.*s  %-7s  %-4s%s  %-4s  %-5s\n",
                   mac, w.ip, w.ip, d->ip[0] ? d->ip : "-", cls,
                   w.vendor, w.vendor, vend, w.name, w.name, name,
                   src, sig, dist, risk, hits_s);
            tui_reset();
        } else {
            tui_dim();    TPRINT(" %-17s", mac);
            tui_normal(); TPRINT("  %-*.*s", w.ip, w.ip, d->ip[0] ? d->ip : "-");

            if (d->cam_conflict)                             tui_heat(0.7);
            else if (d->device_class == DEV_CLASS_CAMERA)    tui_heat(0.5);
            else if (d->device_class != DEV_CLASS_UNKNOWN)   tui_normal();
            else                                             tui_dim();
            TPRINT("  %-6s", cls);

            if (d->vendor[0] || d->camera_vendor[0]) tui_bright(); else tui_dim();
            TPRINT("  %-*.*s", w.vendor, w.vendor, vend);

            if (d->is_ap)             tui_heat(0.7);
            else if (d->hostname[0])  tui_bright();
            else                      tui_normal();
            TPRINT("  %-*.*s", w.name, w.name, name);

            tui_dim();    TPRINT("  %-7s", src);
            tui_dim();    TPRINT("  %-4s", sig);
            tui_dim();    TPRINT("%s", dist);

            /* Risk bucket: heat-graded per level so HIGH/CRIT jump out
             * at operator glance. LOW renders dim to stay quiet. */
            if (risk_heat > 0.0) tui_heat(risk_heat); else tui_dim();
            TPRINT("  %-4s", risk);

            if (hits > 0) tui_heat(0.5); else tui_dim();
            TPRINT("  %-5s\n", hits_s);
            tui_normal();
        }
    }
    tui_normal();
}

void view_devices_key(sloth_state_t *s, int key) {
    /* Detail swallows navigation; Enter or Esc returns. */
    if (s->device_detail) {
        if (key == '\r' || key == '\n' || key == 27) s->device_detail = 0;
        return;
    }
    switch (key) {
    case SLOTH_KEY_UP:
        if (s->device_sel > 0) s->device_sel--;
        break;
    case SLOTH_KEY_DOWN:
        if (s->device_count > 0 && s->device_sel < s->device_count - 1)
            s->device_sel++;
        break;
    case '\r': case '\n':
        if (s->device_sel >= 0 && s->device_sel < s->device_count) {
            const device_t *d = &s->devices[s->device_sel];
            memcpy(s->device_detail_mac, d->mac, 6);
            snprintf(s->device_detail_ip, sizeof(s->device_detail_ip),
                     "%s", d->ip);
            s->device_detail = 1;
        }
        break;
    default:
        break;
    }
}
