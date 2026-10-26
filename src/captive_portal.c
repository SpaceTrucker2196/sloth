#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "captive_portal.h"

/* ── The sentinel table ────────────────────────────────────
 *
 * These are published, fixed values. Unlike the tool fingerprints in
 * #68 they can be written down from documentation, which is why this
 * table ships full and that one ships empty.
 *
 * `expect_body` NULL means the sentinel is a status code rather than a
 * body — Google's check is an empty 204, and a body of any length is
 * itself the interception. */
typedef struct {
    const char *host;
    const char *path;
    const char *expect_body;
    uint16_t    expect_status;
} cp_sentinel_t;

static const cp_sentinel_t SENTINELS[] = {
    /* 69 bytes: the page ends in one LF, and the comparison is exact,
     * so a table without it read every genuine answer as a hijack.
     * Bytes as served on 2026-10-26, in
     * research/tools/connectivity-check-sentinels.md. */
    { "captive.apple.com", "/hotspot-detect.html",
      "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>\n",
      200 },
    { "www.msftconnecttest.com", "/connecttest.txt",
      "Microsoft Connect Test", 200 },
    /* NCSI probes IPv4 and IPv6 in parallel (Microsoft, "Overview of
     * NCSI"); the v6 probe has its own host, listed under NCSI in
     * Microsoft's Windows 11 endpoint list, and answers with the same
     * file. The legacy v6 host answers with ncsi.txt's. Not
     * dns.msftncsi.com: its expected answer is a ULA, which the
     * private-space DNS check would call a spoof. */
    { "ipv6.msftconnecttest.com", "/connecttest.txt",
      "Microsoft Connect Test", 200 },
    { "ipv6.msftncsi.com", "/ncsi.txt", "Microsoft NCSI", 200 },
    { "detectportal.firefox.com", "/success.txt", "success\n", 200 },
    /* What Firefox's captive-portal service actually fetches up to ESR
     * 140: captivedetect.canonicalURL, answered with
     * captivedetect.canonicalContent (90 bytes, no trailing LF). */
    { "detectportal.firefox.com", "/canonical.html",
      "<meta http-equiv=\"refresh\" "
      "content=\"0;url=https://support.mozilla.org/kb/captive-portal\"/>",
      200 },
    /* Firefox release since the move off detectportal: the same two
     * prefs now name an empty 204, and the connectivity service the
     * same success.txt on a new host. */
    { "firefox-portal-detection.com", "/generate_204", NULL, 204 },
    { "firefox-portal-detection.com", "/success.txt", "success\n", 200 },
    { "connectivitycheck.gstatic.com", "/generate_204", NULL, 204 },
    { "www.gstatic.com",               "/generate_204", NULL, 204 },
    { "connectivitycheck.android.com", "/generate_204", NULL, 204 },
    /* #169. Windows 8.1 and earlier: "NCSI sends a plain HTTP GET
     * request to http://www.msftncsi.com/ncsi.txt ... makes sure that
     * the file contains Microsoft NCSI" (Microsoft KB 4494446). */
    { "www.msftncsi.com", "/ncsi.txt", "Microsoft NCSI", 200 },
    /* #169. AOSP NetworkMonitor's DEFAULT_SERVER before the move to
     * connectivitycheck.gstatic.com (android-5.0.0_r1), and one of the
     * Google hosts fluxion's lighttpd config answers for. */
    { "clients3.google.com",           "/generate_204", NULL, 204 },
};

#define N_SENTINELS ((int)(sizeof(SENTINELS) / sizeof(SENTINELS[0])))

static cp_event_t      g_ev[CP_MAX_EVENTS];
static int             g_ev_i;
static int             g_ev_n;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static int host_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    for (;; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
        if (!x) return 1;
    }
}

int cp_is_sentinel_host(const char *host) {
    if (!host || !host[0]) return 0;
    for (int i = 0; i < N_SENTINELS; i++)
        if (host_eq(SENTINELS[i].host, host)) return 1;
    return 0;
}

static const cp_sentinel_t *sentinel_for(const char *host, const char *path) {
    if (!host || !path) return NULL;
    for (int i = 0; i < N_SENTINELS; i++) {
        if (!host_eq(SENTINELS[i].host, host)) continue;
        /* Path compared as a prefix: some clients append a cache-buster
         * query. The host is the strong half of the identity. */
        size_t plen = strlen(SENTINELS[i].path);
        if (strncmp(path, SENTINELS[i].path, plen) == 0)
            return &SENTINELS[i];
    }
    return NULL;
}

int cp_check_response(const http_log_entry_t *resp) {
    if (!resp || !resp->is_response) return 0;
    const cp_sentinel_t *s = sentinel_for(resp->host, resp->path);
    if (!s) return 0;

    /* The gate this detector rests on (#71). sloth does not reassemble
     * TCP, so a body we did not see whole cannot be compared: a prefix
     * that differs from the sentinel is not evidence of interception,
     * it is evidence of a segment boundary. Chunked responses are never
     * complete, so a rogue that chunks its answer evades this check —
     * and does not evade cp_check_dns or cp_check_tls. */
    if (!resp->body_complete) return 0;

    if (s->expect_body == NULL) {
        /* A status-code sentinel. Anything other than the expected
         * status, or any body at all, is the interception — a 204 that
         * arrives with content is not a 204. */
        if (resp->status != s->expect_status) return CP_KIND_HIJACK;
        if (resp->resp_body_len > 0)          return CP_KIND_HIJACK;
        return 0;
    }

    if (resp->status != s->expect_status) return CP_KIND_HIJACK;

    int elen = (int)strlen(s->expect_body);
    if (resp->resp_body_len != elen) return CP_KIND_HIJACK;
    if (memcmp(resp->resp_body, s->expect_body, (size_t)elen) != 0)
        return CP_KIND_HIJACK;
    return 0;
}

/* Private and carrier-grade-NAT space. A public sentinel resolving here
 * is being answered by something on the local network. */
static int ip_is_private_v4(const char *ip) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    if (a == 10) return 1;
    if (a == 192 && b == 168) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 169 && b == 254) return 1;          /* link-local */
    if (a == 127) return 1;
    if (a == 100 && b >= 64 && b <= 127) return 1;   /* CGNAT 100.64/10 */
    if (a == 0) return 1;
    return 0;
}

static int ip_is_private(const char *ip) {
    if (!ip || !ip[0]) return 0;
    if (strchr(ip, ':')) {
        /* IPv6: unique-local (fc00::/7) and link-local (fe80::/10). */
        if (ip[0] == 'f' || ip[0] == 'F') {
            char c1 = ip[1];
            if (c1 == 'c' || c1 == 'd' || c1 == 'C' || c1 == 'D') return 1;
            if ((c1 == 'e' || c1 == 'E') &&
                (ip[2] == '8' || ip[2] == '9' ||
                 ip[2] == 'a' || ip[2] == 'b' ||
                 ip[2] == 'A' || ip[2] == 'B')) return 1;
        }
        if (strcmp(ip, "::1") == 0) return 1;
        return 0;
    }
    return ip_is_private_v4(ip);
}

/* The networks each sentinel is known to live in. Deliberately coarse:
 * these are large operators whose exact addressing changes, so the list
 * is a sanity check rather than an allow-list to alert on. A public
 * address outside it is UNEXPECTED, never SPOOF — being wrong about
 * Apple's current CDN range must not produce a CRIT. */
static int ip_in_known_range(const char *host, const char *ip) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 1;  /* v6: no opinion */
    if (host_eq(host, "captive.apple.com")) return a == 17;
    /* Google and Microsoft addressing is spread across many ranges and
     * changes often enough that asserting one would produce noise.
     * Returning "known" means only the private-space test applies. */
    return 1;
}

int cp_check_dns(const char *qname, const char *answer) {
    if (!cp_is_sentinel_host(qname)) return 0;
    if (!answer || !answer[0]) return 0;
    /* NXDOMAIN and friends arrive as text in the answer field; they are
     * not addresses and say nothing about interception. */
    if (!strchr(answer, '.') && !strchr(answer, ':')) return 0;

    if (ip_is_private(answer)) return CP_KIND_DNS_SPOOF;
    if (!ip_in_known_range(qname, answer)) return CP_KIND_DNS_UNEXPECTED;
    return 0;
}

int cp_check_tls(const char *sni, const char *dst_ip) {
    if (!cp_is_sentinel_host(sni)) return 0;
    if (!ip_is_private(dst_ip)) return 0;
    return CP_KIND_TLS_MITM;
}

/* ── Attack-kit portal fingerprints (#169) ──────────────────
 *
 * Every needle below is a literal from the kit's public source at the
 * commit research/tools/captive-portal-kits.md pins, quoted there with
 * its file. No needle is inferred from a capture. */
enum { KN_END = 0, KN_STATUS, KN_HDR, KN_BODY };

typedef struct {
    uint8_t     where;
    const char *s;     /* KN_STATUS "307"; KN_HDR "name:value-prefix" */
} kit_needle_t;

#define KIT_NEEDLES 3

typedef struct {
    uint8_t      kit;
    const char  *label;
    kit_needle_t n[KIT_NEEDLES];
} kit_row_t;

static const kit_row_t KITS[] = {
    /* wifiphisher answers every GET through one Tornado handler
     * (phishinghttp.py, `(r"/.*", CaptivePortalHandler)`), and
     * Tornado's RequestHandler.clear() sets "Server: TornadoServer/%s".
     * The banner alone is any Tornado app; each row pairs it with that
     * scenario's own index.html. */
    { CP_KIT_WIFIPHISHER, "wifiphisher firmware-upgrade",
      { { KN_HDR,  "server:TornadoServer/" },
        { KN_BODY, "<title>Router Configuration Page</title>" } } },
    { CP_KIT_WIFIPHISHER, "wifiphisher oauth-login",
      { { KN_HDR,  "server:TornadoServer/" },
        { KN_BODY, "codepen.io/andytran/pen/PwoQgO" } } },
    { CP_KIT_WIFIPHISHER, "wifiphisher plugin_update",
      { { KN_HDR,  "server:TornadoServer/" },
        { KN_BODY, "<title>Plugin Manager</title>" } } },
    { CP_KIT_WIFIPHISHER, "wifiphisher wifi_connect",
      { { KN_HDR,  "server:TornadoServer/" },
        { KN_BODY, "(C) viazenetti GmbH (Christian Ludwig)" } } },
    /* The Pineapple's Evil Portal skeleton/index.php, uncustomised. */
    { CP_KIT_EVILPORTAL, "pineapple evil-portal default",
      { { KN_BODY, "<title>Evil Portal</title>" },
        { KN_BODY, "This is the default Evil Portal page." } } },
    /* PortalAuth clones a real portal and appends an injection set's
     * CSS and JS to its <head>; all three non-blank sets carry both. */
    { CP_KIT_PORTALAUTH, "pineapple portalauth injection",
      { { KN_BODY, "#pa_overlay-back {" },
        { KN_BODY, "/captiveportal/index.php" } } },
    /* airgeddon set_captive_portal_page(): the generated index.htm. */
    { CP_KIT_AIRGEDDON, "airgeddon captive portal",
      { { KN_BODY, "<link rel=\"stylesheet\" type=\"text/css\" href=\"portal.css\"/>" },
        { KN_BODY, "<form method=\"post\" id=\"loginform\" name=\"loginform\" action=\"check.htm\">" } } },
    /* fluxion's default ("disconnected") lighttpd config: every host
     * but its own is answered 307 to http://captive.gateway.lan/. */
    { CP_KIT_FLUXION, "fluxion redirect",
      { { KN_STATUS, "307" },
        { KN_HDR,    "location:http://captive.gateway.lan/" } } },
    /* fluxion's "emulated" connectivity mode serves its own
     * hotspot-detect.html, which is not Apple's: it carries a browser
     * add-on's injected script from wherever the page was saved. */
    { CP_KIT_FLUXION, "fluxion emulated apple check",
      { { KN_BODY, "window[\"_gaUserPrefs\"] = { ioo : function() { return true; } }" },
        { KN_BODY, "<title>Success</title>" } } },
    { CP_KIT_FLUXION, "fluxion login page",
      { { KN_BODY, "<title>Wireless Protected Access: Login</title>" },
        { KN_BODY, "jquery.mobile-1.4.5.min.css" } } },
};

#define N_KITS ((int)(sizeof(KITS) / sizeof(KITS[0])))

/* Bounded substring search; memmem is a GNU extension. */
static int has_bytes(const char *h, int hlen, const char *n) {
    int nlen = (int)strlen(n);
    if (nlen == 0 || hlen < nlen) return 0;
    for (int i = 0; i + nlen <= hlen; i++)
        if (h[i] == n[0] && memcmp(h + i, n, (size_t)nlen) == 0) return 1;
    return 0;
}

static char lc(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

/* One header line "Name: value" against "name:value-prefix". The name
 * is case-insensitive (RFC 9110 §5.1); the value prefix is not, since
 * the kit writes it one way and that spelling is the fingerprint. */
static int hdr_has(const char *h, int hlen, const char *want) {
    const char *colon = strchr(want, ':');
    if (!colon) return 0;
    int wn = (int)(colon - want);
    const char *wv = colon + 1;
    int wvl = (int)strlen(wv);
    int i = 0;
    while (i < hlen && h[i] != '\n') i++;      /* the status line */
    while (i < hlen) {
        i++;                                   /* past the '\n' */
        int ls = i;
        while (i < hlen && h[i] != '\n') i++;
        int le = i;                            /* exclusive */
        if (le > ls && h[le - 1] == '\r') le--;
        if (le - ls <= wn || h[ls + wn] != ':') continue;
        int ok = 1;
        for (int k = 0; k < wn; k++)
            if (lc(h[ls + k]) != want[k]) { ok = 0; break; }
        if (!ok) continue;
        int v = ls + wn + 1;
        while (v < le && (h[v] == ' ' || h[v] == '\t')) v++;
        if (le - v >= wvl && memcmp(h + v, wv, (size_t)wvl) == 0) return 1;
    }
    return 0;
}

int cp_match_kit(const uint8_t *seg, int len, const char **label) {
    if (label) *label = "";
    if (!seg || len < 12) return 0;
    const char *p = (const char *)seg;
    if (memcmp(p, "HTTP/1.", 7) != 0) return 0;
    if (p[7] != '0' && p[7] != '1') return 0;
    if (p[8] != ' ') return 0;
    for (int i = 9; i < 12; i++)
        if (p[i] < '0' || p[i] > '9') return 0;

    /* The header block ends at the first blank line. A segment without
     * one is headers only, and has no body to search. */
    int hlen = len, boff = len;
    for (int i = 0; i + 1 < len; i++) {
        if (p[i] == '\n' && p[i + 1] == '\n') { hlen = i; boff = i + 2; break; }
        if (i + 3 < len && p[i] == '\r' && p[i + 1] == '\n' &&
            p[i + 2] == '\r' && p[i + 3] == '\n') { hlen = i; boff = i + 4; break; }
    }
    const char *body = p + boff;
    int blen = len - boff;

    for (int r = 0; r < N_KITS; r++) {
        const kit_row_t *row = &KITS[r];
        int ok = 1, any = 0;
        for (int k = 0; k < KIT_NEEDLES && ok; k++) {
            const kit_needle_t *n = &row->n[k];
            if (n->where == KN_END) break;
            any = 1;
            if (n->where == KN_STATUS)    ok = (memcmp(p + 9, n->s, 3) == 0);
            else if (n->where == KN_HDR)  ok = hdr_has(p, hlen, n->s);
            else                          ok = has_bytes(body, blen, n->s);
        }
        if (ok && any) {
            if (label) *label = row->label;
            return row->kit;
        }
    }
    return 0;
}

const char *cp_kit_name(uint8_t kit) {
    switch (kit) {
    case CP_KIT_WIFIPHISHER: return "wifiphisher";
    case CP_KIT_EVILPORTAL:  return "pineapple-evilportal";
    case CP_KIT_PORTALAUTH:  return "pineapple-portalauth";
    case CP_KIT_AIRGEDDON:   return "airgeddon";
    case CP_KIT_FLUXION:     return "fluxion";
    default:                 return "";
    }
}

void cp_record(uint8_t kind, const char *host, const char *src,
               const char *evidence, time_t now) {
    cp_record_ex(kind, 0, host, src, NULL, 0, evidence, now);
}

void cp_record_ex(uint8_t kind, uint8_t kit, const char *host,
                  const char *src, const char *server,
                  uint16_t server_port, const char *evidence, time_t now) {
    if (!kind) return;
    pthread_mutex_lock(&g_mu);
    /* A kit answers every URL with its page (fluxion's 307 is every
     * host a victim's phone touches), so one kit, server and client
     * would otherwise fill the 64-slot ring and evict the probe events
     * it exists to escalate. The repeat refreshes the one slot. */
    if (kind == CP_KIND_KIT) {
        for (int i = 0; i < g_ev_n; i++) {
            cp_event_t *o = &g_ev[i];
            if (o->kind != CP_KIND_KIT || o->kit != kit) continue;
            if (strcmp(o->server, server ? server : "") != 0) continue;
            if (strcmp(o->src, src ? src : "") != 0) continue;
            snprintf(o->host, sizeof(o->host), "%s", host ? host : "");
            if (evidence)
                snprintf(o->evidence, sizeof(o->evidence), "%s", evidence);
            o->server_port = server_port;
            o->ts = now;
            pthread_mutex_unlock(&g_mu);
            return;
        }
    }
    cp_event_t *e = &g_ev[g_ev_i];
    memset(e, 0, sizeof(*e));
    e->kind = kind;
    e->kit  = kit;
    snprintf(e->host,   sizeof(e->host),   "%s", host   ? host   : "");
    snprintf(e->src,    sizeof(e->src),    "%s", src    ? src    : "");
    snprintf(e->server, sizeof(e->server), "%s", server ? server : "");
    e->server_port = server_port;
    if (evidence) snprintf(e->evidence, sizeof(e->evidence), "%s", evidence);
    e->ts = now;
    g_ev_i = (g_ev_i + 1) % CP_MAX_EVENTS;
    if (g_ev_n < CP_MAX_EVENTS) g_ev_n++;
    pthread_mutex_unlock(&g_mu);
}

void cp_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    int n = g_ev_n;
    for (int k = 0; k < n; k++) {
        int idx = (g_ev_i - 1 - k + CP_MAX_EVENTS * 2) % CP_MAX_EVENTS;
        s->cp_events[k] = g_ev[idx];
    }
    s->cp_event_count = n;
    pthread_mutex_unlock(&g_mu);
}

int cp_event_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_ev_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void cp_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_ev, 0, sizeof(g_ev));
    g_ev_i = 0;
    g_ev_n = 0;
    pthread_mutex_unlock(&g_mu);
}

const char *cp_kind_label(uint8_t kind) {
    switch (kind) {
    case CP_KIND_HIJACK:         return "portal answered the check";
    case CP_KIND_DNS_SPOOF:      return "DNS answer is local";
    case CP_KIND_DNS_UNEXPECTED: return "DNS answer outside known range";
    case CP_KIND_TLS_MITM:       return "TLS terminated locally";
    case CP_KIND_KIT:            return "attack-kit portal page";
    default:                     return "";
    }
}
