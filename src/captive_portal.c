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
    { "captive.apple.com", "/hotspot-detect.html",
      "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
      200 },
    { "www.msftconnecttest.com", "/connecttest.txt",
      "Microsoft Connect Test", 200 },
    { "detectportal.firefox.com", "/success.txt", "success\n", 200 },
    { "connectivitycheck.gstatic.com", "/generate_204", NULL, 204 },
    { "www.gstatic.com",               "/generate_204", NULL, 204 },
    { "connectivitycheck.android.com", "/generate_204", NULL, 204 },
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

void cp_record(uint8_t kind, const char *host, const char *src,
               const char *evidence, time_t now) {
    if (!kind) return;
    pthread_mutex_lock(&g_mu);
    cp_event_t *e = &g_ev[g_ev_i];
    memset(e, 0, sizeof(*e));
    e->kind = kind;
    snprintf(e->host, sizeof(e->host), "%s", host ? host : "");
    snprintf(e->src,  sizeof(e->src),  "%s", src  ? src  : "");
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
    default:                     return "";
    }
}
