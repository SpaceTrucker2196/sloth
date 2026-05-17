#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <pthread.h>

#include "sloth.h"
#include "ssdp_snoop.h"

/* ── Internal table ──────────────────────────────────────── */

static ssdp_device_t   g_devs[MAX_SSDP_DEVICES];
static int             g_count = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── Header parsing ──────────────────────────────────────── */

/* Extract a header value from an SSDP payload into out[outsz].
 * Skips the request line, then scans subsequent lines case-insensitively.
 * Returns 1 on success, 0 if the header is not present. */
static int get_hdr(const char *data, int len, const char *name,
                   char *out, int outsz) {
    const char *p = (const char *)memchr(data, '\n', (size_t)len);
    if (!p) return 0;
    p++;
    int rem = len - (int)(p - data);
    int nlen = (int)strlen(name);

    while (rem > 0) {
        if (*p == '\r' || *p == '\n') break;
        const char *eol = (const char *)memchr(p, '\n', (size_t)rem);
        int llen = eol ? (int)(eol - p) : rem;
        int vlen = llen;
        if (vlen > 0 && p[vlen - 1] == '\r') vlen--;

        if (vlen > nlen &&
            strncasecmp(p, name, (size_t)nlen) == 0 &&
            p[nlen] == ':') {
            const char *val = p + nlen + 1;
            vlen -= nlen + 1;
            while (vlen > 0 && (*val == ' ' || *val == '\t')) { val++; vlen--; }
            while (vlen > 0 && (val[vlen-1] == ' ' || val[vlen-1] == '\t')) vlen--;
            if (vlen >= outsz) vlen = outsz - 1;
            memcpy(out, val, (size_t)vlen);
            out[vlen] = '\0';
            return 1;
        }
        if (!eol) break;
        rem -= llen + 1;
        p    = eol + 1;
    }
    return 0;
}

/* ── Type shortener ──────────────────────────────────────── */

/* For a URN like "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
 * return a pointer to "InternetGatewayDevice:1".
 * For "upnp:rootdevice" return "rootdevice".
 * For "ssdp:all" return "all".
 * Falls back to the full string if structure is unexpected. */
static const char *short_type(const char *nt) {
    /* find the second-to-last colon */
    const char *last  = strrchr(nt, ':');
    if (!last) return nt;
    if (last == nt) return nt + 1;
    /* walk backwards to find the colon before last */
    const char *prev = last - 1;
    while (prev > nt && *prev != ':') prev--;
    if (*prev == ':') return prev + 1;
    return nt;
}

/* ── Table helpers ───────────────────────────────────────── */

static ssdp_device_t *find_or_create(const char *usn, const char *ip,
                                     const char *type) {
    /* Prefer USN as key if non-empty */
    if (usn[0]) {
        for (int i = 0; i < g_count; i++)
            if (strcmp(g_devs[i].usn, usn) == 0) return &g_devs[i];
    } else {
        /* Fall back to ip+type */
        for (int i = 0; i < g_count; i++)
            if (strcmp(g_devs[i].ip, ip) == 0 &&
                strcmp(g_devs[i].type, type) == 0) return &g_devs[i];
    }

    if (g_count >= MAX_SSDP_DEVICES) {
        /* evict oldest */
        int oldest = 0;
        for (int i = 1; i < g_count; i++)
            if (g_devs[i].last_seen < g_devs[oldest].last_seen) oldest = i;
        memset(&g_devs[oldest], 0, sizeof(g_devs[oldest]));
        return &g_devs[oldest];
    }
    ssdp_device_t *e = &g_devs[g_count++];
    memset(e, 0, sizeof(*e));
    return e;
}

/* ── Public API ──────────────────────────────────────────── */

int ssdp_snoop(const char *src_ip, const uint8_t *data, int len,
               char *info, int infosz) {
    if (len < 10) return 0;
    const char *msg = (const char *)data;

    int is_notify   = (strncasecmp(msg, "NOTIFY ",   7) == 0);
    int is_msearch  = (strncasecmp(msg, "M-SEARCH ", 9) == 0);
    if (!is_notify && !is_msearch) return 0;

    char nt[80]  = ""; char nts[32]  = ""; char usn[96] = "";
    char loc[96] = ""; char st[80]   = "";
    get_hdr(msg, len, "NT",       nt,  sizeof(nt));
    get_hdr(msg, len, "NTS",      nts, sizeof(nts));
    get_hdr(msg, len, "USN",      usn, sizeof(usn));
    get_hdr(msg, len, "LOCATION", loc, sizeof(loc));
    get_hdr(msg, len, "ST",       st,  sizeof(st));

    /* Determine NTS short string */
    const char *nts_short = "search";
    if (is_notify) {
        if      (strstr(nts, "alive"))  nts_short = "alive";
        else if (strstr(nts, "byebye")) nts_short = "byebye";
        else if (strstr(nts, "update")) nts_short = "update";
        else                            nts_short = "notify";
    }

    const char *type = is_notify ? nt : st;

    pthread_mutex_lock(&g_mu);
    ssdp_device_t *e = find_or_create(usn, src_ip, type);
    snprintf(e->ip,       sizeof(e->ip),       "%s", src_ip);
    snprintf(e->type,     sizeof(e->type),      "%s", type);
    snprintf(e->usn,      sizeof(e->usn),       "%s", usn);
    snprintf(e->location, sizeof(e->location),  "%s", loc);
    snprintf(e->nts,      sizeof(e->nts),       "%s", nts_short);
    e->last_seen = time(NULL);
    pthread_mutex_unlock(&g_mu);

    if (info && infosz > 0) {
        const char *ts = short_type(type);
        snprintf(info, (size_t)infosz, "SSDP %s %.46s", nts_short, ts);
    }
    return 1;
}

void ssdp_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_SSDP_DEVICES ? g_count : MAX_SSDP_DEVICES;
    memcpy(s->ssdp_devices, g_devs, (size_t)n * sizeof(ssdp_device_t));
    s->ssdp_count = n;
    pthread_mutex_unlock(&g_mu);
}

void ssdp_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_devs, 0, sizeof(g_devs));
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
