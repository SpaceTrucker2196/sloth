#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <pthread.h>

#include "sloth.h"
#include "sloth_clock.h"
#include "ssdp_snoop.h"
#include "stab.h"
#include "sensor_health.h"

/* ── Internal table ──────────────────────────────────────── */

static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* USN when the announcement carries one; otherwise (ip, type). The two
 * modes are the lookup's, so they are the key's: a USN-less key matches
 * any row with that ip and type, exactly as the hand-rolled loop did. */
typedef struct { const char *usn, *ip, *type; } ssdp_key_t;

static int dev_key_eq(const void *row, const void *key) {
    const ssdp_device_t *d = row; const ssdp_key_t *k = key;
    if (k->usn[0]) return strcmp(d->usn, k->usn) == 0;
    return strcmp(d->ip, k->ip) == 0 && strcmp(d->type, k->type) == 0;
}

/* STAB_OLDEST (#110): every field of the key is the announcer's to
 * choose, so a flood of invented USNs churns the table — counted as
 * evict_ssdp_device — rather than freezing it. */
STAB_DECL(g_devs, ssdp_device_t, MAX_SSDP_DEVICES, last_seen, STAB_OLDEST,
          SH_EVICT_SSDP_DEVICE, NULL, dev_key_eq);

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

/* `now` 0: the caller stamps last_seen from its own clock read under the
 * same g_mu hold, before any other lookup can see the row. That read is
 * left exactly where it was — moving modules onto an injected clock is
 * its own slice, not this one. */
static ssdp_device_t *dev_get(const char *usn, const char *ip,
                              const char *type) {
    ssdp_key_t key = { usn, ip, type };
    return stab_get(&g_devs, &key, 0, NULL);
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
    ssdp_device_t *e = dev_get(usn, src_ip, type);
    snprintf(e->ip,       sizeof(e->ip),       "%s", src_ip);
    snprintf(e->type,     sizeof(e->type),      "%s", type);
    snprintf(e->usn,      sizeof(e->usn),       "%s", usn);
    snprintf(e->location, sizeof(e->location),  "%s", loc);
    snprintf(e->nts,      sizeof(e->nts),       "%s", nts_short);
    e->last_seen = sloth_wall();
    pthread_mutex_unlock(&g_mu);

    if (info && infosz > 0) {
        const char *ts = short_type(type);
        snprintf(info, (size_t)infosz, "SSDP %s %.46s", nts_short, ts);
    }
    return 1;
}

void ssdp_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = stab_snapshot(&g_devs, s->ssdp_devices, MAX_SSDP_DEVICES);
    s->ssdp_count = n;
    pthread_mutex_unlock(&g_mu);
}

void ssdp_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_devs);
    pthread_mutex_unlock(&g_mu);
}
