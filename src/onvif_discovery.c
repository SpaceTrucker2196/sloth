#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "sloth.h"
#include "sloth_clock.h"
#include "onvif_discovery.h"
#include "stab.h"
#include "sensor_health.h"

/* ── Internal table ──────────────────────────────────────── */

/* UUID when the message carries one; otherwise the source IP, and then
 * only against rows that never learned a UUID — a UUID-less Bye must
 * not attach to a different device that shares the address. */
typedef struct { const char *uuid, *ip; } onvif_key_t;

static int dev_key_eq(const void *row, const void *key) {
    const onvif_device_t *d = row; const onvif_key_t *k = key;
    if (k->uuid[0]) return strcmp(d->uuid, k->uuid) == 0;
    return !d->uuid[0] && strcmp(d->ip, k->ip) == 0;
}

/* STAB_OLDEST (#110), tallied as evict_onvif_device: the UUID is the
 * sender's to choose, so a spray of invented ones churns the table. */
STAB_DECL(g_devs, onvif_device_t, MAX_ONVIF_DEVICES, last_seen, STAB_OLDEST,
          SH_EVICT_ONVIF_DEVICE, NULL, dev_key_eq);
static pthread_mutex_t  g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── Minimal XML scanning ────────────────────────────────────
 *
 * Not a general XML parser. WS-Discovery's own body elements are a
 * closed, known set of simple-content leaves (OASIS WS-Discovery 1.1
 * §2: Types is an xs:list of QName, Scopes an xs:list of xs:anyURI,
 * XAddrs an xs:list of xs:anyURI), so a tag-name scan is sufficient
 * and keeps this module free of a parsing dependency sloth does not
 * otherwise need. See onvif_discovery.h for what this does not
 * handle. */

/* True if buf contains an opening tag whose local name is `local` —
 * "<local" or ":local" (the latter catches any namespace prefix)
 * immediately followed by whitespace, '>' or '/'. */
static int xml_has_open_tag(const char *buf, int len, const char *local) {
    size_t ll = strlen(local);
    for (int i = 0; i + 1 < len; i++) {
        if (buf[i] != '<' && buf[i] != ':') continue;
        if (i + 1 + (int)ll > len) continue;
        if (memcmp(buf + i + 1, local, ll) != 0) continue;
        int j = i + 1 + (int)ll;
        char c = (j < len) ? buf[j] : '\0';
        if (c == '>' || c == '/' || c == ' ' || c == '\t' ||
            c == '\r' || c == '\n')
            return 1;
    }
    return 0;
}

/* Trim ASCII whitespace from both ends of an in-place NUL-terminated
 * string (pretty-printed SOAP indents element text). */
static void trim(char *s) {
    size_t n = strlen(s);
    size_t start = 0;
    while (start < n && isspace((unsigned char)s[start])) start++;
    size_t end = n;
    while (end > start && isspace((unsigned char)s[end - 1])) end--;
    size_t outlen = end - start;
    if (start) memmove(s, s + start, outlen);
    s[outlen] = '\0';
}

/* Find the first open tag named `local`, skip past its '>' (so any
 * attributes on it are tolerated), and copy the text up to the next
 * '<' into out[outsz]. Returns 1 if the element was found. */
static int extract_elem(const char *buf, int len, const char *local,
                        char *out, int outsz) {
    size_t ll = strlen(local);
    for (int i = 0; i + 1 < len; i++) {
        if (buf[i] != '<' && buf[i] != ':') continue;
        if (i + 1 + (int)ll > len) continue;
        if (memcmp(buf + i + 1, local, ll) != 0) continue;
        int j = i + 1 + (int)ll;
        char c = (j < len) ? buf[j] : '\0';
        if (c != '>' && c != '/' && c != ' ' && c != '\t' &&
            c != '\r' && c != '\n')
            continue;

        while (j < len && buf[j] != '>') j++;
        if (j >= len) continue;
        j++;                               /* past the opening tag's '>' */

        int start = j;
        while (j < len && buf[j] != '<') j++;
        int clen = j - start;
        if (clen < 0) clen = 0;
        if (clen >= outsz) clen = outsz - 1;
        memcpy(out, buf + start, (size_t)clen);
        out[clen] = '\0';
        trim(out);
        return 1;
    }
    return 0;
}

/* The EndpointReference's identity is WS-Addressing's own "Address"
 * element (typically "urn:uuid:...", but this stores whatever scheme
 * is actually there). This must go through extract_elem rather than a
 * bare "urn:uuid:" pattern search: the SOAP header's wsa:MessageID is
 * *also* commonly a urn:uuid value, and a pattern search finds
 * whichever comes first in the message — which is the header, not the
 * endpoint identity this module actually wants. */
static int extract_uuid(const char *buf, int len, char *out, int outsz) {
    return extract_elem(buf, len, "Address", out, outsz);
}

/* ── Public parse ────────────────────────────────────────── */

int onvif_ws_discovery_parse(const uint8_t *data, int len, onvif_msg_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    if (!data || len < 20) return 0;
    const char *buf = (const char *)data;
    if (memchr(buf, '<', (size_t)len) == NULL) return 0;

    /* Checked in this order so the plural "ProbeMatches"/"ResolveMatches"
     * wrapper is what's matched, not a bare client Probe/Resolve query —
     * which carries no XAddrs/Types of its own and is not one of the
     * four device-announcement shapes this module cares about. */
    const char *kind = NULL;
    if      (xml_has_open_tag(buf, len, "ProbeMatches"))   kind = "ProbeMatch";
    else if (xml_has_open_tag(buf, len, "ResolveMatches")) kind = "ResolveMatch";
    else if (xml_has_open_tag(buf, len, "Hello"))          kind = "Hello";
    else if (xml_has_open_tag(buf, len, "Bye"))            kind = "Bye";
    if (!kind) return 0;

    snprintf(out->kind, sizeof(out->kind), "%s", kind);
    extract_uuid(buf, len, out->uuid, sizeof(out->uuid));
    extract_elem(buf, len, "Types",  out->types,  sizeof(out->types));
    extract_elem(buf, len, "Scopes", out->scopes, sizeof(out->scopes));
    extract_elem(buf, len, "XAddrs", out->xaddrs, sizeof(out->xaddrs));

    /* ONVIF Core Specification, device discovery: a Network Video
     * Transmitter announces itself with Types containing (a possibly
     * prefixed) "NetworkVideoTransmitter". */
    out->is_camera = (strstr(out->types, "NetworkVideoTransmitter") != NULL);
    return 1;
}

/* ── Table helpers ───────────────────────────────────────── */

/* `now` 0: the caller stamps last_seen from its own clock read under the
 * same g_mu hold, before any other lookup can see the row. That read is
 * left exactly where it was — moving modules onto an injected clock is
 * its own slice, not this one. */
static onvif_device_t *dev_get(const char *uuid, const char *ip) {
    onvif_key_t key = { uuid, ip };
    return stab_get(&g_devs, &key, 0, NULL);
}

/* ── Public API ──────────────────────────────────────────── */

int onvif_ws_discovery_snoop(const char *src_ip, const uint8_t *data, int len,
                             char *info, int infosz) {
    onvif_msg_t m;
    if (!onvif_ws_discovery_parse(data, len, &m)) return 0;

    pthread_mutex_lock(&g_mu);
    onvif_device_t *e = dev_get(m.uuid, src_ip);
    snprintf(e->ip, sizeof(e->ip), "%s", src_ip);
    /* A Bye carries only the EndpointReference (OASIS WS-Discovery 1.1
     * §4.2) — never overwrite the last-known Types/Scopes/XAddrs with
     * a message that is silent about them. */
    if (m.uuid[0])   snprintf(e->uuid,   sizeof(e->uuid),   "%s", m.uuid);
    if (m.types[0])  snprintf(e->types,  sizeof(e->types),  "%s", m.types);
    if (m.scopes[0]) snprintf(e->scopes, sizeof(e->scopes), "%s", m.scopes);
    if (m.xaddrs[0]) snprintf(e->xaddrs, sizeof(e->xaddrs), "%s", m.xaddrs);
    snprintf(e->kind, sizeof(e->kind), "%s", m.kind);
    /* Sticky: once an endpoint has shown camera Types, a later Bye
     * (which carries none) must not make it look like it never was
     * one. */
    if (m.is_camera) e->is_camera = 1;
    e->last_seen = sloth_wall();
    /* Read under the lock: once it is released the row is the table's
     * again, and an eviction on another thread may already have handed
     * it to a different device. */
    int is_camera = e->is_camera;
    pthread_mutex_unlock(&g_mu);

    if (info && infosz > 0)
        snprintf(info, (size_t)infosz, "WSD %s%s", m.kind,
                 is_camera ? " cam" : "");
    return 1;
}

void onvif_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = stab_snapshot(&g_devs, s->onvif_devices, MAX_ONVIF_DEVICES);
    s->onvif_count = n;
    pthread_mutex_unlock(&g_mu);
}

void onvif_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_devs);
    pthread_mutex_unlock(&g_mu);
}
