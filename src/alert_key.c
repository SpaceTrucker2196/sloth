#include "alert_key.h"

#include <stdio.h>
#include <string.h>

#define AKEY_FNV64_OFFSET 0xcbf29ce484222325ULL
#define AKEY_FNV64_PRIME  0x100000001b3ULL

static uint64_t akey_fnv(const void *data, size_t n, uint64_t h) {
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= AKEY_FNV64_PRIME; }
    return h;
}

/* Append raw bytes; any shortfall poisons the whole key. Never writes a
 * partial component, so an overflowed buffer is never mistaken for a
 * shorter valid key even if a caller ignores akey_end(). */
static void put(akey_t *k, const char *s, size_t n) {
    if (k->overflow) return;
    if (k->len + n + 1 > k->n) { k->overflow = 1; return; }
    memcpy(k->buf + k->len, s, n);
    k->len += n;
    k->buf[k->len] = '\0';
}

static void sep(akey_t *k) { put(k, ":", 1); }

static void put_hash(akey_t *k, uint64_t h) {
    char hx[17];
    snprintf(hx, sizeof(hx), "%016llx", (unsigned long long)h);
    put(k, hx, 16);
}

static int tok_ok(const char *s) {
    size_t n = 0;
    for (; s[n]; n++) {
        unsigned char c = (unsigned char)s[n];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) return 0;
    }
    return n > 0 && n <= AKEY_TOK_MAX;
}

void akey_begin(akey_t *k, char *buf, size_t n, const char *rule) {
    k->buf = buf;
    k->n = n;
    k->len = 0;
    k->overflow = (!buf || n == 0);
    if (buf && n) buf[0] = '\0';
    if (!rule || !tok_ok(rule)) { k->overflow = 1; return; }
    put(k, rule, strlen(rule));
}

void akey_mac(akey_t *k, const uint8_t mac[6]) {
    char m[18];
    snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    sep(k);
    put(k, m, 17);
}

void akey_u(akey_t *k, unsigned v) {
    char d[16];
    int n = snprintf(d, sizeof(d), "%u", v);
    sep(k);
    put(k, d, (size_t)n);
}

void akey_tok(akey_t *k, const char *tok) {
    if (!tok || !tok_ok(tok)) { k->overflow = 1; return; }
    sep(k);
    put(k, tok, strlen(tok));
}

void akey_hex(akey_t *k, const uint8_t *b, size_t n) {
    static const char hx[] = "0123456789abcdef";
    sep(k);
    for (size_t i = 0; i < n && !k->overflow; i++) {
        char two[2] = { hx[(b[i] >> 4) & 0xF], hx[b[i] & 0xF] };
        put(k, two, 2);
    }
}

/* Bytes that may appear verbatim in a remote component. ':' is the
 * separator, ',' and '[' ']' are punctuation other components use; the
 * rest is anything a terminal or a log grep could choke on. */
static int remote_keeps(unsigned char c) {
    return c > 0x20 && c < 0x7f && c != ':' && c != ',' && c != '[' && c != ']';
}

void akey_remote(akey_t *k, const char *s, size_t keep) {
    if (!s) s = "";
    size_t full = strlen(s);
    char tmp[256];
    if (keep > sizeof(tmp)) keep = sizeof(tmp);
    size_t m = full < keep ? full : keep;
    for (size_t i = 0; i < m; i++)
        tmp[i] = remote_keeps((unsigned char)s[i]) ? s[i] : '_';
    sep(k);
    put(k, tmp, m);
    sep(k);
    put_hash(k, akey_fnv(s, full, AKEY_FNV64_OFFSET));
}

/* An address as inet_ntop renders one: hex digits, '.', ':', at most
 * INET6_ADDRSTRLEN - 1. IPv6 is bracketed so its colons cannot be read
 * as component separators. Anything else is keyed as a remote string. */
void akey_ip(akey_t *k, const char *ip) {
    size_t n = ip ? strlen(ip) : 0;
    int ok = n > 0 && n <= 45, colon = 0;
    for (size_t i = 0; ok && i < n; i++) {
        unsigned char c = (unsigned char)ip[i];
        if (c == ':') colon = 1;
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F') || c == '.')) ok = 0;
    }
    if (!ok) { akey_remote(k, ip, AKEY_IP_FALLBACK_KEEP); return; }
    sep(k);
    if (colon) put(k, "[", 1);
    put(k, ip, n);
    if (colon) put(k, "]", 1);
}

void akey_set(akey_t *k, const char *const *items, int n) {
    if (n < 0 || n > AKEY_SET_MAX || (n > 0 && !items)) { k->overflow = 1; return; }
    const char *sorted[AKEY_SET_MAX];
    for (int i = 0; i < n; i++) sorted[i] = items[i] ? items[i] : "";
    for (int i = 1; i < n; i++) {
        const char *v = sorted[i];
        int j = i - 1;
        while (j >= 0 && strcmp(sorted[j], v) > 0) { sorted[j + 1] = sorted[j]; j--; }
        sorted[j + 1] = v;
    }
    /* Each member hashed with its terminating NUL, so {"ab","c"} and
     * {"a","bc"} cannot join to the same byte stream. */
    uint64_t h = AKEY_FNV64_OFFSET;
    for (int i = 0; i < n; i++) h = akey_fnv(sorted[i], strlen(sorted[i]) + 1, h);
    akey_u(k, (unsigned)n);
    sep(k);
    put_hash(k, h);
}

const char *akey_end(akey_t *k) {
    if (!k->buf || k->n == 0) return "";
    if (k->overflow) k->buf[0] = '\0';
    return k->buf;
}
