#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "sloth.h"
#include "nbns_snoop.h"
#include "dns.h"

/* ── Internal table ──────────────────────────────────────── */

static nbns_name_t     g_names[MAX_NBNS_NAMES];
static int             g_count = 0;
static pthread_mutex_t g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* ── NetBIOS First Level Encoding (RFC 1001 §14.1) ─────── */

/* Decode 32 encoded bytes → 15-char name (spaces stripped) + suffix. */
static void decode_nb_name(const uint8_t *enc, char *out, int outsz,
                            uint8_t *sfx) {
    uint8_t raw[16];
    for (int i = 0; i < 16; i++) {
        uint8_t hi = (uint8_t)((enc[i * 2]     - 'A') & 0x0F);
        uint8_t lo = (uint8_t)((enc[i * 2 + 1] - 'A') & 0x0F);
        raw[i] = (uint8_t)((hi << 4) | lo);
    }
    if (sfx) *sfx = raw[15];
    int len = 15;
    while (len > 0 && raw[len - 1] == ' ') len--;
    if (len >= outsz) len = outsz - 1;
    if (len > 0) memcpy(out, raw, (size_t)len);
    out[len] = '\0';
}

/* Skip a DNS-encoded name; returns pointer past the final byte, or NULL. */
static const uint8_t *skip_name(const uint8_t *p, const uint8_t *end) {
    while (p < end) {
        uint8_t b = *p;
        if (b == 0x00) return p + 1;
        if ((b & 0xC0) == 0xC0) {
            if (p + 2 > end) return NULL;
            return p + 2;
        }
        p += 1 + b;
    }
    return NULL;
}

/* ── Table helpers ───────────────────────────────────────── */

static nbns_name_t *find_or_create(const char *name, uint8_t sfx) {
    for (int i = 0; i < g_count; i++) {
        if (g_names[i].suffix == sfx &&
            strcmp(g_names[i].name, name) == 0)
            return &g_names[i];
    }
    if (g_count >= MAX_NBNS_NAMES) return NULL;
    nbns_name_t *e = &g_names[g_count++];
    memset(e, 0, sizeof(*e));
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->suffix = sfx;
    return e;
}

/* ── Public API ──────────────────────────────────────────── */

int nbns_snoop(const uint8_t *msg, int len, char *info, int infosz) {
    if (len < 12) return 0;

    uint16_t flags   = (uint16_t)((msg[2] << 8) | msg[3]);
    int      is_resp = (flags >> 15) & 1;
    uint16_t qdcount = (uint16_t)((msg[4] << 8) | msg[5]);
    uint16_t ancount = (uint16_t)((msg[6] << 8) | msg[7]);

    if (qdcount > 8 || ancount > 8) return 0;

    const uint8_t *p   = msg + 12;
    const uint8_t *end = msg + len;

    /* Process questions — extract queried name even on queries. */
    for (int i = 0; i < qdcount; i++) {
        char    name[16] = ""; uint8_t sfx = 0;
        int     got_name = 0;
        if (p < end && *p == 0x20 && p + 34 <= end) {
            decode_nb_name(p + 1, name, sizeof(name), &sfx);
            got_name = name[0] != '\0';
        }
        const uint8_t *after = skip_name(p, end);
        if (!after || after + 4 > end) return 0;
        p = after + 4; /* skip QTYPE + QCLASS */

        if (!is_resp && got_name) {
            pthread_mutex_lock(&g_mu);
            nbns_name_t *e = find_or_create(name, sfx);
            if (e) e->last_seen = time(NULL);
            pthread_mutex_unlock(&g_mu);
            if (info && infosz > 0)
                snprintf(info, (size_t)infosz, "NBNS %s?", name);
        }
    }

    if (!is_resp) return (info && info[0]) ? 1 : 0;

    /* Parse answer RRs. */
    for (int i = 0; i < ancount && p < end; i++) {
        char    name[16] = ""; uint8_t sfx = 0;
        int     got_name = 0;
        if (p < end && *p == 0x20 && p + 34 <= end) {
            decode_nb_name(p + 1, name, sizeof(name), &sfx);
            got_name = name[0] != '\0';
        }
        const uint8_t *after = skip_name(p, end);
        if (!after || after + 10 > end) break;

        uint16_t       rtype  = (uint16_t)((after[0] << 8) | after[1]);
        uint16_t       rdlen  = (uint16_t)((after[8] << 8) | after[9]);
        const uint8_t *rdata  = after + 10;
        if (rdata + rdlen > end) break;

        /* NB record (0x0020): 2-byte flags + 4-byte IPv4 */
        if (rtype == 0x0020 && rdlen >= 6 && got_name) {
            char ip[INET_ADDRSTRLEN] = "";
            inet_ntop(AF_INET, rdata + 2, ip, sizeof(ip));
            pthread_mutex_lock(&g_mu);
            nbns_name_t *e = find_or_create(name, sfx);
            if (e) {
                if (ip[0]) snprintf(e->ip, sizeof(e->ip), "%s", ip);
                e->last_seen = time(NULL);
            }
            pthread_mutex_unlock(&g_mu);
            if (ip[0]) {
                dns_set_resolved(ip, name);
                if (info && infosz > 0)
                    snprintf(info, (size_t)infosz,
                             "NBNS %s -> %s", name, ip);
            }
        }

        p = rdata + rdlen;
    }

    return (info && info[0]) ? 1 : 0;
}

void nbns_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_NBNS_NAMES ? g_count : MAX_NBNS_NAMES;
    memcpy(s->nbns_names, g_names, (size_t)n * sizeof(nbns_name_t));
    s->nbns_count = n;
    pthread_mutex_unlock(&g_mu);
}

void nbns_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_names, 0, sizeof(g_names));
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}
