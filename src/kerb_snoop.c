#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "kerb_snoop.h"

static kerb_event_t    g_tbl[MAX_KERB_EVENTS];
static int             g_n  = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Kerberos message-type tags per RFC 4120 §5.3 / §5.4 — outer
 * [APPLICATION n] wrapper byte. */
#define K_AS_REQ     0x6A   /* [APPLICATION 10] */
#define K_AS_REP     0x6B   /* [APPLICATION 11] */
#define K_TGS_REQ    0x6C   /* [APPLICATION 12] */
#define K_TGS_REP    0x6D   /* [APPLICATION 13] */
#define K_KRB_ERROR  0x7E   /* [APPLICATION 30] */

/* RFC 4120 §7.5.9 error codes. */
#define KDC_ERR_C_PRINCIPAL_UNKNOWN  6
#define KDC_ERR_PREAUTH_FAILED       24
#define KDC_ERR_PREAUTH_REQUIRED     25

/* Walk a KRB-ERROR message body for the [6] error-code field. The
 * SEQUENCE under [APPLICATION 30] holds context-specific tags
 * 0xA0..0xA6; the error code is [6] explicit, wrapping an INTEGER.
 * In DER that's `A6 LEN 02 ilen <bytes>`. We scan a bounded prefix
 * of the message rather than parsing the full ASN.1 tree — every
 * KRB-ERROR has the error-code field within the first ~80 bytes,
 * even with maximum-length time and realm fields.
 *
 * Returns the error code, or -1 if not found. */
static int parse_krb_error_code(const uint8_t *p, int n) {
    int limit = n < 96 ? n : 96;
    for (int i = 0; i + 4 < limit; i++) {
        if (p[i] != 0xA6) continue;
        uint8_t outer_len = p[i + 1];
        if (outer_len < 3 || i + 1 + outer_len >= limit) continue;
        if (p[i + 2] != 0x02) continue;          /* inner INTEGER */
        uint8_t int_len = p[i + 3];
        if (int_len == 0 || int_len > 4) continue;
        if (i + 4 + int_len > limit) continue;
        int code = 0;
        for (int b = 0; b < int_len; b++) {
            code = (code << 8) | p[i + 4 + b];
        }
        return code;
    }
    return -1;
}

/* Find the Kerberos message starting at offset 0 or offset 4 of
 * `payload` (TCP/88 prepends a 4-byte length). Returns a pointer to
 * the Kerberos message and writes its length to *out_len. NULL on
 * no recognised header. */
static const uint8_t *find_kerb_msg(const uint8_t *payload, int len,
                                     int *out_len) {
    if (len < 1) return NULL;
    uint8_t t = payload[0];
    if (t == K_AS_REQ || t == K_AS_REP ||
        t == K_TGS_REQ || t == K_TGS_REP ||
        t == K_KRB_ERROR) {
        *out_len = len;
        return payload;
    }
    if (len < 5) return NULL;
    /* TCP framing: 4-byte length (network order) then the message. */
    if (payload[0] == 0x00) {
        uint8_t inner = payload[4];
        if (inner == K_AS_REQ || inner == K_AS_REP ||
            inner == K_TGS_REQ || inner == K_TGS_REP ||
            inner == K_KRB_ERROR) {
            *out_len = len - 4;
            return payload + 4;
        }
    }
    return NULL;
}

static int find_or_alloc(const char *src_ip) {
    for (int i = 0; i < g_n; i++) {
        if (strcmp(g_tbl[i].src_ip, src_ip) == 0) return i;
    }
    int slot;
    if (g_n < MAX_KERB_EVENTS) {
        slot = g_n++;
    } else {
        /* Evict the oldest entry by last_seen. */
        slot = 0;
        for (int i = 1; i < g_n; i++) {
            if (g_tbl[i].last_seen < g_tbl[slot].last_seen) slot = i;
        }
    }
    memset(&g_tbl[slot], 0, sizeof(g_tbl[slot]));
    snprintf(g_tbl[slot].src_ip, sizeof(g_tbl[slot].src_ip), "%s", src_ip);
    return slot;
}

int kerb_snoop_observe(const char *src_ip, uint16_t src_port,
                       const char *dst_ip, uint16_t dst_port,
                       const uint8_t *payload, int len) {
    if (!src_ip || !dst_ip || !payload || len < 1) return 0;

    /* Identify the *client* side — the endpoint NOT on port 88. The
     * server (KDC) is whichever side has port 88. */
    const char *client_ip;
    if      (dst_port == 88) client_ip = src_ip;
    else if (src_port == 88) client_ip = dst_ip;
    else                     return 0;

    int kerb_len;
    const uint8_t *msg = find_kerb_msg(payload, len, &kerb_len);
    if (!msg || kerb_len < 1) return 0;

    uint8_t mtype = msg[0];

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);
    int idx = find_or_alloc(client_ip);
    kerb_event_t *e = &g_tbl[idx];
    if (e->first_seen == 0) e->first_seen = now;
    e->last_seen = now;

    switch (mtype) {
    case K_AS_REQ:    e->as_req_count++;  break;
    case K_AS_REP:    e->as_rep_count++;  break;
    case K_TGS_REQ:   e->tgs_req_count++; break;
    case K_TGS_REP:   e->tgs_rep_count++; break;
    case K_KRB_ERROR: {
        int code = parse_krb_error_code(msg, kerb_len);
        switch (code) {
        case KDC_ERR_PREAUTH_REQUIRED:    e->preauth_required_count++;  break;
        case KDC_ERR_PREAUTH_FAILED:      e->preauth_failed_count++;    break;
        case KDC_ERR_C_PRINCIPAL_UNKNOWN: e->principal_unknown_count++; break;
        default:                          e->error_other_count++;       break;
        }
        break;
    }
    default: break;
    }

    pthread_mutex_unlock(&g_mu);
    return 1;
}

void kerb_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_KERB_EVENTS ? g_n : MAX_KERB_EVENTS;
    for (int i = 0; i < n; i++) s->kerb_events[i] = g_tbl[i];
    s->kerb_event_count = n;
    pthread_mutex_unlock(&g_mu);
}

void kerb_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}
