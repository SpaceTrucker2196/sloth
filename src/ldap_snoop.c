#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ldap_snoop.h"
#include "sloth_clock.h"
#include "stab.h"

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Bounded table (#110): STAB_OLDEST, so a spray of new keys churns
 * the table and is tallied, but can never make it allocate or refuse.
 * g_mu is held by the callers across get-and-update, so the table
 * itself runs unlocked (mu = NULL). stab_get never returns NULL under
 * STAB_OLDEST. */
static int key_eq(const void *row, const void *key) {
    return strcmp(((const ldap_event_t *)row)->src_ip, (const char *)key) == 0;
}
STAB_DECL(g_tbl, ldap_event_t, MAX_LDAP_EVENTS, last_seen, STAB_OLDEST,
          SH_EVICT_LDAP_EVENT, NULL, key_eq);

/* LDAP protocolOp tags (RFC 4511 §4.1.1 / §4.5.1 / §4.5.3). The
 * outer SEQUENCE wraps messageID + protocolOp; the op tag is
 * [APPLICATION n] constructed. */
#define LDAP_OP_BIND_REQ        0x60    /* [APPLICATION 0]  */
#define LDAP_OP_SEARCH_REQ      0x63    /* [APPLICATION 3]  */
#define LDAP_OP_SEARCH_RES_REF  0x73    /* [APPLICATION 19] */

/* Parse a BER definite-length field starting at `p`. On success
 * returns the length value and writes the number of bytes consumed
 * to *out_used. Returns -1 on malformed / indefinite-length input. */
static int ber_len(const uint8_t *p, int n, int *out_used) {
    if (n < 1) return -1;
    if (p[0] < 0x80) { *out_used = 1; return p[0]; }
    int nb = p[0] & 0x7f;
    if (nb == 0 || nb > 4 || n < 1 + nb) return -1;
    int len = 0;
    for (int i = 0; i < nb; i++) len = (len << 8) | p[1 + i];
    *out_used = 1 + nb;
    return len;
}

/* Walk the LDAP message envelope to expose the protocolOp tag,
 * leaving everything else as raw bytes. Returns the protocolOp
 * tag byte and the offset of the op body (just past the op tag +
 * op length), or -1 on malformed input. */
static int peek_op(const uint8_t *p, int n, int *op_body_off,
                   int *op_body_len) {
    if (n < 2 || p[0] != 0x30) return -1;        /* outer SEQUENCE */
    int used = 0;
    int outer_len = ber_len(p + 1, n - 1, &used);
    if (outer_len < 0) return -1;
    int off = 1 + used;
    /* messageID INTEGER */
    if (off >= n || p[off] != 0x02) return -1;
    int mid_used = 0;
    int mid_len = ber_len(p + off + 1, n - off - 1, &mid_used);
    if (mid_len < 0) return -1;
    off += 1 + mid_used + mid_len;
    if (off >= n) return -1;
    /* protocolOp */
    int op_tag = p[off];
    int op_used = 0;
    int op_len = ber_len(p + off + 1, n - off - 1, &op_used);
    if (op_len < 0) return -1;
    *op_body_off = off + 1 + op_used;
    *op_body_len = op_len;
    return op_tag;
}

/* BindRequest body shape (RFC 4511 §4.2):
 *   version  INTEGER (1..127)
 *   name     LDAPDN  (OCTET STRING)
 *   authentication  CHOICE { simple [0] OCTET STRING, sasl [3] ... }
 *
 * For anon-bind detection we only care whether `name` is empty.
 * The version INTEGER is `02 01 03` for v3; the name is `04 LEN ...`.
 * An empty DN is `04 00`. */
static int bind_has_empty_dn(const uint8_t *p, int n) {
    if (n < 5) return 0;
    /* Skip version INTEGER. */
    if (p[0] != 0x02) return 0;
    int used = 0;
    int vlen = ber_len(p + 1, n - 1, &used);
    if (vlen < 0) return 0;
    int off = 1 + used + vlen;
    if (off + 2 > n) return 0;
    if (p[off] != 0x04) return 0;                /* OCTET STRING (name) */
    int nlen_used = 0;
    int nlen = ber_len(p + off + 1, n - off - 1, &nlen_used);
    if (nlen < 0) return 0;
    return nlen == 0;
}

int ldap_snoop_observe(const char *src_ip, uint16_t src_port,
                       const char *dst_ip, uint16_t dst_port,
                       const uint8_t *payload, int len) {
    if (!src_ip || !dst_ip || !payload || len < 2) return 0;

    /* Identify the client side — the endpoint NOT on an LDAP port. */
    const char *client_ip;
    if (dst_port == 389 || dst_port == 3268) {
        client_ip = src_ip;
    } else if (src_port == 389 || src_port == 3268) {
        client_ip = dst_ip;
    } else {
        return 0;
    }

    int body_off = 0, body_len = 0;
    int op = peek_op(payload, len, &body_off, &body_len);
    if (op < 0) return 0;
    if (op != LDAP_OP_BIND_REQ &&
        op != LDAP_OP_SEARCH_REQ &&
        op != LDAP_OP_SEARCH_RES_REF) return 0;

    time_t now = sloth_wall();
    pthread_mutex_lock(&g_mu);
    int created;
    ldap_event_t *e = stab_get(&g_tbl, client_ip, now, &created);
    if (created) snprintf(e->src_ip, sizeof(e->src_ip), "%s", client_ip);
    if (e->first_seen == 0) e->first_seen = now;
    e->last_seen = now;

    switch (op) {
    case LDAP_OP_BIND_REQ:
        e->bind_count++;
        if (body_off + body_len <= len &&
            bind_has_empty_dn(payload + body_off, body_len)) {
            e->bind_anon_count++;
        }
        break;
    case LDAP_OP_SEARCH_REQ:
        e->search_count++;
        break;
    case LDAP_OP_SEARCH_RES_REF:
        e->search_ref_count++;
        break;
    }

    pthread_mutex_unlock(&g_mu);
    return 1;
}

void ldap_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    s->ldap_event_count = stab_snapshot(&g_tbl, s->ldap_events, MAX_LDAP_EVENTS);
    pthread_mutex_unlock(&g_mu);
}

void ldap_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_tbl);
    pthread_mutex_unlock(&g_mu);
}
