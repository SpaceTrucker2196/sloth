#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "smb_snoop.h"
#include "stab.h"

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Bounded table (#110): STAB_OLDEST, so a spray of new keys churns
 * the table and is tallied, but can never make it allocate or refuse.
 * g_mu is held by the callers across get-and-update, so the table
 * itself runs unlocked (mu = NULL). stab_get never returns NULL under
 * STAB_OLDEST. */
typedef struct { const char *client_ip, *server_ip; uint16_t server_port; } smb_key_t;
static int key_eq(const void *row, const void *key) {
    const smb_session_t *e = row; const smb_key_t *k = key;
    return e->server_port == k->server_port &&
           strcmp(e->client_ip, k->client_ip) == 0 &&
           strcmp(e->server_ip, k->server_ip) == 0;
}
STAB_DECL(g_tbl, smb_session_t, MAX_SMB_SESSIONS, last_seen, STAB_OLDEST,
          SH_EVICT_SMB_SESSION, NULL, key_eq);

/* Detect SMB magic at the start of the buffer OR after a 4-byte
 * NetBIOS Session Service header (port 139, and many port-445 stacks
 * that retain the NBSS framing for compatibility).
 *
 * Returns "SMB1", "SMB2", or NULL when no magic is found. The
 * caller treats SMB3 as SMB2 — distinguishing requires parsing the
 * negotiate response's Dialect field, which the rogue-SMB1 rule
 * doesn't need. */
static const char *detect_dialect(const uint8_t *p, int n) {
    if (n < 4) return NULL;
    /* Direct (no NBSS framing). */
    if (p[0] == 0xff && p[1] == 'S' && p[2] == 'M' && p[3] == 'B') return "SMB1";
    if (p[0] == 0xfe && p[1] == 'S' && p[2] == 'M' && p[3] == 'B') return "SMB2";
    /* NBSS framed: byte 0 = message type, bytes 1-3 = 24-bit length. */
    if (n >= 8 && p[0] == 0x00) {
        if (p[4] == 0xff && p[5] == 'S' && p[6] == 'M' && p[7] == 'B') return "SMB1";
        if (p[4] == 0xfe && p[5] == 'S' && p[6] == 'M' && p[7] == 'B') return "SMB2";
    }
    return NULL;
}

int smb_snoop_observe(const char *src_ip, uint16_t src_port,
                      const char *dst_ip, uint16_t dst_port,
                      const uint8_t *payload, int len) {
    if (!src_ip || !dst_ip || !payload || len < 4) return 0;

    /* Server side is whichever of src/dst is on the SMB port. If
     * neither is, the caller shouldn't have routed us here, but be
     * defensive — return 0 and let the caller log the packet as a
     * generic TCP segment. */
    uint16_t server_port;
    const char *client_ip, *server_ip;
    if (dst_port == 445 || dst_port == 139) {
        server_port = dst_port;
        server_ip   = dst_ip;
        client_ip   = src_ip;
    } else if (src_port == 445 || src_port == 139) {
        server_port = src_port;
        server_ip   = src_ip;
        client_ip   = dst_ip;
    } else {
        return 0;
    }

    const char *dialect = detect_dialect(payload, len);
    if (!dialect) return 0;

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);
    smb_key_t key = { client_ip, server_ip, server_port };
    int created;
    smb_session_t *e = stab_get(&g_tbl, &key, now, &created);
    if (created) {
        snprintf(e->client_ip, sizeof(e->client_ip), "%s", client_ip);
        snprintf(e->server_ip, sizeof(e->server_ip), "%s", server_ip);
        e->server_port = server_port;
    }
    if (e->first_seen == 0) e->first_seen = now;
    e->last_seen = now;
    e->count++;
    /* Sticky to SMB1: if we ever saw SMB1 on this flow, keep that
     * recorded. A flow that downgrades from SMB2 negotiation to a
     * v1 session is the precise pattern attackers force. */
    if (!e->dialect[0] || strcmp(e->dialect, "SMB1") != 0) {
        snprintf(e->dialect, sizeof(e->dialect), "%s", dialect);
    }
    pthread_mutex_unlock(&g_mu);
    return 1;
}

void smb_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    s->smb_session_count = stab_snapshot(&g_tbl, s->smb_sessions, MAX_SMB_SESSIONS);
    pthread_mutex_unlock(&g_mu);
}

void smb_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_tbl);
    pthread_mutex_unlock(&g_mu);
}
