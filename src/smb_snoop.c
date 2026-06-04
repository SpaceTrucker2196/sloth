#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "smb_snoop.h"

static smb_session_t   g_tbl[MAX_SMB_SESSIONS];
static int             g_n  = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

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

static int find_or_alloc(const char *client_ip, const char *server_ip,
                         uint16_t server_port) {
    for (int i = 0; i < g_n; i++) {
        if (g_tbl[i].server_port == server_port &&
            strcmp(g_tbl[i].client_ip, client_ip) == 0 &&
            strcmp(g_tbl[i].server_ip, server_ip) == 0) {
            return i;
        }
    }
    int slot;
    if (g_n < MAX_SMB_SESSIONS) {
        slot = g_n++;
    } else {
        /* Evict the oldest by last_seen. */
        slot = 0;
        for (int i = 1; i < g_n; i++) {
            if (g_tbl[i].last_seen < g_tbl[slot].last_seen) slot = i;
        }
    }
    memset(&g_tbl[slot], 0, sizeof(g_tbl[slot]));
    snprintf(g_tbl[slot].client_ip, sizeof(g_tbl[slot].client_ip), "%s", client_ip);
    snprintf(g_tbl[slot].server_ip, sizeof(g_tbl[slot].server_ip), "%s", server_ip);
    g_tbl[slot].server_port = server_port;
    return slot;
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
    int idx = find_or_alloc(client_ip, server_ip, server_port);
    smb_session_t *e = &g_tbl[idx];
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
    int n = g_n < MAX_SMB_SESSIONS ? g_n : MAX_SMB_SESSIONS;
    for (int i = 0; i < n; i++) s->smb_sessions[i] = g_tbl[i];
    s->smb_session_count = n;
    pthread_mutex_unlock(&g_mu);
}

void smb_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}
