#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ssh_snoop.h"
#include "stab.h"

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Bounded table (#110): STAB_OLDEST, so a spray of new keys churns
 * the table and is tallied, but can never make it allocate or refuse.
 * g_mu is held by the callers across get-and-update, so the table
 * itself runs unlocked (mu = NULL). stab_get never returns NULL under
 * STAB_OLDEST. */
typedef struct { const char *src_ip, *dst_ip; } ssh_key_t;
static int key_eq(const void *row, const void *key) {
    const ssh_flow_t *e = row; const ssh_key_t *k = key;
    return strcmp(e->src_ip, k->src_ip) == 0 && strcmp(e->dst_ip, k->dst_ip) == 0;
}
STAB_DECL(g_tbl, ssh_flow_t, MAX_SSH_FLOWS, last_seen, STAB_OLDEST,
          SH_EVICT_SSH_FLOW, NULL, key_eq);

/* RFC 4253 §4.2 — the protocol version exchange string takes the
 * form:
 *   SSH-protoversion-softwareversion SP comments CR LF
 * Protoversion is "1.99" (server speaks both 1 and 2) or "2.0".
 * Both are eight ASCII bytes (`SSH-1.99` / `SSH-2.0-`). We require
 * the literal `SSH-` prefix plus a second `-` within the first 12
 * bytes so that arbitrary cleartext beginning with "SSH-" doesn't
 * trigger detection. */
static int looks_like_ssh_banner(const uint8_t *p, int len) {
    if (len < 6) return 0;
    if (p[0] != 'S' || p[1] != 'S' || p[2] != 'H' || p[3] != '-') return 0;
    int hyphen_window = len < 12 ? len : 12;
    for (int i = 4; i < hyphen_window; i++) {
        if (p[i] == '-') return 1;
    }
    return 0;
}

/* Copy banner safely — stop at CR/LF, cap to dest size, strip
 * trailing whitespace. The banner is sized to leave room for a
 * generous server-id string without truncating useful tail. */
static void copy_banner(char *dst, size_t cap, const uint8_t *src, int len) {
    if (cap == 0) return;
    size_t i = 0;
    int    cap_minus_one = (int)(cap - 1);
    for (; i < (size_t)len && (int)i < cap_minus_one; i++) {
        uint8_t c = src[i];
        if (c == '\r' || c == '\n') break;
        if (c < 0x20 || c > 0x7E) break;        /* non-printable */
        dst[i] = (char)c;
    }
    dst[i] = '\0';
}

int ssh_snoop_observe(const char *src_ip, uint16_t src_port,
                      const char *dst_ip, uint16_t dst_port,
                      const uint8_t *payload, int len) {
    if (!src_ip || !dst_ip || !payload || len <= 0) return 0;
    if (src_port != 22 && dst_port != 22) return 0;
    if (!looks_like_ssh_banner(payload, len)) return 0;

    /* Only count *server* banners. Each connection produces exactly
     * one server banner (it's the first thing the server sends),
     * so counting them is equivalent to counting connection
     * establishments that reached the SSH handshake — the unit we
     * want for brute-force detection. The client banner is sent
     * just afterwards but is not counted; doing so would double
     * every connection. */
    const char *client_ip, *server_ip;
    if (src_port == 22) {
        server_ip = src_ip;
        client_ip = dst_ip;
    } else {
        /* Client banner — observed but not counted; this branch
         * exists so the function isn't asymmetric, but no flow
         * entry is touched. */
        (void)dst_port;
        return 0;
    }

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);
    ssh_key_t key = { client_ip, server_ip };
    int created;
    ssh_flow_t *e = stab_get(&g_tbl, &key, now, &created);
    if (created) {
        snprintf(e->src_ip, sizeof(e->src_ip), "%s", client_ip);
        snprintf(e->dst_ip, sizeof(e->dst_ip), "%s", server_ip);
    }
    if (e->first_seen == 0) e->first_seen = now;
    e->last_seen = now;
    e->banner_count++;
    copy_banner(e->server_banner, sizeof(e->server_banner), payload, len);
    pthread_mutex_unlock(&g_mu);

    (void)dst_port;
    return 1;
}

void ssh_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    s->ssh_flow_count = stab_snapshot(&g_tbl, s->ssh_flows, MAX_SSH_FLOWS);
    pthread_mutex_unlock(&g_mu);
}

void ssh_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_tbl);
    pthread_mutex_unlock(&g_mu);
}
