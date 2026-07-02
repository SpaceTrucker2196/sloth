/* Cleartext credential exposure recorder — roadmap #16 phase 3.
 *
 * Records the *fact* of a cleartext credential exposure (source IP,
 * destination, protocol, username) so the alert engine can surface
 * it and the JSONL log can carry it. Passwords are never stored,
 * hashed, or truncated — this file has no code path that touches
 * a password value. That's enforced by the module boundary: no
 * function here accepts a password argument.
 *
 * Ring buffer with coalescing by (src, dst, dst_port, protocol,
 * username) — repeat observations for the same tuple bump the
 * timestamp instead of stacking rows. */

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "cleartext_creds.h"
#include "jsonl.h"

static cleartext_cred_t g_ring[MAX_CLEARTEXT_CREDS];
static int              g_count = 0;
static pthread_mutex_t  g_mu    = PTHREAD_MUTEX_INITIALIZER;

/* Only allow printable ASCII in usernames — strip control chars so a
 * malformed frame can't inject JSONL / TUI escape sequences. */
static void sanitize_copy(char *dst, int dstsz, const char *src) {
    if (!src) { dst[0] = '\0'; return; }
    int j = 0;
    for (int i = 0; src[i] && j + 1 < dstsz; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c >= 0x20 && c < 0x7f) dst[j++] = (char)c;
    }
    dst[j] = '\0';
}

static int find_row(const char *src, const char *dst, uint16_t port,
                    const char *proto, const char *user)
{
    for (int i = 0; i < g_count; i++) {
        const cleartext_cred_t *r = &g_ring[i];
        if (r->dst_port != port) continue;
        if (strcmp(r->src,      src)   != 0) continue;
        if (strcmp(r->dst,      dst)   != 0) continue;
        if (strcmp(r->protocol, proto) != 0) continue;
        if (user && strcmp(r->username, user) != 0) continue;
        return i;
    }
    return -1;
}

/* Evict the row with the oldest timestamp. Called when the ring is
 * full and a fresh (src, dst, protocol, username) arrives. */
static int evict_oldest(void) {
    int oldest = 0;
    for (int i = 1; i < g_count; i++)
        if (g_ring[i].ts < g_ring[oldest].ts) oldest = i;
    return oldest;
}

void cleartext_creds_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_ring, 0, sizeof(g_ring));
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}

void cleartext_creds_record_user(const char *src, const char *dst,
                                 uint16_t dst_port, const char *protocol,
                                 const char *username)
{
    if (!src || !dst || !protocol || !username || !username[0]) return;

    char user_clean[64];
    sanitize_copy(user_clean, sizeof(user_clean), username);
    if (!user_clean[0]) return;   /* all-control-chars input → drop */

    pthread_mutex_lock(&g_mu);

    int idx = find_row(src, dst, dst_port, protocol, user_clean);
    if (idx >= 0) {
        g_ring[idx].ts = time(NULL);
        pthread_mutex_unlock(&g_mu);
        return;
    }

    int slot = (g_count < MAX_CLEARTEXT_CREDS) ? g_count++ : evict_oldest();
    cleartext_cred_t *r = &g_ring[slot];
    memset(r, 0, sizeof(*r));
    snprintf(r->src,      sizeof(r->src),      "%s", src);
    snprintf(r->dst,      sizeof(r->dst),      "%s", dst);
    r->dst_port = dst_port;
    snprintf(r->protocol, sizeof(r->protocol), "%s", protocol);
    snprintf(r->username, sizeof(r->username), "%s", user_clean);
    r->password_observed = 0;
    r->ts = time(NULL);

    /* JSONL log — one line per new exposure. Fired here rather than in
     * the alert engine so downstream consumers see each unique cred
     * event without waiting for the dedup engine to flush. */
    jsonl_emit_cleartext_cred(r);

    pthread_mutex_unlock(&g_mu);
}

void cleartext_creds_mark_password(const char *src, const char *dst,
                                   uint16_t dst_port, const char *protocol)
{
    if (!src || !dst || !protocol) return;

    pthread_mutex_lock(&g_mu);

    /* Match on (src, dst, port, protocol) — any username row for this
     * flow is fair game. Bumps the most-recently-touched matching row
     * so the "password observed" tag lands on the latest USER we saw. */
    int best = -1;
    for (int i = 0; i < g_count; i++) {
        const cleartext_cred_t *r = &g_ring[i];
        if (r->dst_port != dst_port) continue;
        if (strcmp(r->src,      src)   != 0) continue;
        if (strcmp(r->dst,      dst)   != 0) continue;
        if (strcmp(r->protocol, protocol) != 0) continue;
        if (best < 0 || r->ts > g_ring[best].ts) best = i;
    }
    if (best >= 0) {
        g_ring[best].password_observed = 1;
        g_ring[best].ts = time(NULL);
    }
    pthread_mutex_unlock(&g_mu);
}

void cleartext_creds_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    int n = g_count < MAX_CLEARTEXT_CREDS ? g_count : MAX_CLEARTEXT_CREDS;
    memcpy(s->cleartext_creds, g_ring, (size_t)n * sizeof(cleartext_cred_t));
    s->cleartext_cred_count = n;
    pthread_mutex_unlock(&g_mu);
}
