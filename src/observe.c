#include "observe.h"

#include <pthread.h>

/* Strict observation is the shipped default (#84 slice 2, extended to
 * the scan trigger and discovery in slice 3). */
static int g_active_allowed = 0;
static int g_strict_locked  = 0;

/* The policy is written once during argv parsing and read afterwards,
 * including from the capture thread. A mutex rather than a bare int so
 * the read is a defined operation, matching how src/dns.c guards the
 * resolver half. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

void observe_lock_strict(void) {
    pthread_mutex_lock(&g_mu);
    g_strict_locked  = 1;
    g_active_allowed = 0;
    pthread_mutex_unlock(&g_mu);
}

int observe_strict_locked(void) {
    pthread_mutex_lock(&g_mu);
    int l = g_strict_locked;
    pthread_mutex_unlock(&g_mu);
    return l;
}

void observe_set_active_allowed(int allowed) {
    pthread_mutex_lock(&g_mu);
    /* A locked run refuses the enable outright rather than honouring it
     * and reporting the breach later. */
    if (!(g_strict_locked && allowed))
        g_active_allowed = allowed ? 1 : 0;
    pthread_mutex_unlock(&g_mu);
}

int observe_active_allowed(void) {
    pthread_mutex_lock(&g_mu);
    int a = g_active_allowed;
    pthread_mutex_unlock(&g_mu);
    return a;
}

int observe_discovery_allowed(void) {
    return !observe_strict_locked();
}

void observe_reset_policy(void) {
    pthread_mutex_lock(&g_mu);
    g_active_allowed = 0;
    g_strict_locked  = 0;
    pthread_mutex_unlock(&g_mu);
}

int observe_strict_refuses_socket(int strict_locked, int spec_is_remote) {
    return strict_locked && spec_is_remote == 1;
}

/* Pure by construction: no mutex, no global, no I/O. The policy it
 * composes has one owner each — the socket clause defers to
 * observe_strict_refuses_socket() rather than restating == 1, so a
 * future change to that ruling cannot leave two copies disagreeing.
 *
 * The apply step deliberately stays in main(): observe must not call
 * into dns (src/dns.c documents the one-way lock order observe <- dns),
 * and inverting that would be a cycle. So this returns what to do and
 * main() does it. */
void observe_resolve_profile(const observe_profile_req_t *req,
                             observe_profile_t *out) {
    if (!req || !out) return;

    out->refusal          = OBSERVE_PROFILE_OK;
    out->exit_code        = 0;
    out->strict_locked    = req->strict ? 1 : 0;
    out->active_allowed   = 0;
    out->resolver_enabled = 0;
    out->hop_enabled      = req->hop ? 1 : 0;

    /* A command line carrying both flags states two incompatible
     * intents. Refused either way round because the request carries no
     * ordering to prefer one by. */
    if (req->strict && req->allow_active) {
        out->refusal   = OBSERVE_PROFILE_REFUSE_ACTIVE_UNDER_STRICT;
        out->exit_code = 2;
        return;
    }

    /* Gated on have_data_socket so a socket_is_remote left over from an
     * earlier parse cannot refuse a run that asked for no socket. */
    if (req->have_data_socket &&
        observe_strict_refuses_socket(out->strict_locked,
                                      req->socket_is_remote)) {
        out->refusal   = OBSERVE_PROFILE_REFUSE_ROUTABLE_SOCKET_UNDER_STRICT;
        out->exit_code = 2;
        return;
    }

    if (req->allow_active) {
        out->active_allowed   = 1;
        out->resolver_enabled = 1;
    }
}
