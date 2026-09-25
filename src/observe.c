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
