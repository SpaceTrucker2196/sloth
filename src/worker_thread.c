#include "worker_thread.h"

void worker_signal_set(sigset_t *set)
{
    sigemptyset(set);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGTERM);
}

int worker_thread_create(pthread_t *t, void *(*fn)(void *), void *arg)
{
    sigset_t block, saved;
    worker_signal_set(&block);
    int rc = pthread_sigmask(SIG_BLOCK, &block, &saved);
    if (rc != 0) return rc;
    rc = pthread_create(t, NULL, fn, arg);
    /* Restoring cannot fail with a set pthread_sigmask() just returned. */
    (void)pthread_sigmask(SIG_SETMASK, &saved, NULL);
    return rc;
}
