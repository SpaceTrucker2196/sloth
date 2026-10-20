#ifndef SLOTH_WORKER_THREAD_H
#define SLOTH_WORKER_THREAD_H

#include <pthread.h>
#include <signal.h>

/* Every thread sloth starts goes through here (#95).
 *
 * POSIX delivers a process-directed signal to any one thread that does
 * not block it (XSH 2.4.1). main() installs on_signal() for SIGINT and
 * SIGTERM, and that handler only sets g_quit; it is correct on any
 * thread, but the shutdown it requests is observed by the main loop,
 * and a handler running on a worker interrupts whatever that worker was
 * doing — a blocking pcap_dispatch() returns EINTR, the DNS worker's
 * getnameinfo() is cut short. Blocking both signals in every worker
 * leaves the main thread as the only eligible target.
 *
 * The mask is set in the creating thread around pthread_create() rather
 * than first thing in the worker, because a new thread inherits its
 * creator's mask (XSH pthread_create): there is no window in which the
 * worker exists with the signals unblocked. The caller's own mask is
 * restored before return.
 *
 * SIGHUP is not handled by sloth (it keeps its default action, which
 * terminates the process from whichever thread receives it), so it is
 * not in the set. */

/* Fill `set` with the signals worker threads keep blocked. */
void worker_signal_set(sigset_t *set);

/* pthread_create() with worker_signal_set() blocked in the new thread.
 * Returns pthread_create()'s result, or the pthread_sigmask() error if
 * the mask could not be set (no thread is created then). */
int worker_thread_create(pthread_t *t, void *(*fn)(void *), void *arg);

#endif
