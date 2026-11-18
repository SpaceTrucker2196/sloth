#ifndef SLOTH_RUN_FLAG_H
#define SLOTH_RUN_FLAG_H

#include <pthread.h>

/* Worker run flag (#95), in a file of its own since #212.
 *
 * It was declared in capture/capture.h and defined in capture/capture.c,
 * the libpcap capture's own file, which made every reader thread that
 * wanted a stop flag (GNSS, ADS-B, APRS, rtl_433) depend on the capture
 * module for three functions that have nothing to do with capture. A
 * daemon with no capture (#211) could not link a reader without it. The
 * type keeps its name: nine files spell it, and a rename would be churn
 * with no reader gaining anything.
 *
 * The flag is written by the thread that stops the worker and read by
 * the worker between batches and by the poll loop's health check. It
 * used to be a bare `volatile int`, which C99 does not make a
 * synchronisation primitive: volatile stops the compiler caching the
 * value, but gives no ordering and no atomicity between threads, so
 * every such read is a data race. The C99 answer is a mutex; C11
 * <stdatomic.h> would change the language contract in AGENTS.md.
 *
 * The flag only makes the stop request itself race-free. What gets a
 * worker out of a blocked call promptly is the worker's own business:
 * pcap_breakloop() for the two libpcap workers, a bounded poll() or
 * sleep for the readers.
 *
 * capture_run_flag_take() clears the flag and returns what it held, in
 * one critical section, so of two concurrent stoppers exactly one sees
 * the 1 and joins the thread. Joining a pthread_t twice is undefined.
 *
 * The mutex is a strict leaf: nothing is called while it is held. */
typedef struct {
    pthread_mutex_t mu;
    int             v;
} capture_run_flag_t;
#define CAPTURE_RUN_FLAG_INIT { PTHREAD_MUTEX_INITIALIZER, 0 }

int  capture_run_flag_get(capture_run_flag_t *f);
void capture_run_flag_set(capture_run_flag_t *f, int v);
int  capture_run_flag_take(capture_run_flag_t *f);

#endif /* SLOTH_RUN_FLAG_H */
