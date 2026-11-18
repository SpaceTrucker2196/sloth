#include "run_flag.h"

/* Run flag (#95). Contract in run_flag.h. */
int capture_run_flag_get(capture_run_flag_t *f) {
    pthread_mutex_lock(&f->mu);
    int v = f->v;
    pthread_mutex_unlock(&f->mu);
    return v;
}

void capture_run_flag_set(capture_run_flag_t *f, int v) {
    pthread_mutex_lock(&f->mu);
    f->v = v;
    pthread_mutex_unlock(&f->mu);
}

int capture_run_flag_take(capture_run_flag_t *f) {
    pthread_mutex_lock(&f->mu);
    int v = f->v;
    f->v = 0;
    pthread_mutex_unlock(&f->mu);
    return v;
}
