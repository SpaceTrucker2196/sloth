#ifndef CAPTURE_H
#define CAPTURE_H

#include "ntop.h"

/* Start a background pcap capture thread writing into s->packets[].
   No-op when pcap_open_live fails (no root / no devices). */
void capture_start(ntop_state_t *s);

/* Signal the capture thread to stop and block until it exits. */
void capture_stop(void);

#endif /* CAPTURE_H */
