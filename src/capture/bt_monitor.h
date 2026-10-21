#ifndef CAPTURE_BT_MONITOR_H
#define CAPTURE_BT_MONITOR_H

#include <stdint.h>
#include <stdio.h>
#include "sloth.h"

/* The Bluetooth HCI monitor capture worker (#144 slice 2, --bt-monitor).
 *
 * One libpcap handle on BT_MONITOR_DEVICE ("bluetooth-monitor",
 * DLT 254), opened before the privilege drop beside the IP handle —
 * binding HCI_CHANNEL_MONITOR needs CAP_NET_RAW — and read on its own
 * worker. Every record goes through the pcap-edge gate and then to
 * ble_mon_ingest() (src/ble_hci.c), which owns the allow-list.
 *
 * This module never sends. The handle has no transmit path in the
 * kernel, and nothing here calls a libpcap send function on it; nor
 * does sloth issue any HCI or MGMT command anywhere. The operator's own
 * stack starts the passive scan (docs/wiki/ble.md).
 *
 * Opt-in: nothing opens unless main() calls bt_monitor_open(). */

#ifdef WITH_PCAP

/* Open BT_MONITOR_DEVICE without starting the worker. Sets s->bt_iface
   on success and s->bt_err on failure (no such device, permission, a
   datalink other than 254). Returns 0 on success, -1 otherwise. */
int  bt_monitor_open(sloth_state_t *s);

/* Start the worker on the handle bt_monitor_open() made; no-op without one. */
void bt_monitor_run(void);

/* Stop and join the worker; close the handle. */
void bt_monitor_stop(void);

int  bt_monitor_is_open(void);

/* Liveness, drops and freshness for sensor_health, as capture_health_poll(). */
void bt_monitor_health_poll(capture_health_t *h);

/* Dispatch DLT 254 records through the worker's own callback,
   synchronously, from an in-memory savefile (no device). The --replay
   route for DLT 254 and the test seam. ts_secs / orig_lens may be NULL.
   Returns the records libpcap handed to the callback, or -1. */
int  bt_monitor_dispatch_frames(const uint8_t *const *frames, const int *lens,
                                const int *orig_lens, const uint32_t *ts_secs,
                                int n);

#else

static inline int  bt_monitor_open(sloth_state_t *s)
    { if (s) snprintf(s->bt_err, sizeof(s->bt_err), "built without libpcap"); return -1; }
static inline void bt_monitor_run(void)     {}
static inline void bt_monitor_stop(void)    {}
static inline int  bt_monitor_is_open(void) { return 0; }
static inline void bt_monitor_health_poll(capture_health_t *h)
    { if (h) { h->open = 0; h->running = 0; } }

#endif /* WITH_PCAP */

#endif /* CAPTURE_BT_MONITOR_H */
