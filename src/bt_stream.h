#ifndef BT_STREAM_H
#define BT_STREAM_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* The Ubertooth capture stream (#144 slice 3): a classic pcap byte
 * stream, framed here into records and dispatched by link type to the
 * pure parsers in src/btle_ll.c and src/bredr_bb.c.
 *
 * libpcap-free on purpose. The worker in src/capture/bt_capture.c reads
 * the operator's file or FIFO with its own poll()/read() loop and hands
 * the bytes here, because libpcap's savefile reader blocks inside
 * fread() on a FIFO whose writer has gone quiet and cannot then be
 * stopped. Owning the framing also keeps every length decision in one
 * pure, fuzzed place.
 *
 * Accepted link types (tcpdump.org link-layer header types):
 *   256  BLUETOOTH_LE_LL_WITH_PHDR   ubertooth-btle -q
 *   192  PPI, inner 251 BLUETOOTH_LE_LL   ubertooth-btle -c
 *   255  BLUETOOTH_BREDR_BB          ubertooth-rx -q
 * Anything else — pcapng included — is refused with a message, and the
 * stream is not read further.
 *
 * Thread model: one stream is fed by one thread (the worker, or a
 * test). The counters and the BR/EDR LAP table sit under the module
 * mutex and are copied out by bt_stream_snapshot() on the poll thread.
 * Advertising observations go to the BLE device table in src/ble_hci.c
 * (sensor kind ble, iface BT_CAPTURE_IFACE). */

/* A record longer than this is skipped and counted as a drop, keeping
 * the stream in step: the pcap-edge gate's own bound (#141). */
#define BT_STREAM_REC_MAX  65535u
/* Longer than this, the length field is not a record length at all
 * and the stream is corrupt from here on: libpcap's own ceiling. */
#define BT_STREAM_REC_SANE 262144u

typedef struct {
    uint8_t  fhdr[24];
    size_t   fhdr_have;
    int      header_done;
    int      swapped;          /* file written big-endian */
    int      nsec;             /* nanosecond timestamps */
    uint32_t dlt;
    uint8_t  rhdr[16];
    size_t   rhdr_have;
    uint32_t incl, orig, ts_sec, ts_frac;
    int      in_record;
    int      skipping;         /* record over BT_STREAM_REC_MAX: discard */
    size_t   have;
    int      finished;         /* refused or corrupt: feed nothing more */
    uint8_t  rec[BT_STREAM_REC_MAX];
} bt_stream_t;

void bt_stream_init(bt_stream_t *st);

/* Feed `n` octets. `wall` is the arrival clock (liveness); records keep
 * their own capture time. Returns 1 while the stream can continue, 0
 * once it has been refused or found corrupt (the state and message are
 * already published). */
int  bt_stream_feed(bt_stream_t *st, const uint8_t *p, size_t n, time_t wall);

/* One framed record of link type `dlt`, past the edge gate. The seam
 * the framer uses and the tests call. */
void bt_stream_record(int dlt, const uint8_t *rec, size_t caplen,
                      time_t frame_ts, time_t wall);

/* --bt-capture given: state WAITING until the header arrives. */
void bt_stream_configure(void);
/* Publish the worker's state and, for REFUSED / ERROR, why. */
void bt_stream_set_state(int state, const char *err);

/* Copy the stream health and the LAP table into `s`; stale_secs is
 * measured against sloth_wall(). */
void bt_stream_snapshot(sloth_state_t *s);

/* Back to OFF, table empty. The eviction tally is untouched. */
void bt_stream_clear(void);

/* Stable names, part of the sensor_health JSONL contract. */
const char *bt_cap_state_name(int state);

#endif /* BT_STREAM_H */
