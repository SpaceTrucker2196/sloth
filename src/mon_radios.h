#ifndef SLOTH_MON_RADIOS_H
#define SLOTH_MON_RADIOS_H

#include <stddef.h>
#include <stdint.h>

#include "wifi_chanhop.h"

/* Several sensor radios (2026-11-16, owner: "go with multi radio mode").
 *
 * --monitor-iface is repeatable. The first names radio 0, the radio
 * probe.c has always opened; each further one (up to MON_RADIO_MAX - 1)
 * is another SENSOR radio: its frames go down the same 802.11 path as
 * radio 0's, into the same parsers, detectors, tables and alerts
 * (src/capture/mon_radio.c opens it and runs its reader thread). This
 * is not --df-iface (src/df.h), whose radios are read for a signal
 * level and nothing else.
 *
 * This file is the part with no libpcap in it, so the suite can test
 * it: the registry of radios and their state, the cross-radio
 * de-duplication, the split of the hop list, and the CLI rules.
 *
 * ── De-duplication ──
 *
 * Two radios in range of one transmission each deliver the frame. Left
 * alone, every flood window, counter, sequence tracker and evidence
 * record would see it once per radio. So a frame is looked up before
 * anything reads it: if an identical frame was delivered from a
 * DIFFERENT radio within MON_DEDUP_WINDOW_US of this one's capture
 * time, it is a duplicate, counted against the radio that brought it
 * and dropped.
 *
 * Identity is the whole 802.11 frame after the radiotap header, FCS
 * off: a 64-bit hash of every octet, and beside it, compared exactly,
 * the length, Frame Control (so the Retry bit), Sequence Control and
 * the transmitter address (the receiver address of a frame that has no
 * transmitter). A retransmission has Retry set where the original has
 * it clear, so it is a different frame and is delivered.
 *
 * The first radio to deliver a frame owns it for the window; only the
 * OTHER radios' copies are dropped. Frames from one radio are never
 * compared with each other, so with one radio nothing changes, and N
 * identical frames heard by two radios are delivered N times, not 2N
 * and not once: a flood of identical RTS or CTS frames, which carry no
 * sequence number, still counts as the flood one radio heard.
 *
 * What that costs, named. Control frames (and two retransmissions of
 * one frame, which are octet-identical) cannot be told from their own
 * repeats, so a repeat only a non-owning radio heard, inside the
 * window, is dropped: the count is the owning radio's, never the sum
 * and not always the union. A frame one radio received damaged
 * (FCS failed) has different octets, is not a duplicate, and is
 * counted where a failed FCS is counted, once per radio that got it
 * damaged.
 *
 * The window. Measured on beta-site (three RTL8821AU on one hub,
 * 2026-11-16, 657 frames two radios both delivered): the capture
 * timestamps of the two copies differed by at most 78 us; the nearest
 * octet-identical repeat on ONE radio (a second retransmission) came
 * 203 us after the first. 5 ms is sixty times the first figure, for a
 * loaded host.
 *
 * The reader threads take their frames in blocks (libpcap's 100 ms
 * buffer timeout), so one radio's copy can be PROCESSED long after the
 * other's although their capture times agree. The table is therefore
 * keyed by capture time, not arrival order: an entry lives in the
 * bucket of its hash and its time slot, a lookup reads the slot and
 * its two neighbours, and nothing is expired by a clock. A full bucket
 * evicts its oldest entry (counted: a duplicate of an evicted frame is
 * delivered). Fixed memory, no allocation.
 *
 * ── Hopping ──
 *
 * Under --hop the list is dealt out: with R radios alive, radio k
 * takes entries k, k+R, k+2R, ... of the list (chanhop_split()). The
 * shares are disjoint, so no two radios sit on one channel, each
 * channel is visited once a cycle, and every channel waits the same
 * number of dwells for its revisit. Each radio keeps its own scheduler
 * and dwell. When a radio is lost the list is dealt again among the
 * ones left, so its channels are not abandoned. */

#define MON_RADIO_MAX        4            /* radio 0 and three more */
#define MON_DEDUP_WINDOW_US  5000
#define MON_DEDUP_BUCKETS    4096         /* a power of two */
#define MON_DEDUP_WAYS       4

typedef enum {
    MON_RADIO_NAMED = 0,     /* on the command line; not opened */
    MON_RADIO_OPEN,          /* handle open, reader not started */
    MON_RADIO_RUNNING,
    MON_RADIO_LOST,          /* the reader ended on its own: the device went */
    MON_RADIO_STOPPED        /* the reader was asked to end */
} mon_radio_state_t;

typedef struct {
    char              iface[16];
    mon_radio_state_t state;
    char              err[80];        /* why NAMED stayed NAMED, or why LOST */
    uint64_t          frames;         /* delivered to the 802.11 path */
    uint64_t          dup_dropped;    /* another radio had delivered them */
    int               freq_mhz;       /* of the newest frame it received, 0 none */
    /* Its share of the hop list (radios 1..; radio 0's is sloth_state_t's
     * chan_* and hop_* as before). 0 channels: not hopping. */
    int               hop_channels;
    int               chan_requested;
    int               chan_confirmed;
    int               retune_failures;
    int               retune_last_errno;
} mon_radio_t;

/* Forget every radio, the de-duplication table and the hop state. */
void mon_radios_reset(void);

/* Register a radio; its index (0 first), or -1 when the table is full,
 * the name is empty or too long, or already registered. Before any
 * reader thread starts. Nothing is registered in a one-radio run. */
int  mon_radios_add(const char *iface);
int  mon_radios_count(void);
/* Radios beyond radio 0 that were named. */
int  mon_radios_extra(void);
/* Whether a second radio is registered: the check the frame path makes. */
int  mon_radios_active(void);
int  mon_radios_get(int radio, mon_radio_t *out);
void mon_radios_set_state(int radio, mon_radio_state_t st, const char *err);
const char *mon_radio_state_name(mon_radio_state_t st);
/* A radio whose frames can still arrive. */
int  mon_radio_alive(mon_radio_state_t st);
/* All radios' dup_dropped, and live entries the table had to evict. */
uint64_t mon_radios_dup_total(void);
uint64_t mon_dedup_evicted(void);

/* One frame from `radio`: dot11/len is the 802.11 frame after radiotap
 * with the FCS off, ts_us its capture time in microseconds (<= 0: the
 * capture's clock is unusable, the frame is delivered unexamined). 1
 * to deliver it, 0 for a duplicate. Counts it either way. With no
 * second radio registered it returns 1 and touches nothing.
 * Thread-safe. */
int  mon_radio_frame(int radio, const uint8_t *dot11, int len, int64_t ts_us,
                     int freq_mhz);

/* The lookup alone, for the tests: 1 when (dot11, len) at ts_us from
 * `radio` duplicates a frame another radio delivered. */
int  mon_dedup_is_dup(int radio, const uint8_t *dot11, int len, int64_t ts_us);

/* ── Hopping ── */

/* Deal the hop list. *h0 is radio 0's scheduler holding the WHOLE list
 * (chanhop_init_default()); on return it holds radio 0's share and the
 * other live radios have theirs. The number of radios sharing. With no
 * second radio registered it leaves *h0 alone and returns 1. */
int  mon_hop_setup(chanhop_t *h0);

/* One poll of the other radios' schedulers, against g_platform: frames
 * since the last call to each radio's channel, tick, retune, record.
 * Radio 0 is chanhop_service()'s as before. When a radio has been lost
 * since the last deal, deals again (radio 0's share too) and returns
 * 1; 0 otherwise. */
int  mon_hop_service(chanhop_t *h0, uint64_t now_ms);

/* Frames radio 0 delivered since the last call: what its scheduler is
 * fed when other radios are registered (mon_frame_total() counts every
 * radio's). */
uint32_t mon_hop_radio0_delta(void);
/* The centre frequencies of the whole --hop list, as mon_hop_setup()
 * was given it (before the deal); the count written, 0 with no list. */
int  mon_hop_plan_mhz(int *mhz, int max);
/* Radio k's scheduler (k >= 1) while it holds a share of the list,
 * NULL otherwise (radio 0's is the caller's own). Main thread only, as
 * the schedulers are: the per-interval coverage record (#242) reads its
 * slots' time and frames after mon_hop_service(). */
const chanhop_t *mon_hop_sched(int radio);
/* The same, writable: the cue table (#248, src/chancue.h) marks a cued
 * channel on whichever radio's share holds it. Main thread only. */
chanhop_t *mon_hop_sched_rw(int radio);

/* ── Command line ── */

typedef struct {
    const char *name[MON_RADIO_MAX];
    int         n;
} mon_cli_t;

/* One --monitor-iface NAME. 1, or 0 with the line to print in err: not
 * an interface name, a raw HCI device, the name given before, or more
 * than MON_RADIO_MAX - 1 beside the first. */
int  mon_cli_add(mon_cli_t *c, const char *name, char *err, size_t errsz);

/* The whole command line: 1, or 0 with the line in err when further
 * radios were named and the run is a --replay, the build has no
 * libpcap, or one of them is also a --df-iface radio. */
int  mon_cli_check(const mon_cli_t *c, const char *const *df_names, int df_n,
                   int replay, int have_pcap, char *err, size_t errsz);

#endif
