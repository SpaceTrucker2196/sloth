#ifndef SLOTH_COV_INTERVAL_CAPTURE_H
#define SLOTH_COV_INTERVAL_CAPTURE_H

#include <stdint.h>
#include <time.h>
#include "sloth.h"
#include "dot11_frame.h"
#include "wifi_chanhop.h"
#include "cov_interval.h"

/* The capture side of the per-interval coverage record (#242 item 2):
 * where the figures of cov_interval.h come from in sloth-wifi. sloth-rf
 * links none of this; nothing it references names it.
 *
 * Time on a channel. A radio under --hop: its scheduler's own dwell
 * accounting (chanhop_slot_time_ms(), the closed dwells and the open
 * one, start-of-dwell to start-of-next, so the poll loop's servicing
 * delay is inside the figure, as in hop_dwell_measured_ms). A radio
 * that is not retuned: the whole time it is running, on the frequency
 * of its newest frame (unknown, 0, before one arrives). Radio 0 counts
 * while the monitor worker runs; another radio while its reader is
 * alive.
 *
 * Frames on a channel: the frames the scheduler attributed to the slot
 * (each poll's new frames go to the channel the radio was confirmed
 * on), or a fixed radio's own delivered count.
 *
 * Frames by class: the monitor path's lifetime per-class tally
 * (mon_frame_class_totals()), differenced at the interval's two ends.
 * Every radio's delivered frames, after the cross-radio de-duplication.
 * The capture interface's own 802.11 frames (a capture interface in
 * monitor mode) are decoded for IP only and are not in it.
 *
 * Drops: the pcap_stats() totals of the capture and the monitor
 * handles, differenced. The further --monitor-iface radios take no
 * pcap_stats() sample today, so their drops are not measured.
 *
 * A --replay run writes no record: its frames arrive as fast as the
 * file reads, so a minute of host time holds an arbitrary slice of the
 * file, and there is no radio to dwell anywhere. */

/* The coverage class (COV_FC_*) of one decoded frame. `bad_fcs`: the
 * radio marked it FCS-failed, and its type is not trusted. An EAPOL
 * frame is a data frame whose LLC/SNAP EtherType is 0x888E, the EAPOL
 * EtherType of IEEE 802.1X; a Protected data frame is `data`, its body
 * being ciphertext.
 * Pure. */
int  cov_frame_class(const dot11_frame_t *fr, int bad_fcs);

/* Radio 0's scheduler under --hop (main.c's), NULL without --hop. */
void cov_iv_capture_set_hop0(const chanhop_t *h0);

/* The poll stage: sample the radios and, once an interval is
 * COV_IV_MS old, close it with the class counts, the drops and the
 * sources. Main thread, after the hop stage and the health stage. */
void cov_iv_capture_poll(const sloth_state_t *s, time_t wall, uint64_t mono_ms);

/* Forget the baselines (and cov_iv_reset()); keeps the hop pointer. */
void cov_iv_capture_reset(void);

#endif /* SLOTH_COV_INTERVAL_CAPTURE_H */
