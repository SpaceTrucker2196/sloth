#ifndef CAPTURE_PROBE_INTERNAL_H
#define CAPTURE_PROBE_INTERNAL_H

/* What src/capture/mon_radio.c needs from probe.c, and nobody else.
 * WITH_PCAP only: it names libpcap's types. */

#include <pcap.h>

/* The 802.11 frame path, as a pcap_handler. `user` is the sensor radio's
 * index cast to a pointer (0: the radio probe.c opened). Serialised
 * inside: any radio's reader thread may call it. */
void probe_radio_frame(u_char *user, const struct pcap_pkthdr *hdr,
                       const u_char *data);

/* ARPHRD_* of a netdev (803 is a radiotap monitor interface); -1 when it
 * does not exist, -2 when its type cannot be read. Honours
 * probe_test_set_sysfs_net(). */
int probe_iface_type(const char *name);

#endif
