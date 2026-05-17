#ifndef PCAP_WRITE_H
#define PCAP_WRITE_H

#include "sloth.h"

/*
 * Write the packet ring buffer to a timestamped .pcap file.
 * Returns 0 on success, -1 on error.
 * path_out receives the file path written (may be NULL).
 */
int pcap_export(const sloth_state_t *s, char *path_out, int path_sz);

#endif /* PCAP_WRITE_H */
