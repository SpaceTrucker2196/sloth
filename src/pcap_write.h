#ifndef PCAP_WRITE_H
#define PCAP_WRITE_H

#include <stddef.h>
#include <time.h>

#include "sloth.h"

/*
 * Write the packet ring buffer to a timestamped .pcap file.
 * Returns 0 on success, -1 on error.
 * path_out receives the file path written (may be NULL).
 */
int pcap_export(const sloth_state_t *s, char *path_out, int path_sz);

/*
 * Build the "ntop_YYYYMMDD_HHMMSS" filename stem from a broken-down local
 * time. `t` may be NULL — localtime_r() fails for a time_t whose year does
 * not fit struct tm — and the epoch stem is used instead.
 *
 * Split out of pcap_export() so that branch is reachable from a test:
 * time(NULL) cannot be steered into failing localtime_r() portably.
 */
void pcap_export_stem(const struct tm *t, char *out, size_t sz);

#endif /* PCAP_WRITE_H */
