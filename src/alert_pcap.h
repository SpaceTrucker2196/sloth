#ifndef ALERT_PCAP_H
#define ALERT_PCAP_H

#include "sloth.h"

/* Configure the directory where per-alert pcap snapshots are written.
 *   - NULL or empty: disable export (alert_pcap_dump becomes a no-op).
 *   - Otherwise: pcap files are created under this directory (the caller
 *     must ensure the directory exists). */
void alert_pcap_set_dir(const char *dir);

/* Returns 1 if a dir was configured. */
int  alert_pcap_enabled(void);

/* Walk s->packets[] and write any packets matching alert->match_ip
 * (and match_port, if non-zero) to a fresh pcap file under the
 * configured dir. Returns the number of packets written, or -1 on error.
 * If out_path is non-NULL, the file path is written there. */
int  alert_pcap_dump(const sloth_state_t *s, const alert_t *a,
                     char *out_path, int out_sz);

#endif /* ALERT_PCAP_H */
