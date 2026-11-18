/* src/dot11_ie.c notes an element walk that ran past its buffer in
 * sloth's sensor-health counters (sh_parse_fault_note(), src/
 * sensor_health.c). slothweb links dot11_ie.c for the alert page's
 * packet capture (web/src/web_pcap.c) but keeps no sensor-health
 * counters and must not link sensor_health.c, which pulls sloth.h: the
 * overrun is already a truncated decode on the page, so the note is
 * dropped here. */
#include "sensor_health.h"

void sh_parse_fault_note(sh_parse_fault_t kind) { (void)kind; }
