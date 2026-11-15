#ifndef SLOTH_CAPTURE_SIDE_H
#define SLOTH_CAPTURE_SIDE_H

/* What a daemon with a capture plugs into the services both daemons
 * share (#213, ADR 0010).
 *
 * The alert engine, sys_status and the memory sample used to name the
 * capture's modules directly: the whole rule table and the pcap
 * exporters, the four capture source rows and the beacon-recall
 * sample, the resolver's call count. Linking any of the three linked
 * the capture, so sloth-rf could not use them. Each now takes that part
 * as data, and this is the one place that hands it over:
 *
 *   alerts_set_table()               every rule, its history, the two
 *                                    pcap exporters   (alerts/rules.h)
 *   sys_status_set_capture_side()    capture, monitor, btmon, btcap rows
 *                                    and the recall sample (sys_status.h)
 *   sh_set_resolver_calls_fn()       the resolver's count (sensor_health.h)
 *
 * `sloth` calls it first thing in main(), and the test binary before
 * its first suite. sloth-rf does not link this file: it selects its
 * own rule table and registers nothing else, which is what "no capture"
 * means to the three services. Idempotent. */
void capture_side_install(void);

#endif /* SLOTH_CAPTURE_SIDE_H */
