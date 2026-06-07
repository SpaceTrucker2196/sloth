#ifndef MQTT_SNOOP_H
#define MQTT_SNOOP_H

#include <stdint.h>
#include "sloth.h"

/* MQTT v3.1 / v3.1.1 / v5 snoop — TCP/1883 (cleartext broker).
 *
 * Parses the MQTT Control Packet fixed header and recognises the
 * Connect / Connack / Subscribe / Publish types. CONNECT payloads
 * are walked to pull the protocol level and the username (when the
 * User Name Flag is set). CONNACK reason codes are read to detect
 * bad-credential responses. Returns 1 on a parseable MQTT packet,
 * 0 otherwise. */
int  mqtt_snoop_observe(const char *src_ip, uint16_t src_port,
                        const char *dst_ip, uint16_t dst_port,
                        const uint8_t *payload, int len);

void mqtt_snoop_snapshot(sloth_state_t *s);
void mqtt_snoop_clear   (void);

#endif /* MQTT_SNOOP_H */
