#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "mqtt_snoop.h"

static mqtt_flow_t     g_tbl[MAX_MQTT_FLOWS];
static int             g_n  = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* MQTT Control Packet types (high nibble of byte 0). */
#define MQTT_CONNECT      0x10
#define MQTT_CONNACK      0x20
#define MQTT_PUBLISH      0x30
#define MQTT_SUBSCRIBE    0x80
#define MQTT_TYPE_MASK    0xF0

/* CONNECT Connect Flags bits (variable header byte 7 in v3.1.1). */
#define MQTT_FLAG_USERNAME  0x80
#define MQTT_FLAG_PASSWORD  0x40
#define MQTT_FLAG_WILL      0x04

/* CONNACK reason codes that mean bad auth / not-authorised. */
static int connack_is_failure(int proto_level, uint8_t code) {
    if (proto_level <= 4) {
        /* v3.1.1 §3.2.2.3 — values 1..5 are all failures. */
        return code >= 1 && code <= 5;
    }
    /* v5 §3.2.2.2 — anything >= 0x80 is a failure. */
    return code >= 0x80;
}

/* MQTT Remaining Length is a 1-4 byte varint (each byte: bit 7 =
 * continuation, bits 0-6 = value). Returns the value and writes
 * the number of bytes consumed into *consumed, or -1 on overrun. */
static int decode_remaining_length(const uint8_t *p, int len, int *consumed) {
    int v = 0, mul = 1;
    for (int i = 0; i < 4 && i < len; i++) {
        uint8_t b = p[i];
        v += (b & 0x7F) * mul;
        if ((b & 0x80) == 0) {
            *consumed = i + 1;
            return v;
        }
        mul *= 128;
    }
    return -1;
}

/* MQTT UTF-8 string: 2-byte big-endian length + that many bytes.
 * Returns the length value (might be 0) and writes the start byte
 * offset of the string body into *body_off, or -1 if the encoded
 * length runs past the buffer. */
static int read_utf8_string(const uint8_t *p, int len, int *body_off) {
    if (len < 2) return -1;
    int slen = ((int)p[0] << 8) | p[1];
    if (slen < 0 || 2 + slen > len) return -1;
    *body_off = 2;
    return slen;
}

static int find_or_alloc(const char *src_ip, const char *dst_ip) {
    for (int i = 0; i < g_n; i++) {
        if (strcmp(g_tbl[i].src_ip, src_ip) == 0 &&
            strcmp(g_tbl[i].dst_ip, dst_ip) == 0) {
            return i;
        }
    }
    int slot;
    if (g_n < MAX_MQTT_FLOWS) {
        slot = g_n++;
    } else {
        slot = 0;
        for (int i = 1; i < g_n; i++) {
            if (g_tbl[i].last_seen < g_tbl[slot].last_seen) slot = i;
        }
    }
    memset(&g_tbl[slot], 0, sizeof(g_tbl[slot]));
    snprintf(g_tbl[slot].src_ip, sizeof(g_tbl[slot].src_ip), "%s", src_ip);
    snprintf(g_tbl[slot].dst_ip, sizeof(g_tbl[slot].dst_ip), "%s", dst_ip);
    return slot;
}

/* Parse a CONNECT variable-header + payload to pull the protocol
 * level and the username (if Username Flag is set). The buffer
 * here is the body after the fixed header. */
static void parse_connect(const uint8_t *body, int blen,
                          int *out_proto_level, char *out_user, size_t user_cap) {
    *out_proto_level = 0;
    if (user_cap) out_user[0] = '\0';

    /* Protocol Name (UTF-8). v3.1 uses "MQIsdp"; v3.1.1/v5 use "MQTT". */
    int boff = 0;
    int name_body = 0;
    int name_len = read_utf8_string(body + boff, blen - boff, &name_body);
    if (name_len < 0) return;
    int name_off = boff + name_body;
    if (name_off + name_len > blen) return;
    /* Sanity check on the protocol-name string. */
    if (name_len == 4) {
        if (memcmp(body + name_off, "MQTT", 4) != 0) return;
    } else if (name_len == 6) {
        if (memcmp(body + name_off, "MQIsdp", 6) != 0) return;
    } else {
        return;
    }
    boff = name_off + name_len;

    /* Protocol Level (1 byte). */
    if (boff + 1 > blen) return;
    int proto_level = body[boff++];
    *out_proto_level = proto_level;

    /* Connect Flags (1 byte). */
    if (boff + 1 > blen) return;
    uint8_t flags = body[boff++];

    /* Keep Alive (2 bytes). */
    if (boff + 2 > blen) return;
    boff += 2;

    /* v5 has a Properties section here: varint length + bytes. */
    if (proto_level >= 5) {
        int pc = 0;
        int plen = decode_remaining_length(body + boff, blen - boff, &pc);
        if (plen < 0 || boff + pc + plen > blen) return;
        boff += pc + plen;
    }

    /* Payload: ClientID first (UTF-8 string, may be empty). */
    int body_off = 0;
    int slen = read_utf8_string(body + boff, blen - boff, &body_off);
    if (slen < 0) return;
    boff += body_off + slen;

    /* If Will Flag is set: Will Properties (v5 only) + Will Topic +
     * Will Payload — both UTF-8 strings. */
    if (flags & MQTT_FLAG_WILL) {
        if (proto_level >= 5) {
            int pc = 0;
            int plen = decode_remaining_length(body + boff, blen - boff, &pc);
            if (plen < 0 || boff + pc + plen > blen) return;
            boff += pc + plen;
        }
        for (int k = 0; k < 2; k++) {
            int bo = 0;
            int sl = read_utf8_string(body + boff, blen - boff, &bo);
            if (sl < 0) return;
            boff += bo + sl;
        }
    }

    /* User Name (UTF-8 string) — what we want. */
    if (flags & MQTT_FLAG_USERNAME) {
        int bo = 0;
        int sl = read_utf8_string(body + boff, blen - boff, &bo);
        if (sl < 0) return;
        int str_off = boff + bo;
        if (str_off + sl > blen) return;
        /* Copy + sanitize (printable ASCII only — defeats JSONL
         * injection via crafted usernames). */
        size_t k = 0;
        for (int i = 0; i < sl && k + 1 < user_cap; i++) {
            uint8_t c = body[str_off + i];
            if (c < 0x20 || c > 0x7E) { out_user[0] = '\0'; return; }
            out_user[k++] = (char)c;
        }
        if (user_cap) out_user[k] = '\0';
    }
}

int mqtt_snoop_observe(const char *src_ip, uint16_t src_port,
                       const char *dst_ip, uint16_t dst_port,
                       const uint8_t *payload, int len) {
    if (!src_ip || !dst_ip || !payload || len < 2) return 0;
    if (src_port != 1883 && dst_port != 1883) return 0;

    uint8_t type_byte = payload[0];
    uint8_t type = type_byte & MQTT_TYPE_MASK;
    if (type != MQTT_CONNECT && type != MQTT_CONNACK &&
        type != MQTT_PUBLISH && type != MQTT_SUBSCRIBE) return 0;

    /* Remaining Length varint. */
    int rl_consumed = 0;
    int rl = decode_remaining_length(payload + 1, len - 1, &rl_consumed);
    if (rl < 0) return 0;
    int hdr_len = 1 + rl_consumed;
    if (hdr_len + rl > len) return 0;

    const uint8_t *body = payload + hdr_len;
    int blen = rl;

    /* Direction: client → broker is the brute-force-relevant side.
     * CONNECT / SUBSCRIBE / PUBLISH (when QoS 1+) all flow that
     * way; CONNACK flows back. Whichever side has dst_port=1883
     * is the client; if src_port=1883 it's the broker replying. */
    const char *client_ip, *broker_ip;
    if (dst_port == 1883) {
        client_ip = src_ip;
        broker_ip = dst_ip;
    } else {
        client_ip = dst_ip;
        broker_ip = src_ip;
    }
    (void)src_port;

    int proto_level_out = 0;
    char username[MQTT_USERNAME_LEN];
    username[0] = '\0';

    int connack_fail = 0;
    if (type == MQTT_CONNECT) {
        parse_connect(body, blen, &proto_level_out, username, sizeof(username));
    } else if (type == MQTT_CONNACK) {
        /* v3.1.1 §3.2.2: byte 0 = ack flags, byte 1 = return code.
         * v5 §3.2.2.2: byte 0 = ack flags, byte 1 = reason code. */
        if (blen >= 2) {
            uint8_t code = body[1];
            /* Use whatever proto_level we already learned on the flow
             * — CONNACK alone doesn't tell us. Default to v3.1.1 (4)
             * since that's the dominant deployment. */
            int pl = 4;
            connack_fail = connack_is_failure(pl, code);
        }
    }

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);
    int idx = find_or_alloc(client_ip, broker_ip);
    mqtt_flow_t *e = &g_tbl[idx];
    if (e->first_seen == 0) e->first_seen = now;
    e->last_seen = now;

    switch (type) {
    case MQTT_CONNECT:
        e->connect_count++;
        if (proto_level_out > 0) e->proto_level = proto_level_out;
        if (username[0])
            snprintf(e->last_username, sizeof(e->last_username),
                     "%s", username);
        break;
    case MQTT_CONNACK:
        if (connack_fail) e->connack_fail_count++;
        break;
    case MQTT_SUBSCRIBE:
        e->subscribe_count++;
        break;
    case MQTT_PUBLISH:
        e->publish_count++;
        break;
    default: break;
    }
    pthread_mutex_unlock(&g_mu);
    return 1;
}

void mqtt_snoop_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_MQTT_FLOWS ? g_n : MAX_MQTT_FLOWS;
    for (int i = 0; i < n; i++) s->mqtt_flows[i] = g_tbl[i];
    s->mqtt_flow_count = n;
    pthread_mutex_unlock(&g_mu);
}

void mqtt_snoop_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}
