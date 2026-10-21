#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "bt_stream.h"
#include "btle_ll.h"
#include "bredr_bb.h"
#include "ble_hci.h"
#include "ble_snoop.h"
#include "capture/frame_edge.h"
#include "sensor_health.h"
#include "sloth_clock.h"
#include "stab.h"

/* Contract in bt_stream.h. The savefile layout read here is libpcap's
 * classic format (pcap-savefile(5); IETF draft-ietf-opsawg-pcap): a
 * 24-octet file header (magic, version 2.4, thiszone, sigfigs, snaplen,
 * link type) and per record a 16-octet header (seconds, fraction,
 * captured length, original length), all in the writer's byte order,
 * which the magic tells. */

#define MAGIC_USEC 0xA1B2C3D4u
#define MAGIC_NSEC 0xA1B23C4Du
#define MAGIC_PCAPNG_SHB 0x0A0D0D0Au

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static bt_capture_health_t g_h;
static int g_h_init;

static int lap_eq(const void *row, const void *key) {
    return ((const bredr_lap_t *)row)->lap == *(const uint32_t *)key;
}
/* STAB_OLDEST, as for the advertiser table: the LAPs on the air are the
 * neighbourhood's choice, so a crowd churns the table rather than
 * freezing it, and every loss lands in evict_bredr_lap. */
STAB_DECL(g_laps, bredr_lap_t, MAX_BREDR_LAPS, last_seen, STAB_OLDEST,
          SH_EVICT_BREDR_LAP, NULL, lap_eq);

static void h_init_locked(void) {
    if (g_h_init) return;
    memset(&g_h, 0, sizeof(g_h));
    g_h.state       = BT_CAP_OFF;
    g_h.dlt         = -1;
    g_h.refused_dlt = -1;
    g_h.stale_secs  = -1;
    g_h_init = 1;
}

const char *bt_cap_state_name(int state) {
    switch (state) {
    case BT_CAP_OFF:       return "off";
    case BT_CAP_WAITING:   return "waiting";
    case BT_CAP_STREAMING: return "streaming";
    case BT_CAP_EOF:       return "eof";
    case BT_CAP_REFUSED:   return "refused";
    case BT_CAP_ERROR:     return "error";
    case BT_CAP_STOPPED:   return "stopped";
    default:               return "";
    }
}

void bt_stream_configure(void) {
    pthread_mutex_lock(&g_mu);
    h_init_locked();
    g_h.configured = 1;
    g_h.state      = BT_CAP_WAITING;
    pthread_mutex_unlock(&g_mu);
}

void bt_stream_set_state(int state, const char *err) {
    pthread_mutex_lock(&g_mu);
    h_init_locked();
    g_h.state = state;
    if (err) snprintf(g_h.err, sizeof(g_h.err), "%s", err);
    pthread_mutex_unlock(&g_mu);
}

static void refuse_dlt_locked(uint32_t dlt) {
    g_h.state       = BT_CAP_REFUSED;
    g_h.refused_dlt = dlt > 0x7FFFFFFFu ? 0x7FFFFFFF : (int)dlt;
    snprintf(g_h.err, sizeof(g_h.err),
             "link type %u refused: want 256 (BLE LL + PHDR), "
             "192 (PPI around 251) or 255 (BR/EDR)", (unsigned)dlt);
}

/* ── Records ───────────────────────────────────────────────────────── */

static void lap_observe_locked(const bredr_bb_t *b, time_t ts) {
    int created = 0;
    bredr_lap_t *r = stab_get(&g_laps, &b->lap, ts, &created);
    if (!r) return;
    if (created) {
        r->lap        = b->lap;
        r->first_seen = ts;
        r->rssi_best  = -128;
    }
    r->last_seen = ts;
    r->channel   = (int8_t)b->rf_channel;
    r->count++;
    if (b->signal_valid) {
        r->has_rssi = 1;
        r->rssi     = b->signal_dbm;
        if (b->signal_dbm > r->rssi_best) r->rssi_best = b->signal_dbm;
    }
    /* The tool's reference names this LAP only when its reference LAP
     * is this LAP too; a reference UAP for some other piconet says
     * nothing about this one. */
    if (b->ref_uap_tool && b->ref_lap_valid && b->ref_lap == b->lap) {
        r->ref_uap_tool = 1;
        r->ref_uap            = b->ref_uap;
    }
}

static void ble_record_locked(int dlt, const uint8_t *rec, size_t len,
                              time_t ts) {
    btle_pkt_t p;
    btle_verdict_t v = dlt == BTLE_DLT_LL_PHDR
        ? btle_phdr_record_parse(rec, len, &p)
        : btle_ppi_record_parse(rec, len, &p);
    if (v != BTLE_V_MALFORMED && p.truncated) g_h.truncated++;
    switch (v) {
    case BTLE_V_ADV: {
        ble_adv_report_t r;
        if (!btle_adv_report(&p, &r)) { g_h.drop++; break; }
        /* Lock order: this module, then ble_hci's. ble_hci never calls
         * back here. */
        ble_obs_t o = { &r, SENSOR_BLE, BT_CAPTURE_IFACE, 0,
                        p.channel_index, 1, ts };
        ble_dev_observe(&o);
        g_h.adv++;
        break;
    }
    case BTLE_V_SCAN_REQ:    g_h.scan_req++;    break;
    case BTLE_V_CONNECT_IND: g_h.connect_ind++; break;
    case BTLE_V_EXT_ADV:     g_h.ext_adv++;     break;
    case BTLE_V_DATA:        g_h.data_pdus++;   break;
    case BTLE_V_OTHER:       g_h.other++;       break;
    case BTLE_V_MALFORMED:
    default:                 g_h.drop++;        break;
    }
}

void bt_stream_record(int dlt, const uint8_t *rec, size_t caplen,
                      time_t frame_ts, time_t wall) {
    pthread_mutex_lock(&g_mu);
    h_init_locked();
    g_h.recv++;
    g_h.last_frame_ts   = frame_ts;
    g_h.last_frame_wall = wall;
    if (dlt == BTLE_DLT_LL_PHDR || dlt == BTLE_DLT_PPI) {
        ble_record_locked(dlt, rec, caplen, frame_ts);
    } else if (dlt == BREDR_DLT_BB) {
        bredr_bb_t b;
        if (bredr_bb_parse(rec, caplen, &b) != 0) {
            g_h.drop++;
        } else {
            g_h.bredr++;
            /* An inquiry access code is shared by everyone inquiring;
             * it names no piconet, so it gets a count, not a row. */
            if (b.iac) g_h.bredr_iac++;
            else       lap_observe_locked(&b, frame_ts);
        }
    } else {
        g_h.drop++;
    }
    pthread_mutex_unlock(&g_mu);
}

/* ── Framing ───────────────────────────────────────────────────────── */

static uint32_t rd32(const uint8_t *p, int swapped) {
    if (swapped)
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void bt_stream_init(bt_stream_t *st) {
    if (!st) return;
    /* The record buffer is not cleared: it is written before it is read. */
    memset(st, 0, offsetof(bt_stream_t, rec));
}

static int finish(bt_stream_t *st) { st->finished = 1; return 0; }

static int take_file_header(bt_stream_t *st) {
    const uint8_t *h = st->fhdr;
    uint32_t m = rd32(h, 0);
    if      (m == MAGIC_USEC)                { st->swapped = 0; st->nsec = 0; }
    else if (m == MAGIC_NSEC)                { st->swapped = 0; st->nsec = 1; }
    else if (rd32(h, 1) == MAGIC_USEC)       { st->swapped = 1; st->nsec = 0; }
    else if (rd32(h, 1) == MAGIC_NSEC)       { st->swapped = 1; st->nsec = 1; }
    else {
        bt_stream_set_state(BT_CAP_REFUSED, m == MAGIC_PCAPNG_SHB
            ? "pcapng refused: write classic pcap (ubertooth-btle -q, ubertooth-rx -q)"
            : "not a pcap file");
        return finish(st);
    }
    uint16_t major = st->swapped ? (uint16_t)((h[4] << 8) | h[5])
                                 : (uint16_t)(h[4] | (h[5] << 8));
    if (major != 2) {
        bt_stream_set_state(BT_CAP_REFUSED, "pcap version is not 2.x");
        return finish(st);
    }
    st->dlt = rd32(h + 20, st->swapped);
    pthread_mutex_lock(&g_mu);
    h_init_locked();
    if (st->dlt != BTLE_DLT_LL_PHDR && st->dlt != BTLE_DLT_PPI &&
        st->dlt != BREDR_DLT_BB) {
        refuse_dlt_locked(st->dlt);
        pthread_mutex_unlock(&g_mu);
        return finish(st);
    }
    g_h.dlt         = (int)st->dlt;
    g_h.channels_of = st->dlt == BREDR_DLT_BB ? BREDR_RF_CHANNELS : 40;
    g_h.state       = BT_CAP_STREAMING;
    g_h.err[0]      = '\0';
    pthread_mutex_unlock(&g_mu);
    st->header_done = 1;
    return 1;
}

static void count_drop(time_t wall) {
    pthread_mutex_lock(&g_mu);
    h_init_locked();
    g_h.recv++;
    g_h.drop++;
    g_h.last_frame_wall = wall;
    pthread_mutex_unlock(&g_mu);
}

static void take_record(bt_stream_t *st, time_t wall) {
    long frac = (long)st->ts_frac;
    if (st->nsec) frac /= 1000;
    frame_view_t f;
    if (!frame_view_init(&f, st->rec, st->incl, st->orig,
                         (long)st->ts_sec, frac, (int)st->dlt)) {
        sh_parse_fault_note(SH_PF_FRAME_EDGE);
        count_drop(wall);
        return;
    }
    bt_stream_record(f.dlt, f.data, (size_t)f.caplen, f.ts_sec, wall);
}

int bt_stream_feed(bt_stream_t *st, const uint8_t *p, size_t n, time_t wall) {
    if (!st || st->finished) return 0;
    while (n > 0) {
        if (!st->header_done) {
            size_t k = sizeof(st->fhdr) - st->fhdr_have;
            if (k > n) k = n;
            memcpy(st->fhdr + st->fhdr_have, p, k);
            st->fhdr_have += k; p += k; n -= k;
            if (st->fhdr_have == sizeof(st->fhdr) && !take_file_header(st))
                return 0;
            continue;
        }
        if (!st->in_record) {
            size_t k = sizeof(st->rhdr) - st->rhdr_have;
            if (k > n) k = n;
            memcpy(st->rhdr + st->rhdr_have, p, k);
            st->rhdr_have += k; p += k; n -= k;
            if (st->rhdr_have < sizeof(st->rhdr)) continue;
            st->rhdr_have = 0;
            st->ts_sec  = rd32(st->rhdr, st->swapped);
            st->ts_frac = rd32(st->rhdr + 4, st->swapped);
            st->incl    = rd32(st->rhdr + 8, st->swapped);
            st->orig    = rd32(st->rhdr + 12, st->swapped);
            if (st->incl > BT_STREAM_REC_SANE) {
                char why[96];
                snprintf(why, sizeof(why),
                         "record length %u: stream corrupt",
                         (unsigned)st->incl);
                bt_stream_set_state(BT_CAP_ERROR, why);
                return finish(st);
            }
            st->in_record = 1;
            st->skipping  = st->incl > BT_STREAM_REC_MAX;
            st->have      = 0;
        }
        size_t k = st->incl - st->have;
        if (k > n) k = n;
        if (!st->skipping) memcpy(st->rec + st->have, p, k);
        st->have += k; p += k; n -= k;
        if (st->have < st->incl) continue;
        st->in_record = 0;
        if (st->skipping) count_drop(wall);
        else              take_record(st, wall);
    }
    return 1;
}

/* ── Snapshot ──────────────────────────────────────────────────────── */

void bt_stream_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    h_init_locked();
    s->btcap = g_h;
    s->btcap.stale_secs = g_h.last_frame_wall
        ? (int)(sloth_wall() - g_h.last_frame_wall) : -1;
    s->bredr_lap_count = stab_snapshot(&g_laps, s->bredr_laps, MAX_BREDR_LAPS);
    pthread_mutex_unlock(&g_mu);
}

void bt_stream_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_laps);
    g_h_init = 0;
    h_init_locked();
    pthread_mutex_unlock(&g_mu);
}
