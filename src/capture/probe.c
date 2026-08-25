#ifdef WITH_PCAP

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <pcap.h>

#include "sloth.h"
#include "capture/probe.h"
#include "radiotap.h"
#include "rf_quality.h"
#include "beacon_snoop.h"
#include "deauth_snoop.h"
#include "probe_pnl.h"
#include "eapol_log.h"
#include "seqnum_track.h"
#include "assoc_track.h"
#include "auth_track.h"
#include "action_snoop.h"

#ifdef PLATFORM_LINUX
#  include <dirent.h>
#endif

/* ── Internal client table ───────────────────────────────── */

static probe_client_t  g_clients[MAX_PROBE_CLIENTS];
static int             g_count   = 0;
static pthread_mutex_t g_mu      = PTHREAD_MUTEX_INITIALIZER;

/* ── Raw 802.11 frame ring (monitor packets band) ────────── */

static mon_frame_t     g_frames[MAX_MON_FRAMES];
static int             g_frame_head;
static int             g_frame_count;
static uint64_t        g_frame_total;   /* cumulative frames ever seen (#28 sensor) */
static pthread_mutex_t g_frame_mu = PTHREAD_MUTEX_INITIALIZER;

uint64_t mon_frame_total(void) {
    pthread_mutex_lock(&g_frame_mu);
    uint64_t t = g_frame_total;
    pthread_mutex_unlock(&g_frame_mu);
    return t;
}

/* Human subtype label for a frame's (type, subtype). */
static const char *frame_label(uint8_t type, uint8_t sub) {
    if (type == 0) {   /* management */
        switch (sub) {
        case 0:  return "AssocReq";  case 1:  return "AssocRsp";
        case 2:  return "ReassoReq"; case 3:  return "ReassoRsp";
        case 4:  return "ProbeReq";  case 5:  return "ProbeRsp";
        case 8:  return "Beacon";    case 10: return "Disassoc";
        case 11: return "Auth";      case 12: return "Deauth";
        case 13: return "Action";    default: return "Mgmt";
        }
    }
    if (type == 1) {   /* control */
        switch (sub) {
        case 9:  return "BlockAck";  case 11: return "RTS";
        case 12: return "CTS";       case 13: return "ACK";
        default: return "Ctrl";
        }
    }
    if (type == 2) return (sub & 0x08) ? "QoSData" : "Data";
    return "Ext";
}

/* Record one captured 802.11 frame (called under no lock from the pcap
 * thread). a1/a2 may be NULL for short frames. */
static void mon_frame_record(uint8_t type, uint8_t sub,
                             const uint8_t *a1, const uint8_t *a2,
                             uint16_t len, int8_t signal) {
    pthread_mutex_lock(&g_frame_mu);
    mon_frame_t *f = &g_frames[g_frame_head];
    f->ts         = time(NULL);
    f->signal_dbm = signal;
    f->len        = len;
    f->type       = type;
    f->subtype    = sub;
    if (a1) memcpy(f->addr1, a1, 6); else memset(f->addr1, 0, 6);
    if (a2) memcpy(f->addr2, a2, 6); else memset(f->addr2, 0, 6);
    snprintf(f->label, sizeof(f->label), "%s", frame_label(type, sub));
    g_frame_head = (g_frame_head + 1) % MAX_MON_FRAMES;
    if (g_frame_count < MAX_MON_FRAMES) g_frame_count++;
    g_frame_total++;
    pthread_mutex_unlock(&g_frame_mu);
}

void mon_frame_snapshot(sloth_state_t *s) {
    pthread_mutex_lock(&g_frame_mu);
    int n = g_frame_count;
    for (int i = 0; i < n; i++) {   /* newest first */
        int idx = (g_frame_head - 1 - i + MAX_MON_FRAMES) % MAX_MON_FRAMES;
        s->mon_frames[i] = g_frames[idx];
    }
    s->mon_frame_count = n;
    pthread_mutex_unlock(&g_frame_mu);
}

/* ── Thread state ────────────────────────────────────────── */

static volatile int  g_running = 0;
static pthread_t     g_thread;
static pcap_t       *g_ph      = NULL;
static sloth_state_t *g_state   = NULL;

/* ── Monitor interface discovery ─────────────────────────── */

#ifdef PLATFORM_LINUX
static int find_monitor_iface(char *buf, int sz) {
    DIR *d = opendir("/sys/class/net");
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        /* Linux iface names are IFNAMSIZ-1 = 15 chars max. Anything
         * longer can't be a real interface and would also bust the
         * snprintf buffers below. */
        size_t nlen = strlen(e->d_name);
        if (nlen >= 16) continue;
        char path[128];
        snprintf(path, sizeof(path), "/sys/class/net/%s/type", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        int type = 0;
        if (fscanf(f, "%d", &type) == 1 && type == 803) { /* ARPHRD_IEEE80211_RADIOTAP */
            fclose(f);
            snprintf(buf, sz, "%s", e->d_name);
            closedir(d);
            return 1;
        }
        fclose(f);
    }
    closedir(d);
    return 0;
}
#else
static int find_monitor_iface(char *buf, int sz) { (void)buf; (void)sz; return 0; }
#endif

/* Radiotap decoding lives in src/radiotap.c so it can be unit-tested —
 * this file is compiled only under WITH_PCAP and is not in the test
 * build, so a parser living here had no coverage. See radiotap.h. */

/* ── Client table update (caller holds g_mu) ─────────────── */

/* Append an observation to a client's RSSI ring (#53). The ring is what
 * lets presence_classify() tell a device that drove past from one that
 * is sitting in the building — dwell alone cannot, because channel
 * hopping makes a resident heard once look brief. Mirrors
 * beacon_snoop's rssi_ring_push; the projection fields that one derives
 * are AP-only and not needed here. */
static void client_rssi_push(probe_client_t *c, int8_t signal, time_t now) {
    rssi_ring_t *r = &c->rssi_ring;
    r->dbm[r->head] = signal;
    r->ts [r->head] = now;
    r->head = (r->head + 1) % RSSI_WIN_SAMPLES;
    if (r->count < RSSI_WIN_SAMPLES) r->count++;
}

static void record_probe(const uint8_t *mac, const char *ssid,
                         int8_t signal, int channel) {
    time_t now = time(NULL);

    /* find existing entry */
    for (int i = 0; i < g_count; i++) {
        if (memcmp(g_clients[i].mac, mac, 6) == 0) {
            g_clients[i].signal_dbm  = signal;
            g_clients[i].channel     = channel;
            g_clients[i].last_seen   = now;
            g_clients[i].frame_count++;
            client_rssi_push(&g_clients[i], signal, now);
            if (ssid[0])   /* prefer named probe over wildcard */
                snprintf(g_clients[i].ssid, sizeof(g_clients[i].ssid),
                         "%s", ssid);
            return;
        }
    }

    /* new entry — evict oldest if full */
    int slot = g_count < MAX_PROBE_CLIENTS ? g_count++ : 0;
    if (g_count == MAX_PROBE_CLIENTS) {
        time_t oldest_ts = g_clients[0].last_seen;
        for (int i = 1; i < g_count; i++) {
            if (g_clients[i].last_seen < oldest_ts) {
                oldest_ts = g_clients[i].last_seen;
                slot = i;
            }
        }
    }

    /* Full reset: the slot may be a recycled eviction, and a stale RSSI
     * ring would attribute the previous device's trajectory to this
     * one — a wrong presence verdict rather than a missing one. */
    memset(&g_clients[slot], 0, sizeof(g_clients[slot]));
    memcpy(g_clients[slot].mac, mac, 6);
    snprintf(g_clients[slot].ssid, sizeof(g_clients[slot].ssid), "%s", ssid);
    g_clients[slot].signal_dbm  = signal;
    g_clients[slot].channel     = channel;
    g_clients[slot].first_seen  = now;
    g_clients[slot].last_seen   = now;
    g_clients[slot].frame_count = 1;
    client_rssi_push(&g_clients[slot], signal, now);
}

/* ── pcap callback ───────────────────────────────────────── */

static void on_probe_frame(u_char *user, const struct pcap_pkthdr *hdr,
                           const u_char *data) {
    (void)user;
    int len = (int)hdr->caplen;
    if (len < 8) return;

    /* parse radiotap header */
    uint16_t rt_len = (uint16_t)(data[2] | (data[3] << 8));
    if ((int)rt_len >= len) return;

    radiotap_info_t rt;
    radiotap_parse(data, len, &rt);
    int8_t signal  = rt.signal_dbm;
    int    channel = rt.channel;

    /* 802.11 frame starts after radiotap */
    const uint8_t *dot11     = data + rt_len;
    int            dot11_len = len  - rt_len;
    /* Minimum framing to read the Frame Control + addr1 (RA): FC(2) +
     * duration(2) + addr1(6) = 10 bytes. Control frames like ACK/CTS are
     * exactly this size. */
    if (dot11_len < 10) return;

    /* Frame Control byte 0: bits 2-3 = type, bits 4-7 = subtype */
    uint8_t fc0  = dot11[0];
    uint8_t type = (fc0 >> 2) & 0x03;
    uint8_t sub  = (fc0 >> 4) & 0x0f;

    /* Per-channel RF quality (roadmap B3). The retry bit is Frame
     * Control byte 1 bit 3; the FCS-failed flag came from radiotap.
     * Counted for every frame type including control frames, because
     * channel health is about the air, not about what the frame said —
     * and a frame that failed its FCS is still evidence the channel is
     * struggling even though its contents are untrustworthy. */
    rf_quality_observe(channel, (dot11[1] & 0x08) ? 1 : 0, rt.bad_fcs,
                       time(NULL));

    /* Log every frame for the monitor packets band, before the per-type
     * dispatch. addr2 (TA/SA) only exists from 16 bytes on — ACK/CTS carry
     * addr1 only, so pass NULL there. */
    mon_frame_record(type, sub, dot11 + 4,
                     dot11_len >= 16 ? dot11 + 10 : NULL,
                     (uint16_t)dot11_len, signal);

    /* The detailed per-type parsers below assume a full management header. */
    if (dot11_len < 24) return;

    /* Data frames (type 2): only of interest for EAPOL-Key extraction.
     * eapol_observe_dot11 internally rejects anything that's not an
     * EAPOL-Key frame, so the cost of unconditional dispatch is just
     * the LLC SNAP check inside. */
    if (type == 2) {
        eapol_observe_dot11(dot11, dot11_len, signal, channel);
        return;
    }
    if (type != 0) return;  /* management frames only beyond this point */

    if (sub == 8) {
        /* Beacon frame — passive AP discovery */
        char    ssid[33]; uint8_t bssid[6]; int channel; char enc[10]; uint16_t bms;
        beacon_rsn_t rsn;
        if (beacon_parse(dot11, dot11_len, signal, ssid, bssid, &channel,
                         enc, &bms, &rsn)) {
            beacon_record(bssid, ssid, signal, channel, enc, bms, &rsn);
            /* A CSA in a beacon is broadcast to every associated client
             * at once (#63). addr2 is passed separately from addr3 even
             * though a beacon's are normally identical — a forged one
             * is where they differ, and that is the whole signal. */
            if (rsn.csa_present)
                csa_observe(dot11 + 16, dot11 + 10,
                            rsn.csa_new_channel, rsn.csa_new_op_class,
                            rsn.csa_switch_mode, rsn.csa_switch_count,
                            CSA_SRC_BEACON, channel, time(NULL));
        }
        return;
    }

    /* Probe-response (5), Association-response (1), Reassoc-response (3)
     * — all carry the real SSID even when the AP's beacon hides it.
     * Assoc/reassoc responses additionally carry a status code that
     * tells us whether the STA actually joined; if so, feed the
     * association tracker. */
    if (sub == 1 || sub == 3 || sub == 5) {
        if (dot11_len < 36) return;
        /* AP → STA: DA(=STA) at addr1, BSSID at addr2/addr3 (same). */
        const uint8_t *sta_p   = dot11 + 4;
        const uint8_t *bssid_p = dot11 + 16;
        /* Status code lives in the assoc/reassoc-resp fixed body:
         *   caps(2) + status(2) + aid(2). probe-resp doesn't have one. */
        int status_ok = 1;
        int fixed = (sub == 5) ? 12 : 6;
        if (sub == 1 || sub == 3) {
            uint16_t status = (uint16_t)(dot11[24 + 2] |
                                          ((uint16_t)dot11[24 + 3] << 8));
            status_ok = (status == 0);
        }
        const uint8_t *ie = dot11 + 24 + fixed;
        int rem = dot11_len - 24 - fixed;
        char ssid[33] = "";
        while (rem >= 2) {
            uint8_t tag = ie[0];
            uint8_t tln = ie[1];
            if (2 + (int)tln > rem) break;
            if (tag == 0) {
                int slen = tln < 32 ? tln : 32;
                memcpy(ssid, ie + 2, (size_t)slen);
                ssid[slen] = '\0';
                break;
            }
            ie += 2 + tln;
            rem -= 2 + tln;
        }
        if (ssid[0]) beacon_reveal_hidden_ssid(bssid_p, ssid);
        if (status_ok && (sub == 1 || sub == 3)) {
            int src = (sub == 1) ? ASSOC_SRC_ASSOC : ASSOC_SRC_REASSOC;
            assoc_observe(bssid_p, sta_p, ssid[0] ? ssid : NULL,
                          src, signal, channel);
        }
        return;
    }

    if (sub == 10 || sub == 12) {
        /* Disassoc (10) or Deauth (12) */
        uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t st;
        if (deauth_parse(dot11, dot11_len, signal, src, dst, bssid, &reason, &st))
            deauth_record(src, dst, bssid, reason, st);
        /* Drop the association for this (BSSID, STA) — either side
         * could be initiating, so try both directions. */
        if (dot11_len >= 22) {
            const uint8_t *a1 = dot11 + 4;
            const uint8_t *a2 = dot11 + 10;
            assoc_forget(a1, a2);
            assoc_forget(a2, a1);
        }
        return;
    }

    if (sub == 11) {
        /* Authentication frame (open / shared-key / SAE / OWE / FILS).
         * We don't decode the algorithm here — the flood signal is the
         * per-AP rate. addr3 (dot11+16) is the BSSID being authenticated
         * to; a burst there means an association-table exhaustion DoS. */
        auth_observe(dot11 + 16, time(NULL));
        return;
    }

    if (sub == 0 || sub == 2) {
        /* Association / reassociation request — #60. The client's side
         * of the exchange: what it asked for, versus what assoc_observe
         * records the AP granting. Parsing lives in assoc_track.c for
         * the same testability reason as the Action dispatch below. */
        assoc_req_t req;
        if (assoc_request_parse(dot11, dot11_len, &req))
            assoc_request_observe(&req, signal, channel);
        return;
    }

    if (sub == 13) {
        /* Action frame (802.11k/v/r) — #59. The whole management
         * surface behind this subtype was previously labelled and
         * dropped. Parsing lives in action_snoop.c rather than here:
         * this file is compiled only under WITH_PCAP and is absent from
         * TEST_SRCS, so logic placed here cannot be tested. */
        action_observe(dot11, dot11_len, time(NULL));
        return;
    }

    if (sub != 4) return;  /* only probe requests beyond this point */

    /* Source Address: bytes 10-15 */
    const uint8_t *sa = dot11 + 10;
    /* Sequence Control field at bytes 22-23 (little-endian).
     * Upper 12 bits = sequence number. Feed the seqnum tracker so we
     * can correlate randomised probe MACs back to the same physical
     * radio across MAC changes. */
    if (dot11_len >= 24) {
        uint16_t sc = (uint16_t)(dot11[22] | (dot11[23] << 8));
        uint16_t seqnum = (uint16_t)(sc >> 4);
        seqnum_track_observe(sa, seqnum);
    }

    /* Parse SSID information element (tag 0) */
    const uint8_t *ie_start = dot11 + 24;
    int            ie_total = dot11_len - 24;
    const uint8_t *ie       = ie_start;
    int            ie_rem   = ie_total;
    char           ssid[33] = "";

    while (ie_rem >= 2) {
        uint8_t tag = ie[0];
        uint8_t tln = ie[1];
        if (2 + (int)tln > ie_rem) break;
        if (tag == 0) {
            int slen = tln < 32 ? tln : 32;
            memcpy(ssid, ie + 2, (size_t)slen);
            ssid[slen] = '\0';
            break;
        }
        ie     += 2 + tln;
        ie_rem -= 2 + tln;
    }

    pthread_mutex_lock(&g_mu);
    record_probe(sa, ssid, signal, channel);
    pthread_mutex_unlock(&g_mu);

    /* OS fingerprint from vendor-specific IEs (strong-signal only). */
    const char *fp  = probe_pnl_fingerprint_ies(ie_start, ie_total);
    /* PHY tier from HT / VHT / HE / EHT IEs. */
    const char *phy = probe_pnl_phy_ies(ie_start, ie_total);

    /* Feed the PNL aggregator — outside the probe-list mutex since
     * probe_pnl_observe takes its own lock. Wildcard probes are dropped
     * inside observe() since they leak no preferred-network info. */
    probe_pnl_observe(sa, ssid, fp, phy);
}

/* ── Capture thread ──────────────────────────────────────── */

static void *probe_thread(void *arg) {
    (void)arg;
    while (g_running) {
        int r = pcap_dispatch(g_ph, 32, on_probe_frame, NULL);
        if (r < 0) break;
    }
    return NULL;
}

/* ── Public API ──────────────────────────────────────────── */

void probe_start(sloth_state_t *s) {
    g_state = s;
    s->probe_err[0] = '\0';

    char iface[16] = "";
    if (!find_monitor_iface(iface, sizeof(iface))) {
        snprintf(s->probe_err, sizeof(s->probe_err),
                 "no monitor-mode iface found (need type 803)");
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    g_ph = pcap_open_live(iface, 65535, 1, 100, errbuf);
    if (!g_ph) {
        snprintf(s->probe_err, sizeof(s->probe_err), "pcap(%s): %.50s", iface, errbuf);
        return;
    }

    int dlt = pcap_datalink(g_ph);
    if (dlt != DLT_IEEE802_11_RADIO) {
        pcap_close(g_ph);
        g_ph = NULL;
        snprintf(s->probe_err, sizeof(s->probe_err),
                 "%s: DLT %d not radiotap", iface, dlt);
        return;
    }

    snprintf(s->probe_iface, sizeof(s->probe_iface), "%s", iface);
    g_running = 1;
    pthread_create(&g_thread, NULL, probe_thread, NULL);
}

void probe_stop(void) {
    if (!g_running) return;
    g_running = 0;
    if (g_ph) pcap_breakloop(g_ph);
    pthread_join(g_thread, NULL);
    if (g_ph) { pcap_close(g_ph); g_ph = NULL; }
}

void probe_snapshot(sloth_state_t *s) {
    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);

    /* age out stale entries in-place */
    int i = 0;
    while (i < g_count) {
        if (now - g_clients[i].last_seen > PROBE_AGE_SECS) {
            g_clients[i] = g_clients[--g_count];
        } else {
            i++;
        }
    }

    /* sort by last_seen descending (insertion sort — table is small) */
    for (int a = 1; a < g_count; a++) {
        probe_client_t tmp = g_clients[a];
        int b = a - 1;
        while (b >= 0 && g_clients[b].last_seen < tmp.last_seen) {
            g_clients[b + 1] = g_clients[b];
            b--;
        }
        g_clients[b + 1] = tmp;
    }

    /* copy to state */
    int n = g_count < MAX_PROBE_CLIENTS ? g_count : MAX_PROBE_CLIENTS;
    memcpy(s->probe_clients, g_clients, (size_t)n * sizeof(probe_client_t));
    s->probe_count = n;
    if (s->probe_sel >= n) s->probe_sel = n > 0 ? n - 1 : 0;

    pthread_mutex_unlock(&g_mu);
}

void probe_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_count = 0;
    pthread_mutex_unlock(&g_mu);
}

void probe_set_iface(sloth_state_t *s, const char *iface) {
    if (!iface || iface[0] == '\0') return;

    /* already scanning on this exact interface */
    if (g_running && strcmp(s->probe_iface, iface) == 0) return;

    if (g_running) probe_stop();

    s->probe_err[0] = '\0';
    g_state = s;
    char errbuf[PCAP_ERRBUF_SIZE];
    g_ph = pcap_open_live(iface, 65535, 1, 100, errbuf);
    if (!g_ph) {
        snprintf(s->probe_err, sizeof(s->probe_err), "pcap(%s): %.50s", iface, errbuf);
        s->probe_iface[0] = '\0';
        return;
    }

    int dlt = pcap_datalink(g_ph);
    if (dlt != DLT_IEEE802_11_RADIO) {
        pcap_close(g_ph);
        g_ph = NULL;
        snprintf(s->probe_err, sizeof(s->probe_err),
                 "%s: DLT %d not radiotap (not in monitor mode?)", iface, dlt);
        s->probe_iface[0] = '\0';
        return;
    }

    snprintf(s->probe_iface, sizeof(s->probe_iface), "%s", iface);
    g_running = 1;
    pthread_create(&g_thread, NULL, probe_thread, NULL);
}

#endif /* WITH_PCAP */
