#ifdef WITH_PCAP

#include <stdio.h>
#include <stdlib.h>   /* malloc/free for the #92 dispatch seam */
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <pcap.h>

#include "sloth.h"
#include "capture/probe.h"
#include "capture/capture.h"   /* capture_classify_exit / stats accounting (#91) */
#include "evidence_ring.h"     /* bounded raw-frame evidence ring (#92) */
#include "radiotap.h"
#include "rf_quality.h"
#include "beacon_snoop.h"
#include "deauth_snoop.h"
#include "flood_window.h"
#include "probe_pnl.h"
#include "eapol_log.h"
#include "fragattack.h"
#include "seqnum_track.h"
#include "assoc_track.h"
#include "auth_track.h"
#include "action_snoop.h"
#include "ctrl_frames.h"
#include "mle.h"

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
static uint64_t        g_bad_clock_total; /* capture ts <= 0 (#92) */
static pthread_mutex_t g_frame_mu = PTHREAD_MUTEX_INITIALIZER;

uint64_t mon_bad_clock_total(void) {
    pthread_mutex_lock(&g_frame_mu);
    uint64_t t = g_bad_clock_total;
    pthread_mutex_unlock(&g_frame_mu);
    return t;
}

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
                             uint16_t len, int8_t signal, time_t ts) {
    pthread_mutex_lock(&g_frame_mu);
    mon_frame_t *f = &g_frames[g_frame_head];
    f->ts         = ts;
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

static capture_run_flag_t g_running = CAPTURE_RUN_FLAG_INIT;   /* #95 */
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
        /* The %.15s precision restates the nlen guard above at the call
         * site. The guard alone is enough at -O2, where gcc propagates
         * it; at -O0 it cannot, and -Wformat-truncation fails the build
         * — which is how the #95 capture-path target found this. Better
         * to bound the conversion than to rely on the optimiser seeing
         * a guard fifteen lines up. */
        snprintf(path, sizeof(path), "/sys/class/net/%.15s/type", e->d_name);
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
    time_t   now    = flood_wall();
    uint64_t now_ms = flood_mono_ms();

    /* find existing entry */
    for (int i = 0; i < g_count; i++) {
        if (memcmp(g_clients[i].mac, mac, 6) == 0) {
            g_clients[i].signal_dbm  = signal;
            g_clients[i].channel     = channel;
            g_clients[i].last_seen   = now;
            g_clients[i].frame_count++;
            client_rssi_push(&g_clients[i], signal, now);
            probe_flood_note(&g_clients[i], now_ms, now);
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
    probe_flood_note(&g_clients[slot], now_ms, now);
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

    /* ── One clock for this frame (#92) ──────────────────────────
     *
     * Every observer below is stamped from the frame's own capture
     * timestamp, not from time(NULL). Nine sites used to read the wall
     * clock while eapol_observe_dot11() alone took hdr->ts, so one frame
     * could be stamped two different seconds depending on scheduling,
     * and a correlation window built from those stamps was not
     * reproducible from the capture it came from. For an evidence tool
     * that is the difference between a record and an anecdote.
     *
     * No fallback, deliberately. Substituting time(NULL) for a
     * timestamp that looks wrong would reintroduce exactly the
     * non-reproducibility this removes — and "looks wrong" is not
     * decidable: a capture replayed from another host legitimately
     * carries clocks far from this one's. A frame is stamped with what
     * the capture says, always.
     *
     * What IS tracked is how often that value is unusable: ts <= 0 is
     * the epoch or before it, which no live kernel produces. The count
     * is published so an operator can tell "quiet" from "this capture's
     * clock is broken", the same distinction the #91 health fields
     * exist to make. Nothing is substituted on the strength of it. */
    const time_t fts = (time_t)hdr->ts.tv_sec;
    if (fts <= 0) {
        pthread_mutex_lock(&g_frame_mu);
        if (g_bad_clock_total < UINT64_MAX) g_bad_clock_total++;
        pthread_mutex_unlock(&g_frame_mu);
    }

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
                       fts);

    /* Log every frame for the monitor packets band, before the per-type
     * dispatch. addr2 (TA/SA) only exists from 16 bytes on — ACK/CTS carry
     * addr1 only, so pass NULL there. */
    mon_frame_record(type, sub, dot11 + 4,
                     dot11_len >= 16 ? dot11 + 10 : NULL,
                     (uint16_t)dot11_len, signal, fts);

    /* Retain the whole frame for evidence (#92). `data`, not `dot11`:
     * the radiotap header is part of the record — it carries the
     * frequency, the FCS verdict and the signal an analyst needs to
     * judge the frame, and the general packet ring's min(caplen, 64)
     * often holds little else.
     *
     * Placed with mon_frame_record() and therefore BEHIND the framing
     * guards above, not in front of them. A frame too short to parse
     * cannot be cited by any alert, and admitting runts would let an
     * attacker flush the whole evidence ring with 10-byte garbage —
     * cheap for them, and it would evict the frames that actually
     * triggered something.
     *
     * The return value (the event ID) is dropped here: nothing records
     * IDs on an alert yet. Wiring the alert engine and the exporter to
     * these IDs is the next #92 slice; this one builds the store and
     * its retrieval path. */
    (void)evidence_ring_note(data, (uint32_t)hdr->caplen, (uint32_t)hdr->len,
                             fts, (long)hdr->ts.tv_usec,
                             (uint16_t)(rt.freq_mhz > 0 && rt.freq_mhz <= 0xFFFF
                                        ? rt.freq_mhz : 0),
                             signal);

    if (type == 1) {
        /* Control frames (#64). Dispatched *above* the 24-byte guard
         * below: a CTS or ACK is 14 bytes and an RTS is 20, so every
         * control frame there is would be dropped by a check written
         * for management headers. Parsing lives in ctrl_frames.c
         * because this file is absent from TEST_SRCS. */
        ctrl_observe(dot11, dot11_len, channel, fts);
        return;
    }

    /* The detailed per-type parsers below assume a full management header. */
    if (dot11_len < 24) return;

    /* Data frames (type 2). eapol_observe_dot11 rejects anything that
     * is not an EAPOL-Key frame internally, so the cost of
     * unconditional dispatch is just the LLC SNAP check inside.
     *
     * frag_observe (#75) needs the *encrypted* ones too — the whole
     * FragAttacks family is about frames on a protected network — so it
     * runs on every data frame, before any payload check. */
    if (type == 2) {
        /* Capture time, not processing time: the handshake pcap's
         * record headers carry it (#92). */
        eapol_observe_dot11(dot11, dot11_len, signal, channel,
                            (time_t)hdr->ts.tv_sec, (long)hdr->ts.tv_usec);
        frag_observe(dot11, dot11_len, fts);
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
            /* An AP's own Multi-Link Element (#67) — the AP-side MLD.
             * The client side arrives via assoc_request_parse. */
            if (rsn.mle_body && rsn.mle_len > 0) {
                sloth_mld_t mld;
                if (mle_parse(rsn.mle_body, rsn.mle_len, &mld))
                    mle_observe(&mld, fts);
            }
            if (rsn.csa_present)
                csa_observe(dot11 + 16, dot11 + 10,
                            rsn.csa_new_channel, rsn.csa_new_op_class,
                            rsn.csa_switch_mode, rsn.csa_switch_count,
                            CSA_SRC_BEACON, channel, fts);
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
            /* frag_note_association (#75 slice 2): the fragment cache
             * should be cleared at exactly this event. Fed from the
             * same status-0 evidence as assoc_observe, not its result —
             * a station demoted by a later EAPOL-ranked entry still
             * really did (re)associate at this moment. */
            frag_note_association(bssid_p, sta_p, fts);
        }
        return;
    }

    if (sub == 10 || sub == 12) {
        /* Disassoc (10) or Deauth (12) */
        deauth_frame_t df;
        if (deauth_parse(dot11, dot11_len, &df))
            deauth_record(&df);
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
        auth_observe(dot11 + 16, fts);
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
        action_observe(dot11, dot11_len, fts);
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

/* Why the monitor worker left its loop (#91 slice 2). Same publication
 * pattern as the data-stream worker in capture.c — see the note there.
 * This is the stream where confusing "quiet channel" with "dead thread"
 * costs most: on a hopping radio an empty dwell is normal. */
static int  g_exit_reason = CAPTURE_EXIT_NONE;
static char g_exit_detail[80];

static void *probe_thread(void *arg) {
    (void)arg;
    int r = 0;
    while (capture_run_flag_get(&g_running)) {
        r = pcap_dispatch(g_ph, 32, on_probe_frame, NULL);
        if (r < 0) break;
    }
    const char *err = (r < 0 && g_ph) ? pcap_geterr(g_ph) : "";
    /* The run-flag mutex is a leaf: read it before taking g_mu. */
    int stop_requested = !capture_run_flag_get(&g_running);
    /* Published under the client-table mutex, as in capture.c: a torn
     * read of the error string is worse than no string at all. */
    pthread_mutex_lock(&g_mu);
    snprintf(g_exit_detail, sizeof(g_exit_detail), "%s", err ? err : "");
    g_exit_reason = (int)capture_classify_exit(r, stop_requested, g_exit_detail);
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

void probe_health_poll(capture_health_t *h) {
    if (!h) return;
    h->open = g_ph != NULL;
    pthread_mutex_lock(&g_mu);
    h->exit_reason = g_exit_reason;
    snprintf(h->exit_detail, sizeof(h->exit_detail), "%s", g_exit_detail);
    int reason = g_exit_reason;
    pthread_mutex_unlock(&g_mu);
    h->running = capture_run_flag_get(&g_running) && reason == CAPTURE_EXIT_NONE;
    if (!g_ph) return;
    struct pcap_stat ps;
    memset(&ps, 0, sizeof(ps));
    if (pcap_stats(g_ph, &ps) == 0)
        capture_stats_accumulate(h, (uint32_t)ps.ps_recv, (uint32_t)ps.ps_drop,
                                 (uint32_t)ps.ps_ifdrop);
}

/* ── Monitor dispatch test seam (#92) ─────────────────────────
 *
 * The 802.11 path had no test entry point. on_probe_frame() is static,
 * src/capture/probe.c is absent from TEST_SRCS, and every monitor test
 * in the suite seeds sloth_state_t instead — so radiotap parsing, the
 * frame-type dispatch and the per-type observers, all of which consume
 * attacker-controlled bytes off the air, were reachable only through a
 * real radio.
 *
 * This is the monitor twin of capture_test_dispatch() (#95) and works
 * the same way: an in-memory libpcap savefile through fmemopen() and
 * pcap_fopen_offline(), so there is no device and no .pcap fixture, and
 * the frames stay hand-built byte arrays. The savefile builder itself
 * is shared, not copied.
 *
 * ts_secs is deliberately a parameter. Nine call sites in this callback
 * read time(NULL) while one takes the frame's own capture timestamp,
 * which is #92's open defect; a seam that could not set per-frame
 * timestamps could not be used to pin the fix. This slice does NOT fix
 * that split — it builds the thing needed to test any fix for it.
 *
 * orig_lens is a parameter for the same reason one slice later: the
 * evidence ring records caplen and len separately, so a seam that could
 * only produce len == caplen could not tell a callback reading hdr->len
 * from one reading hdr->caplen. capture_test_savefile() already took
 * the array; only this wrapper was passing NULL.
 *
 * DLT is fixed to DLT_IEEE802_11_RADIO because that is the only link
 * type probe_open() accepts.
 *
 * Single-threaded and synchronous: no worker exists, so frames are
 * decoded on the calling thread and `s` is fully populated on return.
 * Returns the number of frames libpcap handed to the callback, or -1 if
 * the savefile could not be opened. */
int probe_test_dispatch(sloth_state_t *s,
                        const uint8_t *const *frames, const int *lens,
                        const int *orig_lens,
                        const uint32_t *ts_secs, int n) {
    if (!s) return -1;
    size_t total = 0;
    uint8_t *img = capture_test_savefile(DLT_IEEE802_11_RADIO, frames, lens,
                                         orig_lens, ts_secs, n, &total);
    if (!img) return -1;

    FILE *fp = fmemopen(img, total, "rb");
    if (!fp) { free(img); return -1; }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = pcap_fopen_offline(fp, errbuf);
    if (!pc) { fclose(fp); free(img); return -1; }

    /* on_probe_frame() reads g_state; g_ph is swapped too so anything
     * reached from the callback that consults the handle sees this one. */
    pcap_t        *saved_ph    = g_ph;
    sloth_state_t *saved_state = g_state;
    g_ph    = pc;
    g_state = s;
    int got = pcap_dispatch(pc, n > 0 ? n : -1, on_probe_frame, NULL);
    g_ph    = saved_ph;
    g_state = saved_state;

    pcap_close(pc);          /* closes the FILE* it took ownership of */
    free(img);
    return got;
}

/* ── Public API ──────────────────────────────────────────── */

void probe_open(sloth_state_t *s) {
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
}

void probe_run(void) {
    if (!g_ph || capture_run_flag_get(&g_running)) return;
    /* A restart clears the previous run's verdict (#91 slice 2). */
    pthread_mutex_lock(&g_mu);
    g_exit_reason    = CAPTURE_EXIT_NONE;
    g_exit_detail[0] = '\0';
    pthread_mutex_unlock(&g_mu);
    capture_run_flag_set(&g_running, 1);
    if (pthread_create(&g_thread, NULL, probe_thread, NULL) != 0)
        capture_run_flag_set(&g_running, 0);
}

void probe_start(sloth_state_t *s) {
    probe_open(s);
    probe_run();
}

void probe_stop(void) {
    /* Clear-then-break, as in capture_stop(). */
    if (capture_run_flag_take(&g_running)) {
        if (g_ph) pcap_breakloop(g_ph);
        pthread_join(g_thread, NULL);
    }
    if (g_ph) { pcap_close(g_ph); g_ph = NULL; }
}

void probe_snapshot(sloth_state_t *s) {
    time_t   now    = flood_wall();
    uint64_t now_ms = flood_mono_ms();
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

    /* Flood status decays with time, not with the next frame (#88). */
    for (i = 0; i < g_count; i++) probe_flood_refresh(&g_clients[i], now_ms);

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
    if (capture_run_flag_get(&g_running) && strcmp(s->probe_iface, iface) == 0)
        return;

    /* The launch-time allow-list is an authorization boundary, so an
     * interactive [m] retarget has to clear it too (#85). Enforced here
     * rather than in view_iface_key() because the monitor stream has no
     * per-frame scope check of its own: a second caller of this function
     * would otherwise reopen the hole silently.
     *
     * Refusing before probe_stop() is the point — an operator who lands
     * on an out-of-scope row must not lose the capture that is already
     * running. iface_is_allowed() returns 1 on an empty list, so an
     * unrestricted run is unaffected.
     *
     * Interactive retarget only, and that asymmetry is deliberate
     * rather than unfinished: the owner ruled on 2026-10-04 that the
     * monitor stream stays OUTSIDE the --iface allow-list, so
     * probe_open() goes on opening whatever find_monitor_iface()
     * discovers at startup. Narrowing that would silence 802.11
     * collection for a plain `--iface eth0` run.
     *
     * So an allow-list does not mean "no out-of-scope frame is ever
     * collected" — it scopes the IP capture stream, and this one
     * keystroke. docs/wiki/jsonl-schema.md says so under
     * scope_not_enforced. What this check still buys is that an
     * operator cannot move the radio somewhere they did not declare;
     * sloth's own startup discovery is a different question, and the
     * owner answered it the other way. */
    if (!iface_is_allowed(s, iface)) {
        /* %.15s, not %s: the name comes in as a const char * that the
         * compiler cannot bound, and kernel iface names are under 16
         * bytes anyway (IFNAMSIZ). Bounding it here keeps the suffix
         * that names the flag inside probe_err rather than letting a
         * long argument push it out. */
        snprintf(s->probe_err, sizeof(s->probe_err),
                 "%.15s not in --iface allow-list", iface);
        return;
    }

    probe_stop();   /* also closes a handle opened but never run */

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
    /* A radio can also arrive here, not just at startup discovery: a run
     * that began with no radiotap interface skips main()'s evidence-ring
     * init, and without this the ring would stay dead for the rest of
     * the session while frames flowed — silent evidence loss, which is
     * the defect class #92 exists to remove. Idempotent, so a retarget
     * of an already-running radio keeps the records it has already
     * collected. A failed allocation leaves evidence_ring_note() a
     * no-op; it is not reported here because s->probe_err is the
     * retarget's own refusal channel and overloading it would make a
     * successful retarget look refused. */
    (void)evidence_ring_init_default();
    /* Same reset as probe_run(): [m] retargets the radio, and the new
     * worker must not inherit the old one's exit reason (#91 slice 2). */
    pthread_mutex_lock(&g_mu);
    g_exit_reason    = CAPTURE_EXIT_NONE;
    g_exit_detail[0] = '\0';
    pthread_mutex_unlock(&g_mu);
    /* A failed create must clear the flag, or probe_stop() would join a
     * pthread_t that was never initialised — same guard as probe_run(). */
    capture_run_flag_set(&g_running, 1);
    if (pthread_create(&g_thread, NULL, probe_thread, NULL) != 0)
        capture_run_flag_set(&g_running, 0);
}

#endif /* WITH_PCAP */
