#ifdef WITH_PCAP

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <pcap.h>

#include "sloth.h"
#include "capture/probe.h"
#include "beacon_snoop.h"
#include "deauth_snoop.h"
#include "probe_pnl.h"

#ifdef PLATFORM_LINUX
#  include <dirent.h>
#endif

/* ── Internal client table ───────────────────────────────── */

static probe_client_t  g_clients[MAX_PROBE_CLIENTS];
static int             g_count   = 0;
static pthread_mutex_t g_mu      = PTHREAD_MUTEX_INITIALIZER;

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

/* ── Radiotap parser ─────────────────────────────────────── */

#define RT_PAD(o, a)  (((o) + ((a)-1)) & ~((a)-1))

static void parse_radiotap(const uint8_t *buf, int len,
                           int8_t *signal, int *channel) {
    *signal  = -100;
    *channel = 0;
    if (len < 8) return;

    uint16_t rt_len = (uint16_t)(buf[2] | (buf[3] << 8));
    if (rt_len < 8 || (int)rt_len > len) return;

    uint32_t pres = (uint32_t)(buf[4] | (buf[5]<<8) | (buf[6]<<16) | (buf[7]<<24));

    /* skip extended present bitmaps */
    int off = 8;
    while ((pres & (1u<<31)) && off + 4 <= (int)rt_len)
        off += 4;

    /* re-read first present word for field presence */
    pres = (uint32_t)(buf[4] | (buf[5]<<8) | (buf[6]<<16) | (buf[7]<<24));

    if (pres & (1u<< 0)) { off = RT_PAD(off, 8); off += 8; }  /* TSFT */
    if (pres & (1u<< 1)) {                         off += 1; }  /* FLAGS */
    if (pres & (1u<< 2)) {                         off += 1; }  /* RATE */
    if (pres & (1u<< 3)) {                                       /* CHANNEL */
        off = RT_PAD(off, 2);
        if (off + 2 <= (int)rt_len) {
            uint16_t freq = (uint16_t)(buf[off] | (buf[off+1] << 8));
            if      (freq >= 2412 && freq <= 2484) *channel = (freq - 2407) / 5;
            else if (freq >= 5160 && freq <= 5885) *channel = (freq - 5000) / 5;
        }
        off += 4;
    }
    if (pres & (1u<< 4)) { off += 2; }                          /* FHSS */
    if (pres & (1u<< 5)) {                                       /* DBM_ANTSIGNAL */
        if (off < (int)rt_len) *signal = (int8_t)buf[off];
    }
}

#undef RT_PAD

/* ── Client table update (caller holds g_mu) ─────────────── */

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
            if (ssid[0])   /* prefer named probe over wildcard */
                strncpy(g_clients[i].ssid, ssid, sizeof(g_clients[i].ssid) - 1);
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

    memcpy(g_clients[slot].mac, mac, 6);
    strncpy(g_clients[slot].ssid, ssid, sizeof(g_clients[slot].ssid) - 1);
    g_clients[slot].ssid[sizeof(g_clients[slot].ssid) - 1] = '\0';
    g_clients[slot].signal_dbm  = signal;
    g_clients[slot].channel     = channel;
    g_clients[slot].last_seen   = now;
    g_clients[slot].frame_count = 1;
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

    int8_t signal; int channel;
    parse_radiotap(data, len, &signal, &channel);

    /* 802.11 frame starts after radiotap */
    const uint8_t *dot11     = data + rt_len;
    int            dot11_len = len  - rt_len;
    if (dot11_len < 24) return;

    /* Frame Control byte 0: bits 2-3 = type, bits 4-7 = subtype */
    uint8_t fc0  = dot11[0];
    uint8_t type = (fc0 >> 2) & 0x03;
    uint8_t sub  = (fc0 >> 4) & 0x0f;

    if (type != 0) return;  /* management frames only */

    if (sub == 8) {
        /* Beacon frame — passive AP discovery */
        char    ssid[33]; uint8_t bssid[6]; int channel; char enc[10]; uint16_t bms;
        beacon_rsn_t rsn;
        if (beacon_parse(dot11, dot11_len, signal, ssid, bssid, &channel,
                         enc, &bms, &rsn))
            beacon_record(bssid, ssid, signal, channel, enc, bms, &rsn);
        return;
    }

    if (sub == 10 || sub == 12) {
        /* Disassoc (10) or Deauth (12) */
        uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t st;
        if (deauth_parse(dot11, dot11_len, signal, src, dst, bssid, &reason, &st))
            deauth_record(src, dst, bssid, reason, st);
        return;
    }

    if (sub != 4) return;  /* only probe requests beyond this point */

    /* Source Address: bytes 10-15 */
    const uint8_t *sa = dot11 + 10;

    /* Parse SSID information element (tag 0) */
    const uint8_t *ie     = dot11 + 24;
    int            ie_rem = dot11_len - 24;
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

    /* Feed the PNL aggregator — outside the probe-list mutex since
     * probe_pnl_observe takes its own lock. Wildcard probes are dropped
     * inside observe() since they leak no preferred-network info. */
    probe_pnl_observe(sa, ssid);
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
