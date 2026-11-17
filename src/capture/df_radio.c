/* The --df-iface radios; see df_radio.h. */
#include "capture/df_radio.h"

#include <string.h>

#include "df.h"

#ifdef WITH_PCAP

#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>

#include "sloth.h"
#include "df.h"
#include "ble_hci.h"
#include "radiotap.h"
#include "capture/frame_edge.h"
#include "run_flag.h"
#include "sloth_clock.h"
#include "worker_thread.h"

typedef struct {
    int                radio;        /* df.c's index */
    char               iface[16];
    pcap_t            *ph;
    pthread_t          thread;
    capture_run_flag_t running;
    pthread_mutex_t    mu;           /* the four counters */
    uint64_t           frames, noted, rejects, retune_failures;
} dfr_t;

static dfr_t g_r[DF_MAX_RADIOS];
static int   g_n;
static int   g_init;

static void init_once(void) {
    if (g_init) return;
    for (int i = 0; i < DF_MAX_RADIOS; i++) {
        memset(&g_r[i], 0, sizeof(g_r[i]));
        pthread_mutex_init(&g_r[i].mu, NULL);
        capture_run_flag_t f = CAPTURE_RUN_FLAG_INIT;
        g_r[i].running = f;
    }
    g_init = 1;
}

int df_radio_open(int radio, const char *iface, char *err, size_t errsz) {
    init_once();
    if (err && errsz) err[0] = '\0';
    if (radio < 0 || !iface || !iface[0] || strlen(iface) >= sizeof(g_r[0].iface)) {
        if (err) snprintf(err, errsz, "not an interface name");
        return 0;
    }
    if (g_n >= DF_MAX_RADIOS) {
        if (err) snprintf(err, errsz, "more than %d radios", DF_MAX_RADIOS);
        return 0;
    }
    if (bt_dev_is_raw_hci(iface)) {
        if (err) snprintf(err, errsz, "%.15s refused: raw HCI device", iface);
        return 0;
    }
    char eb[PCAP_ERRBUF_SIZE];
    /* A short snaplen: radiotap and the 802.11 header are all that is
     * read, and the body of a frame this radio hears is not wanted. */
    pcap_t *ph = pcap_open_live(iface, 256, 1, 100, eb);
    if (!ph) {
        if (err) snprintf(err, errsz, "pcap(%.15s): %.50s", iface, eb);
        return 0;
    }
    if (pcap_datalink(ph) != DLT_IEEE802_11_RADIO) {
        if (err) snprintf(err, errsz, "%.15s: DLT %d not radiotap (not in monitor mode?)",
                          iface, pcap_datalink(ph));
        pcap_close(ph);
        return 0;
    }
    dfr_t *r = &g_r[g_n++];
    r->radio = radio;
    snprintf(r->iface, sizeof(r->iface), "%s", iface);
    r->ph = ph;
    return 1;
}

static void on_frame(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data) {
    dfr_t *r = (dfr_t *)user;
    frame_view_t fv;
    radiotap_info_t rt;
    const uint8_t *dot11 = NULL;
    int dot11_len = 0;
    uint8_t ta[6];
    int ok = frame_view_init(&fv, data, hdr->caplen, hdr->len, (long)hdr->ts.tv_sec,
                             (long)hdr->ts.tv_usec, DLT_IEEE802_11_RADIO) &&
             frame_view_radiotap(&fv, &rt, &dot11, &dot11_len) == FRAME_RT_OK;
    int noted = ok && !rt.bad_fcs && df_frame_ta(dot11, dot11_len, ta) && rt.signal_dbm < 0;
    /* The host's clock, as radio 0's note: the table compares ages
     * across radios, and two capture clocks need not agree. */
    if (noted) df_note(r->radio, ta, rt.signal_dbm, rt.channel, sloth_wall());
    pthread_mutex_lock(&r->mu);
    if (ok) r->frames++; else r->rejects++;
    if (noted) r->noted++;
    pthread_mutex_unlock(&r->mu);
}

static void *reader(void *arg) {
    dfr_t *r = arg;
    while (capture_run_flag_get(&r->running)) {
        if (pcap_dispatch(r->ph, 64, on_frame, (u_char *)r) < 0) break;
    }
    return NULL;
}

void df_radio_run(void) {
    for (int i = 0; i < g_n; i++) {
        dfr_t *r = &g_r[i];
        if (!r->ph || capture_run_flag_get(&r->running)) continue;
        capture_run_flag_set(&r->running, 1);
        if (worker_thread_create(&r->thread, reader, r) != 0)
            capture_run_flag_set(&r->running, 0);
    }
}

void df_radio_stop(void) {
    for (int i = 0; i < g_n; i++) {
        dfr_t *r = &g_r[i];
        if (capture_run_flag_take(&r->running)) {
            if (r->ph) pcap_breakloop(r->ph);
            pthread_join(r->thread, NULL);
        }
        if (r->ph) { pcap_close(r->ph); r->ph = NULL; }
    }
    g_n = 0;
}

int df_radio_open_count(void) { return g_n; }

int df_radio_follow(int freq_mhz) {
    int bad = 0;
    if (freq_mhz <= 0) return 0;
    for (int i = 0; i < g_n; i++) {
        dfr_t *r = &g_r[i];
        if (!r->ph) continue;
        int rc = g_platform.set_channel ? g_platform.set_channel(r->iface, freq_mhz)
                                        : -EOPNOTSUPP;
        if (rc != 0) {
            bad++;
            pthread_mutex_lock(&r->mu);
            r->retune_failures++;
            pthread_mutex_unlock(&r->mu);
        }
    }
    return bad;
}

int df_radio_health(int i, df_radio_health_t *out) {
    if (!out || i < 0 || i >= g_n) return 0;
    dfr_t *r = &g_r[i];
    memset(out, 0, sizeof(*out));
    snprintf(out->iface, sizeof(out->iface), "%s", r->iface);
    out->open    = r->ph != NULL;
    out->running = capture_run_flag_get(&r->running);
    pthread_mutex_lock(&r->mu);
    out->frames = r->frames; out->noted = r->noted;
    out->rejects = r->rejects; out->retune_failures = r->retune_failures;
    pthread_mutex_unlock(&r->mu);
    return 1;
}

#else  /* !WITH_PCAP */

int  df_radio_open(int radio, const char *iface, char *err, size_t errsz) {
    (void)radio; (void)iface;
    if (err && errsz) err[0] = '\0';
    return 0;
}
void df_radio_run(void) {}
void df_radio_stop(void) {}
int  df_radio_open_count(void) { return 0; }
int  df_radio_follow(int freq_mhz) { (void)freq_mhz; return 0; }
int  df_radio_health(int i, df_radio_health_t *out) { (void)i; (void)out; return 0; }

#endif
