/* The sensor's own state (owner ruling 2026-11-11: "alerts for
 * under-voltage and a source going down"). Both rules read the snapshot
 * src/sys_status.c re-derives every poll (sys_status_get()), never a
 * platform op, and both are the FIRST exemption form of agents/AGENTS.md
 * "Detectors cite their sources": sloth's own operational state, no
 * adversary, so no technique and nothing in research/ to cite. The set
 * is pinned by tests/test_research_corpus.c ::
 * test_own_state_kinds_are_named.
 *
 * One incident per condition, not one per swing. Both rules hold an
 * incident open across a flap and close it themselves, with the
 * `alert.resolve` reason `recovered`, only once the condition has been
 * clear for SENSOR_RECOVER_S without a break. A supply or a decoder that
 * toggles every few seconds is therefore one incident for as long as it
 * keeps toggling, not a create/resolve pair per toggle. SENSOR_RECOVER_S
 * is under the engine's 300 s quiet period (ALERT_RESOLVE_AFTER_S), so a
 * recovery is reported by this rule rather than by the quiet period,
 * and two minutes is two of sys_status's 60 s batches: a consumer reading
 * the batches sees at least one whole batch of the condition clear
 * before the incident closes.
 *
 * Every clock here is sloth_mono_ms(): durations, never wall time. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sys_status.h"
#include "sloth_clock.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"
#include "sensor_health.h"
#include "cov_interval.h"
#include "rule_coverage.h"
#include "tune.h"

typedef struct {
    int      open;              /* this rule holds an incident open */
    int      ok_on;             /* the condition is clear ... */
    uint64_t ok_since;          /* ... since this mono ms */
    int      down_on;           /* source: DOWN without a break ... */
    uint64_t down_since;
    int      notok_on;          /* source: anything but OK without a break ... */
    uint64_t notok_since;
} sensor_hold_t;

static struct {
    sensor_hold_t uv;
    sensor_hold_t src[SYS_SRC_COUNT];
} g_sensor;

static void suppressed_forget(void);

void rules_sensor_forget(void) {
    memset(&g_sensor, 0, sizeof(g_sensor));
    suppressed_forget();
}

static uint64_t held_ms(uint64_t now, uint64_t since) {
    return now >= since ? now - since : 0;
}

/* The condition is clear this tick. Closes the incident once it has been
 * clear for SENSOR_RECOVER_S; an incident the engine already ended (the
 * operator's `c`, an eviction) is simply forgotten. */
static void hold_clear(sensor_hold_t *h, const char *key, uint64_t mono, time_t now) {
    h->down_on = h->notok_on = 0;
    if (!h->ok_on) { h->ok_on = 1; h->ok_since = mono; }
    if (!h->open) return;
    if (!alert_key_open(key)) { h->open = 0; return; }
    if (held_ms(mono, h->ok_since) >= (uint64_t)SENSOR_RECOVER_S * 1000u) {
        alert_key_resolve(key, now, "recovered");
        h->open = 0;
    }
}

/* ── SENSOR_UNDERVOLT ────────────────────────────────────────────────
 *
 * Fires while the host's under-voltage alarm reads 1: any hwmon
 * inN_lcrit_alarm, which on a Raspberry Pi is the firmware's flag
 * (rpi_volt in0_lcrit_alarm, src/sys_status.c sample_hwmon()). The
 * snapshot is sampled every SYS_SAMPLE_SECS, so an alarm shorter than
 * that is not seen, as sys_status.h says.
 *
 * WARN, never CRIT. A brown-out can corrupt an SD card and wedge a USB
 * radio, but the alarm says the supply dipped, not that either
 * happened, and no source read for this rule gives a held duration past
 * which damage is to be expected; a CRIT on a span chosen here would be
 * a guess presented as a threshold. The sources going quiet are
 * SENSOR_SOURCE_DOWN's to report, with their own severity.
 *
 * Key `undervolt:host`: the host has one supply, whichever node reports
 * it. The detail names the first alarming sensor (id and label) and how
 * many others agree. A host with no alarm node never fires. */
void rule_sensor_undervolt(const sloth_state_t *s, time_t now) {
    (void)s;
    const sys_snapshot_t *sn = sys_status_get();
    static const char key[] = "undervolt:host";
    sensor_hold_t *h = &g_sensor.uv;
    if (!sn->valid || !sn->has_undervolt) return;
    const uint64_t mono = sloth_mono_ms();
    if (!sn->undervolt) { hold_clear(h, key, mono, now); return; }
    h->ok_on = 0;

    const sys_reading_t *first = NULL;
    int others = 0;
    for (int i = 0; i < sn->nvolt; i++) {
        const sys_reading_t *r = &sn->volt[i];
        if (!r->has_alarm || !r->alarm) continue;
        if (!first) first = r; else others++;
    }
    /* Each %s a plain variable, so slothweb's detail audit
     * (sloth-mesh's tests/test_alertfmt.c) can follow it: sid and sname are the
     * host kernel's hwmon id and the driver's name for the input, never
     * a remote's text; more is one of three literals. */
    const char *sid = first ? first->id : "?";
    const char *sname = first && first->label[0] ? first->label : "no label";
    const char *more = !others ? ""
                     : others == 1 ? ", and 1 other sensor" : ", and more sensors";
    char detail[ALERT_DETAIL_LEN];
    snprintf(detail, sizeof(detail),
             "under-voltage alarm on %s (%s)%s: the host's supply is below "
             "what the board needs; brown-outs corrupt SD cards and can "
             "wedge USB radios - check the power supply and cable",
             sid, sname, more);
    fire(ALERT_TYPE_SENSOR_UNDERVOLT, ALERT_SEV_WARN, "SENSOR_UNDERVOLT",
         detail, key, NULL, 0, now);
    h->open = 1;
}

/* ── SENSOR_SOURCE_DOWN ──────────────────────────────────────────────
 *
 * Per configured source (every source_status row whose state is not
 * not_configured: what the command line enabled, and the monitor radio
 * sloth found and opened), keyed `srcdown:<name>`:
 *
 *   opens  when it has read `down` for SENSOR_SRC_DOWN_HOLD_S without a
 *          break, or has not read `ok` for SENSOR_SRC_STALE_S without a
 *          break (stale, or stale and down in turn). The down hold is
 *          one sample interval: a gpsd or decoder reconnect that
 *          succeeds within seconds is not an incident. The stale span
 *          is five of sys_status's 60 s stale threshold and the engine's
 *          own quiet period: a source quiet that long while configured
 *          is not a lull. A source that is down from the first poll -
 *          a capture that never opened - opens after the hold like any
 *          other.
 *   holds  while it reads anything but `ok`, so down -> stale -> down
 *          is one incident;
 *   closes reading `ok` for SENSOR_RECOVER_S without a break.
 *
 * A source that is not configured never fires: its row says nothing
 * about the sensor's health, only about what was asked for. Nor does
 * one sloth-rf trimmed at startup (not_installed, src/rf_trim.h): the
 * SDR its decoder needs is not attached, which is the host's shape and
 * not a fault, and the trim says so once on stderr.
 *
 * Severity: CRIT for the monitor radio and the IP capture, WARN for the
 * rest. Those two are the sensor's main function - every 802.11 rule
 * and view reads the monitor radio and nothing else, every wired rule
 * the capture and nothing else - so with one configured and gone, the
 * sensor is silent on its whole domain while it looks like a quiet
 * network. The others feed one domain each beside it (Bluetooth,
 * position, aircraft, APRS).
 *
 * The detail carries the reader's own word, the state and the freshness
 * band, never an age in seconds: a figure that moves every tick would
 * make every evaluation an observation (#173). */
void rule_sensor_source_down(const sloth_state_t *s, time_t now) {
    (void)s;
    const sys_snapshot_t *sn = sys_status_get();
    if (!sn->valid) return;
    const uint64_t mono = sloth_mono_ms();
    for (int i = 0; i < SYS_SRC_COUNT; i++) {
        const sys_source_t *o = &sn->src[i];
        sensor_hold_t *h = &g_sensor.src[i];
        if (!o->name) continue;
        char key[48];
        akey_t ak;
        akey_begin(&ak, key, sizeof(key), "srcdown");
        akey_tok(&ak, o->name);
        if (!akey_end(&ak)[0]) continue;

        if (o->state == SYS_ST_NOT_CONFIGURED || o->state == SYS_ST_NOT_INSTALLED) {
            /* Not configured now, or trimmed at startup because its
             * receiver is not attached (src/rf_trim.h): nothing is
             * read, so nothing to judge. A source cannot become
             * unconfigured mid-run; if it ever does, an open incident
             * expires on the engine's quiet period. */
            memset(h, 0, sizeof(*h));
            continue;
        }
        if (o->state == SYS_ST_OK) { hold_clear(h, key, mono, now); continue; }

        h->ok_on = 0;
        if (!h->notok_on) { h->notok_on = 1; h->notok_since = mono; }
        if (o->state == SYS_ST_DOWN) {
            if (!h->down_on) { h->down_on = 1; h->down_since = mono; }
        } else {
            h->down_on = 0;
        }
        const int down_held = h->down_on &&
            held_ms(mono, h->down_since) >= (uint64_t)SENSOR_SRC_DOWN_HOLD_S * 1000u;
        const int notok_held =
            held_ms(mono, h->notok_since) >= (uint64_t)SENSOR_SRC_STALE_S * 1000u;
        if (h->open && !alert_key_open(key)) h->open = 0;
        if (!h->open && !down_held && !notok_held) continue;

        const int main_fn = i == SYS_SRC_CAPTURE || i == SYS_SRC_MONITOR;
        const char *state = sys_src_state_name(o->state);
        const char *band = sys_age_band_name(sys_age_band(o->age_s));
        const char *ep = o->endpoint[0] ? o->endpoint : "-";
        /* msg, not detail: slothweb's audit follows the buffer by name,
         * and o->detail (the reader's own words, "why") shares it. */
        const char *why = o->detail[0] ? o->detail : "-";
        char msg[ALERT_DETAIL_LEN];
        snprintf(msg, sizeof(msg),
                 "configured source %s (%s, %s) is %s: %s; last delivery %s%s",
                 o->name, o->kind, ep, state, why, band,
                 main_fn ? " - the sensor is blind on this source's whole "
                           "domain while it is gone" : "");
        fire(ALERT_TYPE_SENSOR_SOURCE_DOWN, main_fn ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
             "SENSOR_SOURCE_DOWN", msg, key, NULL, 0, now);
        h->open = 1;
    }
}

/* ── SENSOR_SUPPRESSED ───────────────────────────────────────────────
 *
 * #242 item 4. SENSOR_SOURCE_DOWN says a source stopped delivering;
 * this says one is delivering and the sensor is still losing what it
 * delivers, so a quiet alert list there is not a quiet site. Four
 * signals, each its own incident (key `suppressed:<signal>`), WARN:
 *
 *   evict   a synthesis table (src/sensor_health.h) evicted at least
 *           suppress.evict_per_min rows in one minute. The six flow
 *           rings and evidence_frame are not judged: they roll over on
 *           a working sensor by design (the reference sensor's
 *           evidence_frame ran 143 a second), and the loss they count
 *           is scrollback and retained frames, not an observation a
 *           rule reads. Nor are alert and pcap_cooldown (sloth's own
 *           bookkeeping; every incident is on the stream already) or
 *           rtl433 (sloth-rf's).
 *   drop    a capture handle (the monitor radio's, or --iface's)
 *           dropped ps_drop + ps_ifdrop of at least suppress.drop_pct
 *           percent of the ps_recv it reported in one minute, and at
 *           least suppress.drop_min frames. libpcap's own counters
 *           (pcap_stats(3PCAP)): the kernel ring was full, or the
 *           interface dropped before the ring.
 *   silent  a channel a radio visited heard no frame for
 *           suppress.silent_intervals coverage intervals in a row
 *           (src/cov_interval.h) while another visited channel of its
 *           band heard frames in each, and it had heard frames earlier
 *           in this run. A channel that was always empty is a channel
 *           with nobody on it, not a suppressed one; a whole band gone
 *           quiet at once is not this signal either (nothing to compare
 *           with).
 *   cue     (#248) under --cue, the passive cueing of src/chancue.h
 *           refused at least suppress.cue_refused_per_min cues at a
 *           limit (active, rate or share) in one minute. Not the
 *           refusals that are no limit (no channel, not hopped).
 *
 * The minute is COV_IV_MS, the coverage record's: one figure per
 * signal per minute, compared with a per-minute threshold. A signal
 * opens at the end of the first minute over its threshold, is
 * re-asserted every tick until a minute ends under it, and closes
 * (`recovered`) once it has been under for SENSOR_RECOVER_S without a
 * break - two whole minutes - the hold SENSOR_SOURCE_DOWN uses.
 *
 * WARN and never CRIT: the sensor is still hearing, and the signal
 * says it is losing a share of what it hears, not that it is blind on a
 * domain (that is SENSOR_SOURCE_DOWN's CRIT). No source gives any of
 * the thresholds; src/alerts.h gives the baseline each sits above.
 *
 * Own operational state (the first exemption form). A beacon spray, a
 * deauth flood or a jammer can drive any of the first three, a
 * trigger flood the fourth, and so can a
 * busy segment, a slow SD card or an AP switched off; the rule names
 * the signal and does not guess which.
 *
 * Not on a --replay: the tables fill at file speed, so a rate per
 * minute of wall clock means nothing, and the coverage record is not
 * kept (src/cov_interval_capture.c).
 *
 * While an incident is open, rules_sensor_suppressed() gives what it
 * suppresses to the coverage environment, and the rules that read that
 * evidence report `partly`, `suppressed` (src/rule_coverage.h). */

enum { SUP_EVICT = 0, SUP_DROP, SUP_SILENT, SUP_CUE, SUP_N };
static const char *const sup_key[SUP_N] = {
    "suppressed:evict", "suppressed:drop", "suppressed:silent", "suppressed:cue",
};

typedef struct {
    int      freq;      /* MHz, merged over radios */
    int      ivb;       /* COV_IVB_* */
    int      heard;     /* frames in an earlier interval */
    int      run;       /* intervals in a row visited, silent, band heard */
} sup_chan_t;

static struct {
    int           started;
    uint64_t      win_start;
    uint64_t      evict[SH_EVICT_KIND_COUNT];
    int           mon_ok, cap_ok;
    uint64_t      mon_recv, mon_lost, cap_recv, cap_lost;
    uint64_t      cue_limit;      /* s->cue.refused_limit at the window's start */
    uint32_t      iv_seq;
    int           nchan;
    sup_chan_t    chan[COV_IV_CHAN_MAX];
    /* Per signal: over its threshold in the last minute, and what it
     * suppresses (or-ed while the incident is open). */
    int           cond[SUP_N];
    unsigned      inputs[SUP_N], frames[SUP_N];
    /* What the detail names, from the minute that last opened or
     * re-asserted the signal. */
    int           ev_worst, ev_over;
    int           dr_mon, dr_cap;
    int           si_mhz, si_ivb, si_others;
    sensor_hold_t hold[SUP_N];
} g_supp;

/* alerts_clear() (the operator's `c` among its callers): the incidents,
 * the windows and each channel's run go, and which channels this run
 * has heard stays. That is a record of what the radio observed, not of
 * an alert: dropping it would leave a channel jammed before the `c`
 * unable to raise the signal again for the rest of the run, since only a
 * minute with frames sets it. A still-silent channel opens a new
 * incident after suppress.silent_intervals more intervals, as a source
 * still down does after its hold. */
static void suppressed_forget(void) {
    sup_chan_t keep[COV_IV_CHAN_MAX];
    const int n = g_supp.nchan;
    memcpy(keep, g_supp.chan, sizeof(keep));
    memset(&g_supp, 0, sizeof(g_supp));
    for (int t = 0; t < n; t++) keep[t].run = 0;
    memcpy(g_supp.chan, keep, sizeof(keep));
    g_supp.nchan = n;
}

void rules_sensor_reset(void) {
    memset(&g_sensor, 0, sizeof(g_sensor));
    memset(&g_supp, 0, sizeof(g_supp));
}

/* What a table's loss suppresses: an input (1u << cov_input_t) and,
 * for an 802.11 table, the frame classes its rows are built from
 * (0 = every 802.11 kind). 0 for a table not judged. Read off the
 * writer each table's sh_evict_t row names. */
static unsigned evict_scope(sh_evict_t k, unsigned *frames) {
    const unsigned dot11 = 1u << COV_IN_DOT11, ip = 1u << COV_IN_IP;
    *frames = 0;
    switch (k) {
    case SH_EVICT_PNL_CLIENT: case SH_EVICT_PNL_SSID: case SH_EVICT_PROBE_CLIENT:
        *frames = COV_F_PROBE; return dot11;
    case SH_EVICT_PROBE_LATENCY:
        *frames = COV_F_PROBE | COV_F_BEACON; return dot11;
    case SH_EVICT_BEACON_AP:
        *frames = COV_F_BEACON; return dot11;
    case SH_EVICT_ASSOC_PAIR: case SH_EVICT_ASSOC_REQ:
        *frames = COV_F_ASSOC; return dot11;
    case SH_EVICT_WPS_SESSION: case SH_EVICT_EAP_SESSION:
    case SH_EVICT_ROGUE_RADIUS: case SH_EVICT_EAPOL_PENDING:
        *frames = COV_F_EAPOL; return dot11;
    case SH_EVICT_DEAUTH_OBS: case SH_EVICT_DEAUTH_VICTIM:
        *frames = COV_F_DEAUTH; return dot11;
    case SH_EVICT_PM_FORGE: case SH_EVICT_QUEUE_EVICT:
    case SH_EVICT_FRAG_BSS: case SH_EVICT_FRAG_STA: case SH_EVICT_FRAG_SESSION:
    case SH_EVICT_FRAG_ASSOC: case SH_EVICT_FRAG_MPDU: case SH_EVICT_FRAG_AP_IDENT:
        *frames = COV_F_DATA; return dot11;
    case SH_EVICT_SEQNUM_CLIENT: case SH_EVICT_RF_CHANNEL:
        return dot11;
    case SH_EVICT_DEVICE:
        /* One table for every source's devices. */
        return dot11 | ip;
    case SH_EVICT_TOP_HOST: case SH_EVICT_DHCP_EVENT: case SH_EVICT_HTTP_FLOW:
    case SH_EVICT_BGP_SESSION: case SH_EVICT_LDAP_EVENT: case SH_EVICT_KERB_EVENT:
    case SH_EVICT_SMB_SESSION: case SH_EVICT_SSH_FLOW: case SH_EVICT_RDP_FLOW:
    case SH_EVICT_SNMP_FLOW: case SH_EVICT_MQTT_FLOW: case SH_EVICT_MDNS_SERVICE:
    case SH_EVICT_NBNS_NAME: case SH_EVICT_ARP_HIST: case SH_EVICT_NDP_RA:
    case SH_EVICT_SSDP_DEVICE: case SH_EVICT_ONVIF_DEVICE: case SH_EVICT_SMTP_FLOW:
    case SH_EVICT_RTSP_EXCHANGE: case SH_EVICT_RTSP_STREAM: case SH_EVICT_LAN_ROLE:
        return ip;
    case SH_EVICT_BLE_DEVICE: case SH_EVICT_BREDR_LAP: case SH_EVICT_BLE_FLOOD:
        return 1u << COV_IN_BLE_ADV;
    case SH_EVICT_ALERT: case SH_EVICT_PCAP_COOLDOWN: case SH_EVICT_EVIDENCE_FRAME:
    case SH_EVICT_DNS_LOG: case SH_EVICT_TLS_LOG: case SH_EVICT_QUIC_LOG:
    case SH_EVICT_HTTP_LOG: case SH_EVICT_NTP_LOG: case SH_EVICT_ICMP_LOG:
    case SH_EVICT_RTL433: case SH_EVICT_PROBE_HIST: case SH_EVICT_KIND_COUNT:
        break;
    }
    return 0;
}

static int handle_ok(const capture_health_t *h) { return h->open && h->stats_valid; }

static void take_window(const sloth_state_t *s, uint64_t mono) {
    g_supp.win_start = mono;
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++)
        g_supp.evict[k] = sh_evict_count((sh_evict_t)k);
    g_supp.mon_ok   = s->probe_iface[0] && handle_ok(&s->mon_health);
    g_supp.mon_recv = s->mon_health.ps_recv;
    g_supp.mon_lost = s->mon_health.ps_drop + s->mon_health.ps_ifdrop;
    g_supp.cap_ok   = s->pkt_iface[0] && handle_ok(&s->cap_health);
    g_supp.cap_recv = s->cap_health.ps_recv;
    g_supp.cap_lost = s->cap_health.ps_drop + s->cap_health.ps_ifdrop;
    g_supp.cue_limit = s->cue.refused_limit;
}

static uint64_t delta(uint64_t now, uint64_t then) { return now >= then ? now - then : 0; }

static void judge_evict(void) {
    const uint64_t thr = (uint64_t)tune_val(TUNE_SUPPRESS_EVICT_PER_MIN);
    int worst = -1, over = 0;
    uint64_t worst_n = 0;
    for (int k = 0; k < SH_EVICT_KIND_COUNT; k++) {
        unsigned fr = 0;
        unsigned in = evict_scope((sh_evict_t)k, &fr);
        uint64_t n = delta(sh_evict_count((sh_evict_t)k), g_supp.evict[k]);
        if (!in || n < thr) continue;
        over++;
        g_supp.inputs[SUP_EVICT] |= in & ~(fr ? 1u << COV_IN_DOT11 : 0u);
        g_supp.frames[SUP_EVICT] |= fr;
        if (n > worst_n) { worst_n = n; worst = k; }
    }
    g_supp.cond[SUP_EVICT] = over > 0;
    if (!over) return;
    g_supp.ev_worst = worst;
    g_supp.ev_over  = over;
}

/* One handle's minute: 1 when it is over both thresholds. */
static int drop_over(int ok_then, const capture_health_t *h,
                     uint64_t recv0, uint64_t lost0) {
    if (!ok_then || !handle_ok(h)) return 0;
    uint64_t recv = delta(h->ps_recv, recv0);
    uint64_t lost = delta(h->ps_drop + h->ps_ifdrop, lost0);
    if (lost < (uint64_t)tune_val(TUNE_SUPPRESS_DROP_MIN)) return 0;
    return lost * 100u >= (uint64_t)tune_val(TUNE_SUPPRESS_DROP_PCT) * recv;
}

static void judge_drop(const sloth_state_t *s) {
    const int mon = s->probe_iface[0] &&
        drop_over(g_supp.mon_ok, &s->mon_health, g_supp.mon_recv, g_supp.mon_lost);
    const int cap = s->pkt_iface[0] &&
        drop_over(g_supp.cap_ok, &s->cap_health, g_supp.cap_recv, g_supp.cap_lost);
    g_supp.cond[SUP_DROP] = mon || cap;
    if (!mon && !cap) return;
    if (mon) g_supp.inputs[SUP_DROP] |= 1u << COV_IN_DOT11;
    if (cap) {
        /* The capture interface delivers 802.11 frames when it is itself
         * in monitor mode (src/rule_coverage_live.c reads it the same). */
        const sys_snapshot_t *sn = sys_status_get();
        int dot11 = sn->valid && strcmp(sn->src[SYS_SRC_CAPTURE].kind, "wifi-monitor") == 0;
        g_supp.inputs[SUP_DROP] |= 1u << (dot11 ? COV_IN_DOT11 : COV_IN_IP);
    }
    g_supp.dr_mon = mon;
    g_supp.dr_cap = cap;
}

/* --cue's refusals at a limit over the minute (#248). A cue refused is
 * a finding whose channel the radio could not be held on, and false
 * triggers are how an attacker would try to hold it: every 802.11 kind
 * loses airtime either way. Under the threshold, or without --cue, not
 * over. */
static void judge_cue(const sloth_state_t *s) {
    uint64_t n = s->cue.on ? delta(s->cue.refused_limit, g_supp.cue_limit) : 0;
    g_supp.cond[SUP_CUE] = n >= (uint64_t)tune_val(TUNE_SUPPRESS_CUE_REFUSED_PER_MIN);
    if (g_supp.cond[SUP_CUE]) g_supp.inputs[SUP_CUE] |= 1u << COV_IN_DOT11;
}

/* A newly closed coverage interval: merge its channels by frequency,
 * then move each tracked channel's run. */
static void judge_silent_iv(const cov_iv_t *iv) {
    int freq[COV_IV_CHAN_MAX], ivb[COV_IV_CHAN_MAX], n = 0;
    uint64_t ms[COV_IV_CHAN_MAX], fr[COV_IV_CHAN_MAX];
    for (int i = 0; i < iv->nchan; i++) {
        const cov_iv_chan_t *c = &iv->chan[i];
        if (c->freq_mhz <= 0 || c->ms == 0) continue;
        int j = 0;
        while (j < n && freq[j] != c->freq_mhz) j++;
        if (j == n) {
            if (n == COV_IV_CHAN_MAX) continue;
            freq[n] = c->freq_mhz; ivb[n] = cov_ivb_of_mhz(c->freq_mhz);
            ms[n] = fr[n] = 0; n++;
        }
        ms[j] += c->ms;
        fr[j] += c->frames;
    }
    /* A channel not visited this interval breaks its run. */
    for (int t = 0; t < g_supp.nchan; t++) {
        int j = 0;
        while (j < n && freq[j] != g_supp.chan[t].freq) j++;
        if (j == n) g_supp.chan[t].run = 0;
    }
    for (int j = 0; j < n; j++) {
        if (ivb[j] == COV_IVB_UNKNOWN) continue;
        int t = 0;
        while (t < g_supp.nchan && g_supp.chan[t].freq != freq[j]) t++;
        if (t == g_supp.nchan) {
            if (t == COV_IV_CHAN_MAX) continue;
            memset(&g_supp.chan[t], 0, sizeof(g_supp.chan[t]));
            g_supp.chan[t].freq = freq[j];
            g_supp.chan[t].ivb  = ivb[j];
            g_supp.nchan++;
        }
        sup_chan_t *c = &g_supp.chan[t];
        if (fr[j] > 0) { c->heard = 1; c->run = 0; continue; }
        int band_heard = 0;
        for (int o = 0; o < n; o++)
            if (o != j && ivb[o] == ivb[j] && fr[o] > 0) band_heard = 1;
        c->run = band_heard && c->heard ? c->run + 1 : 0;
    }
}

static void judge_silent(void) {
    uint32_t newest = cov_iv_seq();
    if (newest == g_supp.iv_seq) return;
    uint32_t from = g_supp.iv_seq + 1;
    if (newest - g_supp.iv_seq > COV_IV_RING) from = newest - COV_IV_RING + 1;
    for (uint32_t q = from; q <= newest; q++) {
        cov_iv_t iv;
        if (cov_iv_get(q, &iv)) judge_silent_iv(&iv);
    }
    g_supp.iv_seq = newest;

    const long need = tune_val(TUNE_SUPPRESS_SILENT_INTERVALS);
    const sup_chan_t *first = NULL;
    int others = 0;
    for (int t = 0; t < g_supp.nchan; t++) {
        if (g_supp.chan[t].run < need) continue;
        if (!first) first = &g_supp.chan[t]; else others++;
    }
    g_supp.cond[SUP_SILENT] = first != NULL;
    if (!first) return;
    g_supp.inputs[SUP_SILENT] |= 1u << COV_IN_DOT11;
    g_supp.si_mhz    = first->freq;
    g_supp.si_ivb    = first->ivb;
    g_supp.si_others = others;
}

/* One signal's incident, re-asserted. The detail names what the minute
 * found and the threshold it passed, never the minute's own count, so
 * an episode is one observation per change of what it names. Each %s,
 * %d and %ld a plain variable bound just above (sloth-mesh's detail
 * audit, tests/test_alertfmt.c there): table and band are sloth's own
 * names (sh_evict_name(), cov_ivb_name()), iface the operator's own
 * interface name, the rest literals or numbers. */
static void fire_suppressed(const sloth_state_t *s, int sig, time_t now) {
    char detail[ALERT_DETAIL_LEN];
    if (sig == SUP_EVICT) {
        const char *table = sh_evict_name((sh_evict_t)g_supp.ev_worst);
        const char *more = g_supp.ev_over == 1 ? ""
                         : g_supp.ev_over == 2 ? " (and 1 other table)"
                                               : " (and other tables)";
        long thr = tune_val(TUNE_SUPPRESS_EVICT_PER_MIN);
        snprintf(detail, sizeof(detail),
                 "table %s%s evicted %ld or more rows in a minute: "
                 "observations it holds are being dropped before the rules "
                 "read them - a spray of new addresses, or a segment busier "
                 "than the table", table, more, thr);
    } else if (sig == SUP_DROP) {
        const char *handle = g_supp.dr_mon ? "monitor" : "capture";
        const char *iface  = g_supp.dr_mon ? s->probe_iface : s->pkt_iface;
        const char *more   = g_supp.dr_mon && g_supp.dr_cap
                           ? ", and the capture handle too" : "";
        long pct = tune_val(TUNE_SUPPRESS_DROP_PCT);
        snprintf(detail, sizeof(detail),
                 "the %s handle (%s) dropped %ld%% or more of what it "
                 "received in a minute%s: frames are lost before any parser "
                 "sees them - a flood, or a host too slow for the link",
                 handle, iface, pct, more);
    } else if (sig == SUP_CUE) {
        long thr = tune_val(TUNE_SUPPRESS_CUE_REFUSED_PER_MIN);
        snprintf(detail, sizeof(detail),
                 "--cue refused %ld or more cues at its limits in a minute: "
                 "findings arrive faster than the radio may be held on their "
                 "channels - false triggers aimed at the hop plan, or more "
                 "real findings than the limits allow", thr);
    } else {
        int mhz = g_supp.si_mhz;
        const char *band = cov_ivb_name(g_supp.si_ivb);
        const char *more = !g_supp.si_others ? ""
                         : g_supp.si_others == 1 ? " (and 1 other channel)"
                                                 : " (and other channels)";
        long need = tune_val(TUNE_SUPPRESS_SILENT_INTERVALS);
        snprintf(detail, sizeof(detail),
                 "%d MHz (%s GHz band)%s heard nothing for %ld or more "
                 "minutes in a row while the rest of its band was heard, "
                 "after hearing frames earlier in this run - jamming, a lost "
                 "antenna path, or every transmitter there switched off",
                 mhz, band, more, need);
    }
    fire(ALERT_TYPE_SENSOR_SUPPRESSED, ALERT_SEV_WARN, "SENSOR_SUPPRESSED",
         detail, sup_key[sig], NULL, 0, now);
}

/* main.c names every replayed stream's interface "replay" (#119). */
static int replaying(const sloth_state_t *s) {
    return strcmp(s->pkt_iface, "replay") == 0 || strcmp(s->probe_iface, "replay") == 0 ||
           strcmp(s->bt_iface, "replay") == 0;
}

void rule_sensor_suppressed(const sloth_state_t *s, time_t now) {
    if (replaying(s)) { memset(&g_supp, 0, sizeof(g_supp)); return; }
    const uint64_t mono = sloth_mono_ms();
    if (!g_supp.started) {
        take_window(s, mono);
        g_supp.iv_seq = cov_iv_seq();
        g_supp.started = 1;
    }
    if (held_ms(mono, g_supp.win_start) >= (uint64_t)COV_IV_MS) {
        judge_evict();
        judge_drop(s);
        judge_cue(s);
        take_window(s, mono);
    }
    judge_silent();

    for (int i = 0; i < SUP_N; i++) {
        sensor_hold_t *h = &g_supp.hold[i];
        if (h->open && !alert_key_open(sup_key[i])) h->open = 0;
        if (!g_supp.cond[i]) {
            hold_clear(h, sup_key[i], mono, now);
            if (!h->open) g_supp.inputs[i] = g_supp.frames[i] = 0;
            continue;
        }
        h->ok_on = 0;
        fire_suppressed(s, i, now);
        h->open = 1;
    }
}

void rules_sensor_suppressed(unsigned *inputs, unsigned *frames) {
    unsigned in = 0, fr = 0;
    for (int i = 0; i < SUP_N; i++) {
        if (!g_supp.hold[i].open || !alert_key_open(sup_key[i])) continue;
        in |= g_supp.inputs[i];
        fr |= g_supp.frames[i];
    }
    if (inputs) *inputs = in;
    if (frames) *frames = fr;
}
