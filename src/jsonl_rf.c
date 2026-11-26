#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "jsonl.h"
#include "jsonl_internal.h"
#include "gps.h"
#include "adsb.h"
#include "aprs.h"
#include "rtl433.h"
#include "victron.h"
#include "sloth_clock.h"
#include "tune.h"
#include "data_socket.h"
#include "sensor_health.h"
#include "sys_status.h"
#include "rule_coverage_live.h"
#include "questions_live.h"
#include "libver.h"
#include "db.h"

/* The receiver's and the decoders' records (#213): gnss_fix, gnss_sky,
 * gnss_sat, adsb_aircraft, aprs_packet, aprs_station, rtl433_device and
 * victron_device, their sensor_health blocks, and the list sloth-rf writes each tick.
 * Moved here from src/jsonl.c so that a daemon with no capture links
 * them; `sloth` still calls every emitter below from
 * jsonl_emit_state_snapshots(), in the place it always did. */

/* ── GNSS observation (2026-11-02) ──────────────────────────────────
 *
 * Three change-only records off the receiver sloth already reads for
 * its position (docs/wiki/gnss.md), each signed on bands, never on a
 * figure that moves every second:
 *
 *   gnss_fix  the newest TPV, key "gnss_fix": gps_gnss_fix_sig()
 *   gnss_sky  the newest SKY's summary, key "gnss_sky": gps_gnss_sky_sig()
 *   gnss_sat  one per satellite in view, key gnssid|prn:
 *             gps_gnss_sat_sig() (used, health, C/N0 to 6 dB, el/az to
 *             15 degrees), so a steady sky writes nothing between
 *             heartbeats and one satellite rising, joining or leaving
 *             the solution or crossing a band writes that one record,
 *             not the whole sky. A satellite that sets writes nothing:
 *             only the current sky is walked, so a consumer infers it
 *             from the row's 300 s heartbeat lapsing (slothweb drops a
 *             row quiet for 660 s); one that sets and re-rises inside a
 *             heartbeat with the same bands is silent too.
 *
 * Per satellite rather than a nested array in gnss_sky, for the same
 * reason ble_device is per advertiser: a consumer keeps a table keyed
 * by the row, and a change in one row costs one line. Every figure is
 * written without %f (gps_fmt_fixed; locale). */
static void kv_fixed(char *buf, int *off, const char *key, double v, int dp) {
    char t[32];
    gps_fmt_fixed(t, sizeof(t), v, dp);
    appendf(buf, LINEBUF, off, ",\"%s\":%s", key, t);
}

void jsonl_emit_gnss(const sloth_state_t *s) {
    if (!any_sink() || !s || !s->gps.has_gps) return;
    time_t now = sloth_wall();
    const gnss_fix_t *f = &s->gnss_fix;
    const gnss_sky_t *k = &s->gnss_sky;
    char buf[LINEBUF]; int off = 0;

    if (f->valid &&
        jsonl_changed(JD_GNSS_FIX, "gnss_fix", 8, gps_gnss_fix_sig(f, k), now)) {
        start_obj(buf, LINEBUF, &off, "gnss_fix", now);
        kv_str(buf, LINEBUF, &off, "src", s->gps.src);
        kv_int(buf, LINEBUF, &off, "fix_ts", (long long)f->ts);
        kv_int(buf, LINEBUF, &off, "mode", f->mode);
        kv_int(buf, LINEBUF, &off, "status", f->status);
        kv_int(buf, LINEBUF, &off, "nsat", k->valid ? k->nsat : -1);
        kv_int(buf, LINEBUF, &off, "usat", k->valid ? k->usat : -1);
        kv_fixed(buf, &off, "hdop", k->hdop, 1);
        kv_fixed(buf, &off, "vdop", k->vdop, 1);
        kv_fixed(buf, &off, "pdop", k->pdop, 1);
        if (f->has_pos) {
            /* Five decimals, as the alerts' stamp exports it; written,
             * never signed ([[location]]'s privacy rules apply). */
            kv_fixed(buf, &off, "lat", f->lat, 5);
            kv_fixed(buf, &off, "lon", f->lon, 5);
        }
        if (f->has_alt)   kv_fixed(buf, &off, "alt_m", f->alt_m, 1);
        if (f->has_eph)   kv_fixed(buf, &off, "eph", f->eph, 1);
        if (f->has_epv)   kv_fixed(buf, &off, "epv", f->epv, 1);
        if (f->has_speed) kv_fixed(buf, &off, "speed_mps", f->speed, 2);
        if (f->has_track) kv_fixed(buf, &off, "track_deg", f->track, 1);
        if (f->has_rx_time)
            kv_int(buf, LINEBUF, &off, "rx_time_ms", f->rx_time_ms);
        if (f->has_time_off)
            kv_int(buf, LINEBUF, &off, "time_off_ms", f->time_off_ms);
        kv_int(buf, LINEBUF, &off, "leap", f->leap);
        kv_int(buf, LINEBUF, &off, "jam", f->jam);
        if (f->has_gst) {
            kv_fixed(buf, &off, "gst_rms", f->gst_rms, 2);
            kv_fixed(buf, &off, "gst_major", f->gst_major, 2);
            kv_fixed(buf, &off, "gst_minor", f->gst_minor, 2);
            kv_fixed(buf, &off, "gst_orient", f->gst_orient, 1);
            kv_fixed(buf, &off, "gst_lat_sd", f->gst_lat_sd, 2);
            kv_fixed(buf, &off, "gst_lon_sd", f->gst_lon_sd, 2);
            kv_fixed(buf, &off, "gst_alt_sd", f->gst_alt_sd, 2);
        }
        kv_int(buf, LINEBUF, &off, "tpv_count", (long long)f->count);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }

    if (!k->valid) return;
    if (jsonl_changed(JD_GNSS_SKY, "gnss_sky", 8, gps_gnss_sky_sig(k), now)) {
        start_obj(buf, LINEBUF, &off, "gnss_sky", now);
        kv_str(buf, LINEBUF, &off, "src", s->gps.src);
        kv_int(buf, LINEBUF, &off, "sky_ts", (long long)k->ts);
        kv_int(buf, LINEBUF, &off, "nsat", k->nsat);
        kv_int(buf, LINEBUF, &off, "usat", k->usat);
        kv_int(buf, LINEBUF, &off, "rows", k->n);
        kv_int(buf, LINEBUF, &off, "overflow", k->overflow);
        kv_fixed(buf, &off, "hdop", k->hdop, 1);
        kv_fixed(buf, &off, "vdop", k->vdop, 1);
        kv_fixed(buf, &off, "pdop", k->pdop, 1);
        kv_fixed(buf, &off, "gdop", k->gdop, 1);
        kv_fixed(buf, &off, "tdop", k->tdop, 1);
        kv_fixed(buf, &off, "cn0_mean", k->cn0_mean, 1);
        kv_fixed(buf, &off, "cn0_max", k->cn0_max, 1);
        kv_fixed(buf, &off, "cn0_sd", k->cn0_sd, 1);
        kv_int(buf, LINEBUF, &off, "cn0_n", k->cn0_n);
        kv_int(buf, LINEBUF, &off, "passes", (long long)k->passes);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
    for (int i = 0; i < k->n && i < GNSS_MAX_SATS; i++) {
        const gnss_sat_t *a = &k->sats[i];
        int16_t key[2] = { (int16_t)a->gnssid, a->prn };
        if (!jsonl_changed(JD_GNSS_SAT, key, sizeof(key), gps_gnss_sat_sig(a), now))
            continue;
        start_obj(buf, LINEBUF, &off, "gnss_sat", now);
        kv_str(buf, LINEBUF, &off, "gnss", a->gnssid >= 0 ? gnss_name(a->gnssid) : "");
        kv_int(buf, LINEBUF, &off, "gnssid", a->gnssid);
        kv_int(buf, LINEBUF, &off, "svid", a->svid);
        kv_int(buf, LINEBUF, &off, "prn", a->prn);
        kv_int(buf, LINEBUF, &off, "sigid", a->sigid);
        /* el / az only when gpsd sent them: a key with -1 was both
         * "absent" and a bird one degree below the horizon. */
        if (a->has_el) kv_int(buf, LINEBUF, &off, "el", a->el);
        if (a->has_az) kv_int(buf, LINEBUF, &off, "az", a->az);
        if (a->has_cn0) kv_fixed(buf, &off, "cn0", a->cn0_x10 / 10.0, 1);
        kv_int(buf, LINEBUF, &off, "used", a->used);
        kv_int(buf, LINEBUF, &off, "health", a->health);
        kv_int(buf, LINEBUF, &off, "sky_ts", (long long)k->ts);
        end_obj(buf, LINEBUF, &off);
        emit_line(buf);
    }
}

/* ── ADS-B aircraft (#26 slice 1, 2026-11-05) ───────────────────────
 *
 * adsb_aircraft: one record per aircraft the --adsb decoder lists,
 * keyed by address (icao + non_icao), change-only on adsb_row_sig() -
 * the held altitude band, the held 0.1 degree position cell, squawk,
 * emergency, callsign, category, and first_seen - never on the figures
 * that move every second (src/adsb.h has the bands and why). So an
 * aircraft is a record when it first appears, one per band or cell it
 * crosses, one per squawk / emergency / callsign change, the 300 s
 * heartbeat while it stays, and one with "state":"gone" when the
 * decoder has not heard it for ADSB_EXPIRE_S. The gone record is
 * written unconditionally (it happens once per row), and also re-signs
 * the slot, so the same address coming back is a fresh record. Every
 * figure is written without %f (gps_fmt_fixed; locale). */
static void emit_adsb_row(const adsb_aircraft_t *a, const char *state,
                          const char *src, time_t now) {
    char buf[LINEBUF]; int off = 0;
    char hex[8];
    snprintf(hex, sizeof(hex), "%s%06x", a->non_icao ? "~" : "",
             (unsigned)(a->icao & 0xffffffu));
    start_obj(buf, LINEBUF, &off, "adsb_aircraft", now);
    kv_str(buf, LINEBUF, &off, "hex", hex);
    kv_int(buf, LINEBUF, &off, "non_icao", a->non_icao);
    kv_str(buf, LINEBUF, &off, "state", state);
    kv_str(buf, LINEBUF, &off, "src", src);
    kv_str(buf, LINEBUF, &off, "source_type", a->type);
    kv_str(buf, LINEBUF, &off, "flight", a->flight);
    kv_str(buf, LINEBUF, &off, "squawk", a->squawk);
    kv_str(buf, LINEBUF, &off, "category", a->category);
    kv_str(buf, LINEBUF, &off, "emergency", adsb_emergency_name(a->emergency));
    kv_int(buf, LINEBUF, &off, "on_ground", a->on_ground);
    if (a->has_alt_baro) kv_int(buf, LINEBUF, &off, "alt_baro", a->alt_baro);
    if (a->has_alt_geom) kv_int(buf, LINEBUF, &off, "alt_geom", a->alt_geom);
    kv_int(buf, LINEBUF, &off, "alt_band", a->alt_band == INT16_MIN ? -1 : a->alt_band);
    if (a->has_gs)        kv_fixed(buf, &off, "gs", a->gs, 1);
    if (a->has_track)     kv_fixed(buf, &off, "track", a->track, 1);
    if (a->has_baro_rate) kv_int(buf, LINEBUF, &off, "baro_rate", a->baro_rate);
    if (a->has_geom_rate) kv_int(buf, LINEBUF, &off, "geom_rate", a->geom_rate);
    if (a->has_pos) {
        kv_fixed(buf, &off, "lat", a->lat, 5);
        kv_fixed(buf, &off, "lon", a->lon, 5);
        kv_int(buf, LINEBUF, &off, "pos_ts", (long long)a->pos_ts);
    }
    if (a->has_rssi)      kv_fixed(buf, &off, "rssi", a->rssi, 1);
    if (a->has_messages)  kv_int(buf, LINEBUF, &off, "messages", (long long)a->messages);
    kv_int(buf, LINEBUF, &off, "first_seen", (long long)a->first_seen);
    kv_int(buf, LINEBUF, &off, "last_seen", (long long)a->last_seen);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

static void adsb_key(const adsb_aircraft_t *a, uint8_t key[4]) {
    key[0] = (uint8_t)(a->icao >> 16);
    key[1] = (uint8_t)(a->icao >> 8);
    key[2] = (uint8_t)a->icao;
    key[3] = a->non_icao;
}

void jsonl_emit_adsb(const sloth_state_t *s) {
    if (!any_sink() || !s || !s->adsb.configured) return;
    time_t now = sloth_wall();
    for (int i = 0; s->adsb_gone && i < s->adsb_gone_count; i++) {
        const adsb_aircraft_t *a = &s->adsb_gone[i];
        uint8_t key[4];
        adsb_key(a, key);
        (void)jsonl_changed(JD_ADSB_AIRCRAFT, key, sizeof(key),
                            ~adsb_row_sig(a), now);
        emit_adsb_row(a, "gone", s->adsb.src, now);
    }
    for (int i = 0; s->adsb_rows && i < s->adsb_count; i++) {
        const adsb_aircraft_t *a = &s->adsb_rows[i];
        uint8_t key[4];
        adsb_key(a, key);
        if (!jsonl_changed(JD_ADSB_AIRCRAFT, key, sizeof(key),
                           adsb_row_sig(a), now))
            continue;
        emit_adsb_row(a, "live", s->adsb.src, now);
    }
}

/* ── APRS (2026-11-05) ──────────────────────────────────────────────
 *
 * aprs_packet: one record per packet Dire Wolf decoded - an event, not
 * a snapshot: the channel's 1200 bit/s bounds the rate to a few a
 * second at the very most. Every parsed field, each omitted when the
 * line left it empty or out of range (never written as 0 or ""). The
 * packets come off src/aprs.c's ring (s->aprs_pkts, oldest first);
 * this writer keeps its own cursor, the newest seq written, so a tick
 * writes each new packet once. With no sink open the cursor still
 * moves: a consumer connecting later is not handed old packets.
 *
 * aprs_station: one record per station (the packet's source), change-
 * only on aprs_station_sig() - the call, first_seen, the held 0.01
 * degree cell, has_pos, the symbol, heard_direct - plus the 300 s
 * heartbeat while it stays, and one "state":"gone" record when it has
 * not been heard for APRS_EXPIRE_S; the gone record re-signs the slot,
 * so the same call coming back is a fresh record. Figures without %f
 * (gps_fmt_fixed; locale). */
static uint64_t g_aprs_cursor;

/* Start the packet cursor over (sloth_reset_all(), #213). The emitter
 * below notices a restarted ring only when the ring's last seq is
 * below the cursor; a second run that decodes as many packets as the
 * first ends on the same seq, and would write none of them. */
void jsonl_aprs_reset(void) { g_aprs_cursor = 0; }

static void kv_str_opt(char *buf, int *off, const char *key, const char *v) {
    if (v && v[0]) kv_str(buf, LINEBUF, off, key, v);
}

static void emit_aprs_packet(const aprs_packet_t *p, const char *src, time_t now) {
    char buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "aprs_packet", now);
    kv_str(buf, LINEBUF, &off, "src", src);
    kv_int(buf, LINEBUF, &off, "seq", (long long)p->seq);
    kv_int(buf, LINEBUF, &off, "chan", p->chan);
    kv_int(buf, LINEBUF, &off, "utime", (long long)p->utime);
    kv_str(buf, LINEBUF, &off, "source", p->source);
    if (p->heard[0]) {
        kv_str(buf, LINEBUF, &off, "heard", p->heard);
        kv_int(buf, LINEBUF, &off, "direct", strcmp(p->heard, p->source) == 0);
    }
    if (p->level >= 0) kv_int(buf, LINEBUF, &off, "level", p->level);
    if (p->error >= 0) kv_int(buf, LINEBUF, &off, "error", p->error);
    if (p->dti) {
        char d[2] = { p->dti, '\0' };
        kv_str(buf, LINEBUF, &off, "dti", d);
    }
    kv_str_opt(buf, &off, "name", p->name);
    kv_str_opt(buf, &off, "symbol", p->symbol);
    if (p->has_pos) {
        kv_fixed(buf, &off, "lat", p->lat, 6);
        kv_fixed(buf, &off, "lon", p->lon, 6);
    }
    if (p->has_speed)  kv_fixed(buf, &off, "speed_kt", p->speed_kt, 1);
    if (p->has_course) kv_fixed(buf, &off, "course", p->course, 1);
    if (p->has_alt)    kv_fixed(buf, &off, "alt_m", p->alt_m, 1);
    kv_str_opt(buf, &off, "freq", p->freq);
    kv_str_opt(buf, &off, "offset", p->offset);
    kv_str_opt(buf, &off, "tone", p->tone);
    kv_str_opt(buf, &off, "system", p->system);
    kv_str_opt(buf, &off, "status", p->status);
    kv_str_opt(buf, &off, "telemetry", p->telemetry);
    kv_str_opt(buf, &off, "comment", p->comment);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

static void emit_aprs_station(const aprs_station_t *a, const char *state,
                              const char *src, time_t now) {
    char buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "aprs_station", now);
    kv_str(buf, LINEBUF, &off, "call", a->call);
    kv_str(buf, LINEBUF, &off, "state", state);
    kv_str(buf, LINEBUF, &off, "src", src);
    kv_int(buf, LINEBUF, &off, "first_seen", (long long)a->first_seen);
    kv_int(buf, LINEBUF, &off, "last_seen", (long long)a->last_seen);
    kv_int(buf, LINEBUF, &off, "packets", (long long)a->packets);
    if (a->via[0]) {
        kv_str(buf, LINEBUF, &off, "via", a->via);
        kv_int(buf, LINEBUF, &off, "direct", a->last_direct);
    }
    kv_int(buf, LINEBUF, &off, "heard_direct", a->heard_direct);
    if (a->level >= 0)      kv_int(buf, LINEBUF, &off, "level", a->level);
    if (a->best_level >= 0) kv_int(buf, LINEBUF, &off, "best_level", a->best_level);
    if (a->dti) {
        char d[2] = { a->dti, '\0' };
        kv_str(buf, LINEBUF, &off, "dti", d);
    }
    kv_str_opt(buf, &off, "symbol", a->symbol);
    if (a->has_pos) {
        kv_fixed(buf, &off, "lat", a->lat, 6);
        kv_fixed(buf, &off, "lon", a->lon, 6);
        kv_int(buf, LINEBUF, &off, "pos_ts", (long long)a->pos_ts);
        if (a->has_speed)  kv_fixed(buf, &off, "speed_kt", a->speed_kt, 1);
        if (a->has_course) kv_fixed(buf, &off, "course", a->course, 1);
        if (a->has_alt)    kv_fixed(buf, &off, "alt_m", a->alt_m, 1);
    }
    kv_str_opt(buf, &off, "system", a->system);
    kv_str_opt(buf, &off, "status", a->status);
    kv_str_opt(buf, &off, "comment", a->comment);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_aprs(const sloth_state_t *s) {
    if (!s || !s->aprs.configured) return;
    int sink = any_sink();
    time_t now = sloth_wall();
    /* The ring restarted under the cursor (aprs_reset(): tests, or a
     * reconfigure): start again from its oldest. */
    if (s->aprs_pkts && s->aprs_pkt_count &&
        s->aprs_pkts[s->aprs_pkt_count - 1].seq < g_aprs_cursor)
        g_aprs_cursor = 0;
    for (int i = 0; s->aprs_pkts && i < s->aprs_pkt_count; i++) {
        const aprs_packet_t *p = &s->aprs_pkts[i];
        if (p->seq <= g_aprs_cursor) continue;
        if (sink) emit_aprs_packet(p, s->aprs.src, now);
        g_aprs_cursor = p->seq;
    }
    if (!sink) return;
    for (int i = 0; s->aprs_gone && i < s->aprs_gone_count; i++) {
        const aprs_station_t *a = &s->aprs_gone[i];
        (void)jsonl_changed(JD_APRS_STATION, a->call, strlen(a->call),
                            ~aprs_station_sig(a), now);
        emit_aprs_station(a, "gone", s->aprs.src, now);
    }
    for (int i = 0; s->aprs_rows && i < s->aprs_count; i++) {
        const aprs_station_t *a = &s->aprs_rows[i];
        if (!jsonl_changed(JD_APRS_STATION, a->call, strlen(a->call),
                           aprs_station_sig(a), now))
            continue;
        emit_aprs_station(a, "live", s->aprs.src, now);
    }
}

/* ── rtl_433 sub-GHz devices (#208, 2026-11-14) ──────────────────────
 *
 * rtl433_device: one record per (model, id) row, change-only on
 * rtl433_device_sig() - the key, first_seen (an evicted row that comes
 * back is a new row), the row's discrete facts, and every continuous
 * value as the band src/rtl433.h defines - plus the 300 s heartbeat
 * while the row stays. There is no "gone" record: the table retires
 * nothing by age (a device heard once is a real observation of the
 * band), so a row leaves only by eviction, which `rtl433_evicted` in
 * sensor_health counts.
 *
 * `msgs`, `last_seen`, `snr`, `noise` and `other_keys` are WRITTEN and
 * not signed: each moves with every decode, and signing one would turn
 * this into the per-decode firehose agents/AGENTS.md forbids - one TPMS
 * on a kerbside sensor writes a line every few seconds for as long as
 * the car is parked within earshot.
 *
 * A temperature or pressure goes out under the key it arrived under
 * (`temperature_C`, `pressure_kPa`, ...), never converted: see
 * include/sloth.h's rtl433_temp_unit_t. Figures without %f
 * (gps_fmt_fixed; locale). */

static void emit_rtl433_device(const rtl433_device_t *d, const char *src,
                               time_t now) {
    char buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "rtl433_device", now);
    kv_str(buf, LINEBUF, &off, "src", src);
    kv_str(buf, LINEBUF, &off, "model", d->model);
    kv_str(buf, LINEBUF, &off, "id", d->id);
    kv_int(buf, LINEBUF, &off, "first_seen", (long long)d->first_seen);
    kv_int(buf, LINEBUF, &off, "last_seen", (long long)d->last_seen);
    kv_int(buf, LINEBUF, &off, "msgs", (long long)d->msgs);
    kv_str_opt(buf, &off, "dev_type", d->type);
    kv_str_opt(buf, &off, "subtype", d->subtype);
    kv_str_opt(buf, &off, "channel", d->channel);
    kv_str_opt(buf, &off, "mic", d->mic);
    kv_str_opt(buf, &off, "mod", d->mod);
    if (d->protocol >= 0) kv_int(buf, LINEBUF, &off, "protocol", d->protocol);
    if (d->has_freq)  kv_fixed(buf, &off, "freq_mhz", d->freq_mhz, 3);
    if (d->has_freq2) kv_fixed(buf, &off, "freq2_mhz", d->freq2_mhz, 3);
    if (d->has_rssi)  kv_fixed(buf, &off, "rssi", d->rssi_db, 1);
    if (d->has_snr)   kv_fixed(buf, &off, "snr", d->snr_db, 1);
    if (d->has_noise) kv_fixed(buf, &off, "noise", d->noise_db, 1);
    if (d->has_battery) kv_fixed(buf, &off, "battery_ok", d->battery_ok, 1);
    if (d->has_temp) {
        char key[20];
        snprintf(key, sizeof(key), "temperature_%s",
                 rtl433_temp_unit_name(d->temp_unit));
        kv_fixed(buf, &off, key, d->temp, 1);
    }
    if (d->has_humidity) kv_fixed(buf, &off, "humidity", d->humidity, 1);
    if (d->has_pressure) {
        char key[20];
        snprintf(key, sizeof(key), "pressure_%s",
                 rtl433_pres_unit_name(d->pres_unit));
        kv_fixed(buf, &off, key, d->pressure, 1);
    }
    kv_int(buf, LINEBUF, &off, "other_keys", (long long)d->other_keys);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_rtl433(const sloth_state_t *s) {
    if (!any_sink() || !s || !s->rtl433.configured) return;
    time_t now = sloth_wall();
    for (int i = 0; s->rtl433_rows && i < s->rtl433_count; i++) {
        const rtl433_device_t *d = &s->rtl433_rows[i];
        /* The key is both halves: two models may share an id, and the
         * row is only a row when both match (rtl433.c dev_key_eq).
         * Hashed to the dedup slot's JSONL_DEDUP_KEYLEN bytes rather
         * than passed raw: jsonl_changed() keeps only the first 16
         * bytes, and a model of 15 or more ("Schrader-EG53MA4") would
         * leave no byte of the id, so two such sensors would share one
         * slot and each tick would write both (#208 review). */
        uint64_t hk[2];
        hk[0] = fnv1a(d->model, strlen(d->model), FNV64_OFFSET);
        hk[1] = fnv1a(d->id, strlen(d->id), fnv1a("\x1f", 1, hk[0]));
        uint8_t key[sizeof(hk)];
        memcpy(key, hk, sizeof(key));
        if (!jsonl_changed(JD_RTL433_DEVICE, key, sizeof(key),
                           rtl433_device_sig(d), now))
            continue;
        emit_rtl433_device(d, s->rtl433.src, now);
    }
}

/* ── Victron devices (--victron, 2026-11-15) ────────────────────────
 *
 * victron_device: one record per address row of sloth-va's file,
 * change-only on victron_device_sig() (values banded there) plus the
 * 300 s heartbeat. `readings`, `sessions`, `last_seen` and `rssi` are
 * written and not signed: each moves with every record sloth-va
 * appends. Values go out under sloth-va's unit-suffixed names. No
 * "gone" record: the table retires nothing. */

static void emit_victron_device(const victron_device_t *d, const char *src,
                                time_t now) {
    char buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "victron_device", now);
    kv_str(buf, LINEBUF, &off, "src", src);
    kv_str(buf, LINEBUF, &off, "mac", d->mac);
    kv_str_opt(buf, &off, "serial", d->serial);
    kv_str_opt(buf, &off, "model", d->model);
    kv_str_opt(buf, &off, "record", d->record);
    kv_str_opt(buf, &off, "session", d->session);
    kv_str_opt(buf, &off, "services", d->services);
    kv_int(buf, LINEBUF, &off, "first_seen", (long long)d->first_seen);
    kv_int(buf, LINEBUF, &off, "last_seen", (long long)d->last_seen);
    kv_int(buf, LINEBUF, &off, "last_readout", (long long)d->last_readout);
    kv_int(buf, LINEBUF, &off, "last_gatt", (long long)d->last_gatt);
    kv_int(buf, LINEBUF, &off, "readings", (long long)d->readings);
    kv_int(buf, LINEBUF, &off, "sessions", (long long)d->sessions);
    if (d->has_rssi) kv_int(buf, LINEBUF, &off, "rssi", d->rssi);
    /* Which of sloth-va's two paths the newest values came from (JSONL
     * 1.10.0): the fleet rule turns on it (a GATT reading is an
     * authenticated connection's, never monitor provenance) and so does
     * slothweb's Victron tab. */
    if (d->nvals > 0)
        kv_str(buf, LINEBUF, &off, "values_src", d->vals_gatt ? "gatt" : "readout");
    for (int i = 0; i < d->nvals; i++)
        kv_fixed(buf, &off, d->vals[i].name, d->vals[i].v, 3);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

void jsonl_emit_victron(const sloth_state_t *s) {
    if (!any_sink() || !s || !s->victron.configured) return;
    time_t now = sloth_wall();
    for (int i = 0; s->victron_rows && i < s->victron_count; i++) {
        const victron_device_t *d = &s->victron_rows[i];
        /* Hashed, not the 17-byte text: jsonl_changed() keeps 16 bytes
         * of a key, which would drop the address's last digit. */
        uint64_t hk = fnv1a(d->mac, strlen(d->mac), FNV64_OFFSET);
        uint8_t key[sizeof(hk)];
        memcpy(key, &hk, sizeof(key));
        if (!jsonl_changed(JD_VICTRON_DEVICE, key, sizeof(key),
                           victron_device_sig(d), now))
            continue;
        emit_victron_device(d, s->victron.src, now);
    }
}

/* ── sensor_health blocks (src/jsonl_internal.h) ─────────── */

void jsonl_sh_rf_sig(const sloth_state_t *s, jsonl_sh_rf_sig_t *o) {
    o->adsb_configured    = s->adsb.configured;
    o->adsb_state         = s->adsb.state;
    o->adsb_read_err_any  = s->adsb.read_errors > 0;
    o->adsb_parse_err_any = s->adsb.parse_errors > 0;
    o->adsb_overflow_any  = s->adsb.overflow > 0;
    o->adsb_bad_any       = s->adsb.bad_entries > 0;
    o->adsb_err_any       = s->adsb.err[0] != '\0';
    o->aprs_configured    = s->aprs.configured;
    o->aprs_state         = s->aprs.state;
    o->aprs_missing       = s->aprs.missing;
    o->aprs_read_err_any  = s->aprs.read_errors > 0;
    o->aprs_bad_any       = s->aprs.bad_lines > 0;
    o->aprs_overflow_any  = s->aprs.overflow > 0;
    o->aprs_err_any       = s->aprs.err[0] != '\0';
    o->aprs_region        = s->aprs.configured ? s->aprs.region : 0;
    o->aprs_freq_mismatch = s->aprs.configured ? s->aprs.freq_mismatch : 0;
    o->aprs_silent        = s->aprs.configured ? s->aprs.silent : 0;
    o->rtl433_configured  = s->rtl433.configured;
    o->rtl433_state       = s->rtl433.state;
    o->rtl433_missing     = s->rtl433.missing;
    o->rtl433_read_err_any  = s->rtl433.read_errors > 0;
    o->rtl433_bad_any       = s->rtl433.bad_lines > 0;
    o->rtl433_evicted_any   = s->rtl433.evicted > 0;
    o->rtl433_other_keys_any = s->rtl433.other_keys > 0;
    o->rtl433_bad_values_any = s->rtl433.bad_values > 0;
    o->rtl433_err_any       = s->rtl433.err[0] != '\0';
    o->victron_configured   = s->victron.configured;
    o->victron_state        = s->victron.state;
    o->victron_missing      = s->victron.missing;
    o->victron_read_err_any = s->victron.read_errors > 0;
    o->victron_bad_any      = s->victron.bad_lines > 0;
    o->victron_full_any     = s->victron.table_full > 0;
    o->victron_other_keys_any = s->victron.other_keys > 0;
    o->victron_bad_values_any = s->victron.bad_values > 0;
    o->victron_err_any      = s->victron.err[0] != '\0';
}

void jsonl_sh_adsb(char *buf, int *off, const sloth_state_t *s) {
    /* --adsb (#26 slice 1), ONLY with --adsb, so a run without it writes
     * exactly what it wrote before. Appended. */
    if (s->adsb.configured) {
        const adsb_health_t *a = &s->adsb;
        kv_str(buf, LINEBUF, off, "adsb_state", adsb_state_name(a->state));
        kv_str(buf, LINEBUF, off, "adsb_src", a->src);
        kv_int(buf, LINEBUF, off, "adsb_age_s", a->age_s);
        kv_int(buf, LINEBUF, off, "adsb_last_read", (long long)a->last_read);
        kv_int(buf, LINEBUF, off, "adsb_aircraft", a->aircraft);
        kv_int(buf, LINEBUF, off, "adsb_messages", (long long)a->messages);
        kv_int(buf, LINEBUF, off, "adsb_reads", (long long)a->reads);
        kv_int(buf, LINEBUF, off, "adsb_read_errors", (long long)a->read_errors);
        kv_int(buf, LINEBUF, off, "adsb_parse_errors", (long long)a->parse_errors);
        kv_int(buf, LINEBUF, off, "adsb_overflow", (long long)a->overflow);
        kv_int(buf, LINEBUF, off, "adsb_bad_entries", (long long)a->bad_entries);
        kv_int(buf, LINEBUF, off, "adsb_expired", (long long)a->expired);
        kv_str(buf, LINEBUF, off, "adsb_err", a->err);
    }
}

void jsonl_sh_aprs(char *buf, int *off, const sloth_state_t *s) {
    /* --aprs, ONLY with --aprs, so a run without it writes exactly what
     * it wrote before. Appended. */
    if (s->aprs.configured) {
        const aprs_health_t *a = &s->aprs;
        kv_str(buf, LINEBUF, off, "aprs_state", aprs_state_name(a->state));
        kv_str(buf, LINEBUF, off, "aprs_src", a->src);
        kv_int(buf, LINEBUF, off, "aprs_missing", a->missing);
        kv_int(buf, LINEBUF, off, "aprs_last_read", (long long)a->last_read);
        kv_int(buf, LINEBUF, off, "aprs_last_packet", (long long)a->last_packet);
        kv_int(buf, LINEBUF, off, "aprs_stations", a->stations);
        kv_int(buf, LINEBUF, off, "aprs_bytes", (long long)a->bytes);
        kv_int(buf, LINEBUF, off, "aprs_lines", (long long)a->lines);
        kv_int(buf, LINEBUF, off, "aprs_packets", (long long)a->packets);
        kv_int(buf, LINEBUF, off, "aprs_bad_lines", (long long)a->bad_lines);
        kv_int(buf, LINEBUF, off, "aprs_overflow", (long long)a->overflow);
        kv_int(buf, LINEBUF, off, "aprs_expired", (long long)a->expired);
        kv_int(buf, LINEBUF, off, "aprs_truncations", (long long)a->truncations);
        kv_int(buf, LINEBUF, off, "aprs_rotations", (long long)a->rotations);
        kv_int(buf, LINEBUF, off, "aprs_read_errors", (long long)a->read_errors);
        kv_str(buf, LINEBUF, off, "aprs_err", a->err);
    }
}

void jsonl_sh_aprs_region(char *buf, int *off, const sloth_state_t *s) {
    /* #204, additive: the APRS region and channel the sensor's position
     * says, the decoder's declared frequency and the two findings. ONLY
     * with --aprs; after the twin193 block and before db_max_mb, so
     * every earlier field keeps its place and the db_max_mb /
     * jsonl_version tail stays as test_jsonl.c pins it. The region's
     * name and Hz only: the position it came from (loc_lat / loc_lon,
     * which sloth already writes) is not repeated or kept here. */
    if (s->aprs.configured) {
        const aprs_health_t *a = &s->aprs;
        kv_str(buf, LINEBUF, off, "aprs_region", aprs_region_name(a->region));
        kv_int(buf, LINEBUF, off, "aprs_region_hz", (long long)a->region_hz);
        kv_int(buf, LINEBUF, off, "aprs_freq_hz", (long long)a->freq_hz);
        kv_int(buf, LINEBUF, off, "aprs_freq_mismatch", a->freq_mismatch);
        kv_int(buf, LINEBUF, off, "aprs_silent", a->silent);
        kv_int(buf, LINEBUF, off, "aprs_silent_after_s", a->silent_after_s);
        kv_int(buf, LINEBUF, off, "aprs_quiet_since", (long long)a->quiet_since);
    }
}

void jsonl_sh_rtl433(char *buf, int *off, const sloth_state_t *s) {
    /* #208, additive (JSONL 1.8.0): the --rtl433 source's health. ONLY
     * with --rtl433, so a run without it writes exactly what it wrote
     * before; appended after the aprs block and before db_max_mb, so
     * every earlier field keeps its place and the db_max_mb /
     * jsonl_version tail stays as test_jsonl.c pins it.
     *
     * `rtl433_other_keys` is the measured size of the gap src/rtl433.h
     * names: keys the decoder wrote that this slice does not store. A
     * rising value is not a fault, it is the per-model field set of
     * whatever is on the air. */
    if (s->rtl433.configured) {
        const rtl433_health_t *r = &s->rtl433;
        kv_str(buf, LINEBUF, off, "rtl433_state", rtl433_state_name(r->state));
        kv_str(buf, LINEBUF, off, "rtl433_src", r->src);
        kv_int(buf, LINEBUF, off, "rtl433_missing", r->missing);
        kv_int(buf, LINEBUF, off, "rtl433_last_read", (long long)r->last_read);
        kv_int(buf, LINEBUF, off, "rtl433_last_msg", (long long)r->last_msg);
        kv_int(buf, LINEBUF, off, "rtl433_devices", r->devices);
        kv_int(buf, LINEBUF, off, "rtl433_bytes", (long long)r->bytes);
        kv_int(buf, LINEBUF, off, "rtl433_lines", (long long)r->lines);
        kv_int(buf, LINEBUF, off, "rtl433_msgs", (long long)r->msgs);
        kv_int(buf, LINEBUF, off, "rtl433_bad_lines", (long long)r->bad_lines);
        for (int k = 0; k < RTL433_REJ_COUNT; k++) {
            char key[32];
            snprintf(key, sizeof(key), "rtl433_rej_%s", rtl433_reject_name(k));
            kv_int(buf, LINEBUF, off, key, (long long)r->rej[k]);
        }
        kv_int(buf, LINEBUF, off, "rtl433_bad_values", (long long)r->bad_values);
        kv_int(buf, LINEBUF, off, "rtl433_other_keys", (long long)r->other_keys);
        kv_int(buf, LINEBUF, off, "rtl433_evicted", (long long)r->evicted);
        kv_int(buf, LINEBUF, off, "rtl433_truncations", (long long)r->truncations);
        kv_int(buf, LINEBUF, off, "rtl433_rotations", (long long)r->rotations);
        kv_int(buf, LINEBUF, off, "rtl433_read_errors", (long long)r->read_errors);
        kv_str(buf, LINEBUF, off, "rtl433_err", r->err);
    }
}

void jsonl_sh_victron(char *buf, int *off, const sloth_state_t *s) {
    /* --victron (2026-11-15, additive; shipped under 1.8.0, carried by
     * 1.9.0, see docs/wiki/jsonl-schema.md "Versioning"): sloth-va's
     * file. ONLY with --victron, appended after the rtl433 block and
     * before the daemon / db_max_mb / jsonl_version tail, for the
     * reason that block gives. */
    if (s->victron.configured) {
        const victron_health_t *v = &s->victron;
        kv_str(buf, LINEBUF, off, "victron_state", victron_state_name(v->state));
        kv_str(buf, LINEBUF, off, "victron_src", v->src);
        kv_int(buf, LINEBUF, off, "victron_missing", v->missing);
        kv_int(buf, LINEBUF, off, "victron_last_read", (long long)v->last_read);
        kv_int(buf, LINEBUF, off, "victron_last_rec", (long long)v->last_rec);
        kv_int(buf, LINEBUF, off, "victron_devices", v->devices);
        kv_int(buf, LINEBUF, off, "victron_bytes", (long long)v->bytes);
        kv_int(buf, LINEBUF, off, "victron_lines", (long long)v->lines);
        kv_int(buf, LINEBUF, off, "victron_records", (long long)v->records);
        kv_int(buf, LINEBUF, off, "victron_bad_lines", (long long)v->bad_lines);
        for (int k = 0; k < VICTRON_REJ_COUNT; k++) {
            char key[32];
            snprintf(key, sizeof(key), "victron_rej_%s", victron_reject_name(k));
            kv_int(buf, LINEBUF, off, key, (long long)v->rej[k]);
        }
        kv_int(buf, LINEBUF, off, "victron_bad_values", (long long)v->bad_values);
        kv_int(buf, LINEBUF, off, "victron_other_keys", (long long)v->other_keys);
        kv_int(buf, LINEBUF, off, "victron_table_full", (long long)v->table_full);
        kv_int(buf, LINEBUF, off, "victron_truncations", (long long)v->truncations);
        kv_int(buf, LINEBUF, off, "victron_rotations", (long long)v->rotations);
        kv_int(buf, LINEBUF, off, "victron_read_errors", (long long)v->read_errors);
        kv_str(buf, LINEBUF, off, "victron_err", v->err);
    }
}

/* ── what sloth-rf writes ─────────────────────────────────── */

/* sloth-rf's sensor_health (#213): the blocks a daemon with no capture
 * has something to say in, and "daemon":"rf". The capture, monitor
 * radio, channel hop, capture scope, pcap export, Bluetooth and twin
 * blocks are not written at all - absent, not zero, because a zero
 * would read as "a capture that is down" on a host whose capture is
 * the other daemon's and may be perfectly well.
 *
 * Change-only like `sloth`'s, on the same kind of signature: states
 * and bands, never a figure that moves every tick. */
void jsonl_emit_sensor_health_rf(const sloth_state_t *s) {
    if (!any_sink() || !s) return;
    time_t now = sloth_wall();

    uint64_t evict_total = sh_evict_total();
    /* The one sink this daemon can fail to write: it has no pcap or
     * handshake export. */
    int jsonl_fail = jsonl_write_failures();
    const int                socket_clients = data_socket_client_count();
    const unsigned long long socket_refused = data_socket_peer_refused_total();
    const int db_cap_mb = db_is_open() ? db_max_mb() : -1;

    struct {
        uint64_t evicted;
        int      storage_fail;
        int      tuned;
        int      socket_clients, socket_refused_any;
        jsonl_sh_gnss_sig_t gnss;
        jsonl_sh_rf_sig_t   rf;
        int      db_max_mb;
    } sig;
    memset(&sig, 0, sizeof(sig));
    sig.evicted            = sh_evict_total_tables();
    sig.storage_fail       = jsonl_fail;
    sig.tuned              = tune_non_default();
    sig.socket_clients     = socket_clients;
    sig.socket_refused_any = socket_refused > 0;
    jsonl_sh_gnss_sig(s, &sig.gnss);
    jsonl_sh_rf_sig(s, &sig.rf);
    sig.db_max_mb          = db_cap_mb;

    static const char health_key[] = "sensor";
    if (!jsonl_changed(JD_SENSOR_HEALTH, health_key, sizeof(health_key) - 1,
                       fnv1a(&sig, sizeof(sig), FNV64_OFFSET), now))
        return;

    char buf[LINEBUF]; int off = 0;
    start_obj(buf, LINEBUF, &off, "sensor_health", now);
    jsonl_sh_evictions(buf, &off, evict_total, jsonl_fail);
    kv_int(buf, LINEBUF, &off, "storage_jsonl_failures", jsonl_fail);
    {
        /* This daemon links no libpcap, so there is none loaded to
         * name: "none", the word a WITH_PCAP=0 build of `sloth` uses. */
        char lbuf[192];
        libver_format_libs(lbuf, sizeof(lbuf), "none");
        jsonl_sh_process(buf, &off, socket_refused, socket_clients, lbuf);
    }
    jsonl_sh_gps(buf, &off, s);
    jsonl_sh_adsb(buf, &off, s);
    jsonl_sh_aprs(buf, &off, s);
    jsonl_sh_aprs_region(buf, &off, s);
    jsonl_sh_rtl433(buf, &off, s);
    jsonl_sh_victron(buf, &off, s);
    jsonl_sh_tail(buf, &off, "rf", db_cap_mb);
    end_obj(buf, LINEBUF, &off);
    emit_line(buf);
}

/* The records sloth-rf writes each tick, in the order `sloth` writes
 * the same ones (jsonl_emit_state_snapshots(), src/jsonl.c): the sensor
 * registry, the receiver, the three decoders, sloth-va's file, the
 * host's status and its source rows, then the daemon's self-report last. */
void jsonl_emit_state_rf(sloth_state_t *s) {
    if (!any_sink() || !s) return;
    jsonl_emit_sensors(s);
    jsonl_emit_gnss(s);
    jsonl_emit_adsb(s);
    jsonl_emit_aprs(s);
    jsonl_emit_rtl433(s);
    jsonl_emit_victron(s);
    sys_status_emit(s);
    cov_live_emit();
    q_emit(s);
    jsonl_emit_sensor_health_rf(s);
}
