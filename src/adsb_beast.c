#include <math.h>
#include <stdio.h>
#include <string.h>

#include "adsb.h"
#include "adsb_beast.h"

/* Contract and sources in adsb_beast.h. Pure: the table calls at the
 * bottom (adsb_feed_beast, adsb_note_*) are src/adsb.c's, under its
 * lock. */

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ── Mode S primitives ─────────────────────────────────────────── */

/* Bits first..last of msg, 1-based and inclusive, MSB first (the
 * numbering every Mode S table uses; readsb's getbits()). */
static unsigned bits(const uint8_t *msg, int first, int last) {
    unsigned v = 0;
    for (int i = first; i <= last; i++)
        v = (v << 1) | ((msg[(i - 1) / 8] >> (7 - (i - 1) % 8)) & 1u);
    return v;
}

uint32_t adsb_modes_crc(const uint8_t *msg, int nbits) {
    /* Long division by 0x1FFF409 ("The 1090 Megahertz Riddle", error
     * control; readsb crc.c MODES_GENERATOR_POLY 0xfff409 without the
     * x^24 term) over the data bits, then the 24 parity bits xored in:
     * the remainder of the whole frame. */
    uint32_t rem = 0;
    int nbytes = nbits / 8;
    for (int i = 0; i < nbytes - 3; i++) {
        rem ^= (uint32_t)msg[i] << 16;
        for (int k = 0; k < 8; k++)
            rem = (rem & 0x800000u) ? ((rem << 1) ^ 0xFFF409u) : (rem << 1);
        rem &= 0xFFFFFFu;
    }
    uint32_t parity = ((uint32_t)msg[nbytes - 3] << 16) |
                      ((uint32_t)msg[nbytes - 2] << 8) | msg[nbytes - 1];
    return (rem ^ parity) & 0xFFFFFFu;
}

int adsb_modes_ac13(unsigned ac13, int *alt_ft) {
    /* Bit 7 of the field (0x40) is M, bit 9 (0x10) is Q. With M = 0 and
     * Q = 1 the other 11 bits are N: altitude = 25 N - 1000 ft. */
    if (!ac13 || (ac13 & 0x40) || !(ac13 & 0x10)) return -1;
    int n = (int)(((ac13 & 0x1F80) >> 2) | ((ac13 & 0x20) >> 1) | (ac13 & 0x0F));
    *alt_ft = n * 25 - 1000;
    return 0;
}

int adsb_modes_ac12(unsigned ac12, int *alt_ft) {
    if (!ac12 || !(ac12 & 0x10)) return -1;
    int n = (int)(((ac12 & 0x0FE0) >> 1) | (ac12 & 0x0F));
    *alt_ft = n * 25 - 1000;
    return 0;
}

int adsb_modes_id13(unsigned id, char out[5]) {
    if (!id) return -1;
    /* C1 A1 C2 A2 C4 A4 X B1 D1 B2 D2 B4 D4, bit 12 first. */
    int a = ((id >> 11) & 1) | (((id >> 9) & 1) << 1) | (((id >> 7) & 1) << 2);
    int b = ((id >> 5) & 1) | (((id >> 3) & 1) << 1) | (((id >> 1) & 1) << 2);
    int c = ((id >> 12) & 1) | (((id >> 10) & 1) << 1) | (((id >> 8) & 1) << 2);
    int d = ((id >> 4) & 1) | (((id >> 2) & 1) << 1) | ((id & 1) << 2);
    out[0] = (char)('0' + a);
    out[1] = (char)('0' + b);
    out[2] = (char)('0' + c);
    out[3] = (char)('0' + d);
    out[4] = '\0';
    return 0;
}

/* ── CPR ───────────────────────────────────────────────────────── */

#define CPR_NZ    15
#define CPR_SCALE 131072.0   /* 2^17 */

int adsb_cpr_nl(double lat) {
    lat = fabs(lat);
    if (lat < 1e-9) return 59;
    if (fabs(lat - 87.0) < 1e-9) return 2;
    if (lat > 87.0) return 1;
    double c = cos(M_PI / 180.0 * lat);
    double a = 1.0 - (1.0 - cos(M_PI / (2.0 * CPR_NZ))) / (c * c);
    return (int)floor(2.0 * M_PI / acos(a));
}

static double pmod(double a, double b) {
    double r = fmod(a, b);
    return r < 0 ? r + b : r;
}

int adsb_cpr_global(int lat_e, int lon_e, int lat_o, int lon_o, int odd_newest,
                    double *lat, double *lon) {
    double ye = lat_e / CPR_SCALE, yo = lat_o / CPR_SCALE;
    double xe = lon_e / CPR_SCALE, xo = lon_o / CPR_SCALE;
    double dlat_e = 360.0 / (4 * CPR_NZ), dlat_o = 360.0 / (4 * CPR_NZ - 1);
    double j = floor(59.0 * ye - 60.0 * yo + 0.5);
    double late = dlat_e * (pmod(j, 60.0) + ye);
    double lato = dlat_o * (pmod(j, 59.0) + yo);
    if (late >= 270.0) late -= 360.0;
    if (lato >= 270.0) lato -= 360.0;
    if (late < -90.0 || late > 90.0 || lato < -90.0 || lato > 90.0) return -1;
    int nl = adsb_cpr_nl(late);
    if (nl != adsb_cpr_nl(lato)) return -1;
    double la = odd_newest ? lato : late;
    double m = floor(xe * (nl - 1) - xo * nl + 0.5);
    int n = odd_newest ? (nl - 1 > 1 ? nl - 1 : 1) : (nl > 1 ? nl : 1);
    double lo = (360.0 / n) * (pmod(m, n) + (odd_newest ? xo : xe));
    if (lo >= 180.0) lo -= 360.0;
    *lat = la;
    *lon = lo;
    return 0;
}

int adsb_cpr_local(double ref_lat, double ref_lon, int cpr_lat, int cpr_lon,
                   int odd, double *lat, double *lon) {
    double y = cpr_lat / CPR_SCALE, x = cpr_lon / CPR_SCALE;
    double dlat = 360.0 / (odd ? 4 * CPR_NZ - 1 : 4 * CPR_NZ);
    double j = floor(ref_lat / dlat) + floor(pmod(ref_lat, dlat) / dlat - y + 0.5);
    double la = dlat * (j + y);
    if (la < -90.0 || la > 90.0 || fabs(la - ref_lat) > dlat / 2) return -1;
    int nl = adsb_cpr_nl(la) - (odd ? 1 : 0);
    double dlon = 360.0 / (nl > 1 ? nl : 1);
    double m = floor(ref_lon / dlon) + floor(pmod(ref_lon, dlon) / dlon - x + 0.5);
    double lo = dlon * (m + x);
    if (lo >= 180.0) lo -= 360.0;
    if (lo < -180.0) lo += 360.0;
    if (fabs(lo - ref_lon) > dlon / 2 && fabs(lo - ref_lon) < 360.0 - dlon / 2)
        return -1;
    *lat = la;
    *lon = lo;
    return 0;
}

/* Great-circle distance, km (haversine, mean radius). */
static double dist_km(double la1, double lo1, double la2, double lo2) {
    double r = M_PI / 180.0;
    double dla = (la2 - la1) * r, dlo = (lo2 - lo1) * r;
    double h = sin(dla / 2) * sin(dla / 2) +
               cos(la1 * r) * cos(la2 * r) * sin(dlo / 2) * sin(dlo / 2);
    return 2.0 * 6371.0 * asin(sqrt(h > 1.0 ? 1.0 : h));
}

/* ── Tracks ────────────────────────────────────────────────────── */

void adsb_beast_init(adsb_beast_t *b) {
    if (b) memset(b, 0, sizeof(*b));
}

static adsb_beast_track_t *trk_find(adsb_beast_t *b, uint32_t addr, int non_icao) {
    for (int i = 0; i < ADSB_BEAST_TRACKS; i++) {
        adsb_beast_track_t *t = &b->trk[i];
        if (t->used && t->addr == addr && t->non_icao == non_icao) return t;
    }
    return NULL;
}

/* Find or take a slot, evicting the longest unheard. */
static adsb_beast_track_t *trk_get(adsb_beast_t *b, uint32_t addr, int non_icao,
                                   uint64_t mono_ms) {
    adsb_beast_track_t *t = trk_find(b, addr, non_icao), *old = NULL;
    if (!t) {
        for (int i = 0; i < ADSB_BEAST_TRACKS; i++) {
            adsb_beast_track_t *c = &b->trk[i];
            if (!c->used) { old = c; break; }
            if (!old || c->last_mono < old->last_mono) old = c;
        }
        t = old;
        memset(t, 0, sizeof(*t));
        t->used = 1;
        t->addr = addr;
        t->non_icao = (uint8_t)non_icao;
    }
    t->last_mono = mono_ms;
    return t;
}

static int confirmed(const adsb_beast_track_t *t, uint64_t mono_ms) {
    return t && t->confirmed_mono &&
           mono_ms >= t->confirmed_mono &&
           mono_ms - t->confirmed_mono <= ADSB_BEAST_CONFIRM_MS;
}

static void rssi_note(adsb_beast_track_t *t, uint8_t signal, adsb_aircraft_t *out) {
    if (signal) {
        double v = signal / 255.0;
        t->sig[t->sig_next] = v * v;
        t->sig_next = (uint8_t)((t->sig_next + 1) % 8);
        if (t->sig_n < 8) t->sig_n++;
    }
    if (!t->sig_n) return;
    double sum = 0;
    for (int i = 0; i < t->sig_n; i++) sum += t->sig[i];
    out->has_rssi = 1;
    out->rssi = 10.0 * log10(sum / t->sig_n + 1.125e-5);
}

/* ── ES decoders: me is the 56-bit ME field ────────────────────── */

static const char ais[] =
    "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?";

static void es_ident(const uint8_t *me, int tc, adsb_aircraft_t *o) {
    char cs[9] = { 0 };
    for (int i = 0; i < 8; i++) {
        char ch = ais[bits(me, 9 + 6 * i, 14 + 6 * i)];
        /* The Riddle's table: letters, digits, space; anything else is a
         * corrupt or unassigned code and the callsign is not taken. */
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == ' '))
            goto category;
        cs[i] = ch;
    }
    cs[8] = '\0';
    for (int i = 7; i >= 0 && cs[i] == ' '; i--) cs[i] = '\0';
    memcpy(o->flight, cs, sizeof(o->flight));
category:
    /* readsb: category = ((0x0E - TC) << 4) | CA, printed "%02X":
     * TC 4 is A, 3 B, 2 C, 1 D. */
    o->category[0] = (char)('A' + (4 - tc));
    o->category[1] = (char)('0' + bits(me, 6, 8));
    o->category[2] = '\0';
}

/* The altitude, and the CPR fields for position(). */
static void es_airborne(const uint8_t *me, int tc, adsb_aircraft_t *o,
                        int *cpr_odd, int *cpr_lat, int *cpr_lon) {
    int alt = 0;
    if (adsb_modes_ac12(bits(me, 9, 20), &alt) == 0) {
        if (tc >= 20) { o->has_alt_geom = 1; o->alt_geom = alt; }
        else          { o->has_alt_baro = 1; o->alt_baro = alt; }
    }
    *cpr_odd = (int)bits(me, 22, 22);
    *cpr_lat = (int)bits(me, 23, 39);
    *cpr_lon = (int)bits(me, 40, 56);
}

static void es_velocity(const uint8_t *me, adsb_aircraft_t *o) {
    unsigned st = bits(me, 6, 8);
    if (st < 1 || st > 4) return;
    if (st <= 2) {
        unsigned vew = bits(me, 15, 24), vns = bits(me, 26, 35);
        if (vew && vns) {
            int k = st == 2 ? 4 : 1;
            double vx = (double)(vew - 1) * k * (bits(me, 14, 14) ? -1 : 1);
            double vy = (double)(vns - 1) * k * (bits(me, 25, 25) ? -1 : 1);
            o->has_gs = 1;
            o->gs = sqrt(vx * vx + vy * vy);
            if (o->gs > 0) {
                double trk = atan2(vx, vy) * 180.0 / M_PI;
                if (trk < 0) trk += 360.0;
                o->has_track = 1;
                o->track = trk;
            }
        }
    }
    unsigned vr = bits(me, 38, 46);
    if (vr) {
        int rate = (int)(vr - 1) * (bits(me, 37, 37) ? -64 : 64);
        if (bits(me, 36, 36)) { o->has_baro_rate = 1; o->baro_rate = rate; }
        else                  { o->has_geom_rate = 1; o->geom_rate = rate; }
    }
}

static void es_status(const uint8_t *me, adsb_aircraft_t *o) {
    if (bits(me, 6, 8) != 1) return;
    /* readsb emergency_t: none, general, lifeguard, minfuel, nordo,
     * unlawful, downed, reserved - the ADSB_EMERG_* order. */
    o->emergency = (int8_t)(ADSB_EMERG_NONE + (int)bits(me, 9, 11));
    adsb_modes_id13(bits(me, 12, 24), o->squawk);
}

/* ── One frame ─────────────────────────────────────────────────── */

static void out_init(adsb_aircraft_t *o, uint32_t addr, int non_icao) {
    memset(o, 0, sizeof(*o));
    o->icao = addr;
    o->non_icao = (uint8_t)non_icao;
    o->emergency = ADSB_EMERG_ABSENT;
}

/* The position from this frame's CPR, or a refusal. */
static int position(adsb_beast_t *b, adsb_beast_track_t *t, int odd,
                    int cl, int cn, uint64_t mono_ms, adsb_aircraft_t *o) {
    t->cpr_valid[odd] = 1;
    t->cpr_lat[odd] = cl;
    t->cpr_lon[odd] = cn;
    t->cpr_mono[odd] = mono_ms;
    double la = 0, lo = 0;
    int ok = -1, tried = 0;
    int ref = t->has_ref && mono_ms >= t->ref_mono &&
              mono_ms - t->ref_mono <= ADSB_BEAST_REF_MS;
    if (t->cpr_valid[!odd] && mono_ms >= t->cpr_mono[!odd] &&
        mono_ms - t->cpr_mono[!odd] <= ADSB_BEAST_CPR_PAIR_MS) {
        tried = 1;
        ok = odd ? adsb_cpr_global(t->cpr_lat[0], t->cpr_lon[0], cl, cn, 1, &la, &lo)
                 : adsb_cpr_global(cl, cn, t->cpr_lat[1], t->cpr_lon[1], 0, &la, &lo);
    }
    if (ok != 0 && ref) {
        tried = 1;
        ok = adsb_cpr_local(t->ref_lat, t->ref_lon, cl, cn, odd, &la, &lo);
    }
    if (!tried) return 0;            /* no fresh pair, no reference: wait */
    if (ok != 0) {
        b->cpr_rejected++;
        return -1;
    }
    if (ref) {
        double el = (double)(mono_ms - t->ref_mono) / 1000.0;
        if (dist_km(t->ref_lat, t->ref_lon, la, lo) >
            ADSB_BEAST_MAX_KMS * el + ADSB_BEAST_SLACK_KM) {
            b->cpr_rejected++;
            return -1;
        }
    }
    t->has_ref = 1;
    t->ref_lat = la;
    t->ref_lon = lo;
    t->ref_mono = mono_ms;
    o->has_pos = 1;
    o->lat = la;
    o->lon = lo;
    return 0;
}

int adsb_beast_decode(adsb_beast_t *b, const uint8_t *msg, int len,
                      uint8_t signal, uint64_t ts, uint64_t mono_ms,
                      adsb_aircraft_t *o) {
    int df = (int)(msg[0] >> 3);
    if ((len == 7 && df >= 16) || (len == 14 && df < 16) || (len != 7 && len != 14)) {
        b->ignored++;
        return ADSB_BEAST_IGNORED;
    }
    uint32_t rem = adsb_modes_crc(msg, len * 8);
    adsb_beast_track_t *t;

    if (df == 11) {
        /* Parity/interrogator: the remainder's low 7 bits are the
         * interrogator code of the radar that asked (readsb: IID =
         * crc & 0x7f). Non-zero there is a reply to some radar, not an
         * error; only II = 0 (a squitter) vouches, as in readsb. */
        if (rem & 0xFFFF80u) { b->crc_bad++; return ADSB_BEAST_CRC; }
        if (rem) { b->ignored++; return ADSB_BEAST_IGNORED; }
        t = trk_get(b, bits(msg, 9, 32), 0, mono_ms);
        t->confirmed_mono = mono_ms ? mono_ms : 1;
        return ADSB_BEAST_CONFIRM;
    }

    if (df == 4 || df == 5 || df == 20 || df == 21) {
        /* Address/parity: the remainder is the address, right or wrong. */
        t = trk_find(b, rem, 0);
        if (!confirmed(t, mono_ms)) { b->ghosts++; return ADSB_BEAST_GHOST; }
        t->last_mono = mono_ms;
        out_init(o, rem, 0);
        if (!t->had_adsb) memcpy(o->type, "mode_s", 7);
        if (df == 4 || df == 20) {
            int alt = 0;
            if (adsb_modes_ac13(bits(msg, 20, 32), &alt) == 0) {
                o->has_alt_baro = 1;
                o->alt_baro = alt;
            }
        } else {
            adsb_modes_id13(bits(msg, 20, 32), o->squawk);
        }
        rssi_note(t, signal, o);
        return ADSB_BEAST_ROW;
    }

    if (df != 17 && df != 18) { b->ignored++; return ADSB_BEAST_IGNORED; }
    if (rem != 0) { b->crc_bad++; return ADSB_BEAST_CRC; }

    const uint8_t *me = msg + 4;
    int tc = (int)bits(me, 1, 5);
    uint32_t addr = bits(msg, 9, 32);
    const char *type = "adsb_icao";
    int non_icao = 0, check_imf = 0;
    if (df == 18) {
        switch (bits(msg, 6, 8)) {
        case 0: type = "adsb_icao_nt"; break;
        case 1: type = "adsb_other"; non_icao = 1; break;
        case 2: type = "tisb_icao"; check_imf = 1; break;
        case 5: type = "tisb_other"; non_icao = 1; break;
        case 6: type = "adsr_icao"; check_imf = 1; break;
        default: b->ignored++; return ADSB_BEAST_IGNORED;
        }
        if (check_imf) {
            /* The IMF bit sits where each type code puts it (readsb
             * setIMF() callers): velocity 9, airborne position 8,
             * status 56; identification has none. */
            int imf = 0;
            if (tc == 19) imf = (int)bits(me, 9, 9);
            else if ((tc >= 9 && tc <= 18) || (tc >= 20 && tc <= 22)) imf = (int)bits(me, 8, 8);
            else if (tc == 28) imf = (int)bits(me, 56, 56);
            if (imf) {
                non_icao = 1;
                type = df == 18 && bits(msg, 6, 8) == 2 ? "tisb_trackfile" : "adsr_other";
            }
        }
    }
    if (ts == ADSB_BEAST_MLAT_TS) type = "mlat";

    t = trk_get(b, addr, non_icao, mono_ms);
    if (df == 17) t->confirmed_mono = mono_ms ? mono_ms : 1;
    t->had_adsb = 1;
    out_init(o, addr, non_icao);
    snprintf(o->type, sizeof(o->type), "%s", type);
    int r = ADSB_BEAST_ROW;
    if (tc >= 1 && tc <= 4) {
        es_ident(me, tc, o);
    } else if (tc >= 5 && tc <= 8) {
        o->on_ground = 1;
    } else if ((tc >= 9 && tc <= 18) || (tc >= 20 && tc <= 22)) {
        int odd = 0, cl = 0, cn = 0;
        es_airborne(me, tc, o, &odd, &cl, &cn);
        if (position(b, t, odd, cl, cn, mono_ms, o) < 0) r = ADSB_BEAST_CPR_REJECT;
    } else if (tc == 19) {
        es_velocity(me, o);
    } else if (tc == 28) {
        es_status(me, o);
    }
    /* Other type codes (0, 23-27, 29-31) carry nothing the table keeps;
     * the frame still counts for the row: it was heard. */
    rssi_note(t, signal, o);
    return r;
}

/* ── The framer ────────────────────────────────────────────────── */

enum { F_HUNT = 0, F_TYPE, F_BODY, F_ESC };

static void frame_done(adsb_beast_t *b, int64_t wall_ms, uint64_t mono_ms) {
    b->frames++;
    if (b->type == '1') {
        b->modeac++;
        adsb_note_sbs_alive(wall_ms, mono_ms);
        return;
    }
    if (b->type != '2' && b->type != '3') {   /* 0xE3 receiver id, '5' */
        b->skipped++;
        adsb_note_sbs_alive(wall_ms, mono_ms);
        return;
    }
    uint64_t ts = 0;
    for (int i = 0; i < 6; i++) ts = (ts << 8) | b->body[i];
    int r = adsb_beast_decode(b, b->body + 7, b->type == '2' ? 7 : 14,
                              b->body[6], ts, mono_ms, &b->out);
    if (r == ADSB_BEAST_ROW || r == ADSB_BEAST_CPR_REJECT)
        adsb_feed_beast(&b->out, wall_ms, mono_ms);
    else if (r == ADSB_BEAST_CRC)
        adsb_note_bad_frame(wall_ms, mono_ms);
    else
        adsb_note_sbs_alive(wall_ms, mono_ms);
}

static void parse_error(adsb_beast_t *b, const char *why) {
    b->parse_errors++;
    adsb_note_parse_error(why);
}

/* A TYPE byte just after 0x1A. */
static void frame_start(adsb_beast_t *b, uint8_t ty) {
    int need;
    switch (ty) {
    case '1':  need = 6 + 1 + 2;  break;
    case '2':  need = 6 + 1 + 7;  break;
    case '3':  need = 6 + 1 + 14; break;
    case '5':  need = 21;         break;
    case 0xE3: need = 8;          break;
    case 0x1A:                    /* a doubled 0x1A seen while hunting */
        b->st = F_HUNT;
        return;
    default:
        parse_error(b, "Beast frame of unknown type");
        b->st = F_HUNT;
        return;
    }
    b->type = ty;
    b->need = need;
    b->got = 0;
    b->st = F_BODY;
}

void adsb_beast_feed(adsb_beast_t *b, const uint8_t *data, size_t n,
                     int64_t wall_ms, uint64_t mono_ms) {
    if (!b || !data) return;
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = data[i];
        switch (b->st) {
        case F_HUNT:
            if (ch == 0x1A) {
                if (b->garbage_run) parse_error(b, "Beast stream out of sync");
                b->garbage_run = 0;
                b->st = F_TYPE;
            } else {
                b->garbage_run = 1;
            }
            break;
        case F_TYPE:
            frame_start(b, ch);
            break;
        case F_BODY:
            if (ch == 0x1A) { b->st = F_ESC; break; }
            b->body[b->got++] = ch;
            if (b->got == b->need) {
                b->st = F_HUNT;
                frame_done(b, wall_ms, mono_ms);
            }
            break;
        case F_ESC:
            if (ch == 0x1A) {
                b->body[b->got++] = 0x1A;
                b->st = F_BODY;
                if (b->got == b->need) {
                    b->st = F_HUNT;
                    frame_done(b, wall_ms, mono_ms);
                }
            } else {
                /* A lone 0x1A: the frame was cut short and this is the
                 * next one's start (readBeast() resyncs the same way). */
                parse_error(b, "Beast frame cut short");
                frame_start(b, ch);
            }
            break;
        default:
            b->st = F_HUNT;
        }
    }
}
