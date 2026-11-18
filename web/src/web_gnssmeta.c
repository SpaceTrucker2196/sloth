#include "web_gnssmeta.h"

#include <stdio.h>
#include <string.h>

char web_gnss_sys_letter(int gnssid) {
    switch (gnssid) {
    case 0: return 'G';
    case 1: return 'S';
    case 2: return 'E';
    case 3: return 'C';
    case 5: return 'J';
    case 6: return 'R';
    case 7: return 'I';
    default: return 0;
    }
}

int web_gnss_sat_number(int gnssid, int svid, int prn) {
    if (svid > 0) {
        /* gpsd's SBAS svid is the PRN (120..158); RINEX numbers it
         * PRN - 100. */
        if (gnssid == 1) return svid >= 100 ? svid - 100 : -1;
        return svid;
    }
    /* No svid (an NMEA-only gpsd): the NMEA 4.10 / gpsd PRN ranges,
     * only where one range is one system. */
    switch (gnssid) {
    case 0: return prn >= 1 && prn <= 32 ? prn : -1;
    case 1: return prn >= 120 && prn <= 158 ? prn - 100
                 : prn >= 33 && prn <= 64 ? prn + 87 - 100 : -1;
    case 5: return prn >= 193 && prn <= 202 ? prn - 192 : -1;
    case 6: return prn >= 65 && prn <= 96 ? prn - 64 : -1;
    default: return -1;
    }
}

void web_gnss_rinex_id(int gnssid, int svid, int prn, char out[8]) {
    char sys = web_gnss_sys_letter(gnssid);
    int n = web_gnss_sat_number(gnssid, svid, prn);
    out[0] = '\0';
    if (!sys || n < 1 || n > 99) return;
    snprintf(out, 8, "%c%02d", sys, n);
}

const web_gnss_veh_t *web_gnss_vehicle(int gnssid, int svid, int prn, long long ts,
                                       const char **plane, const char **slot) {
    if (plane) *plane = "";
    if (slot) *slot = "";
    char sys = web_gnss_sys_letter(gnssid);
    int n = web_gnss_sat_number(gnssid, svid, prn);
    if (!sys || sys == 'S' || n < 1) return NULL;
    for (int i = 0; i < web_gnss_asgs_n; i++) {
        const web_gnss_asg_t *a = &web_gnss_asgs[i];
        if (a->sys != sys || a->num != n || ts < a->from || ts >= a->to) continue;
        for (int j = 0; j < web_gnss_planes_n; j++) {
            const web_gnss_plane_t *p = &web_gnss_planes[j];
            if (p->veh == a->veh && ts >= p->from && ts < p->to) {
                if (plane) *plane = p->plane;
                if (slot) *slot = p->slot;
                break;
            }
        }
        return &web_gnss_vehs[a->veh];
    }
    return NULL;
}

void web_gnss_ident_json(web_jw_t *w, int gnssid, int svid, int prn, long long ts) {
    char id[8];
    web_gnss_rinex_id(gnssid, svid, prn, id);
    web_jw_raw(w, ",\"id\":"); web_jw_str(w, id);
    const char *pl, *sl;
    const web_gnss_veh_t *v = web_gnss_vehicle(gnssid, svid, prn, ts, &pl, &sl);
    web_jw_raw(w, ",\"veh\":");
    if (!v) { web_jw_raw(w, "null"); return; }
    web_jw_raw(w, "{\"svn\":"); web_jw_str(w, v->svn);
    web_jw_raw(w, ",\"norad\":"); web_jw_int(w, v->satcat);
    web_jw_raw(w, ",\"cospar\":"); web_jw_str(w, v->cospar);
    web_jw_raw(w, ",\"name\":"); web_jw_str(w, v->name);
    web_jw_raw(w, ",\"block\":"); web_jw_str(w, v->block);
    web_jw_raw(w, ",\"launched\":"); web_jw_str(w, v->launched);
    web_jw_raw(w, ",\"plane\":"); web_jw_str(w, pl);
    web_jw_raw(w, ",\"slot\":"); web_jw_str(w, sl);
    web_jw_raw(w, "}");
}
