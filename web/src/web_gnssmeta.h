/* Which satellite a GNSS signal is (2026-11-05): the identifier and the
 * vehicle behind a gpsd satellite row.
 *
 * The identifier is the RINEX one (RINEX 3.05 / 4.0 §3.5, "satellite
 * numbers"): a system letter (G GPS, R GLONASS, E Galileo, C BeiDou,
 * J QZSS, I NavIC, S SBAS) and two digits - the PRN for GPS, the slot
 * for GLONASS, the PRN within the system for the rest, PRN - 100 for
 * SBAS - so G05, R09, E11, C23, J02, S31. gpsd's svid is exactly that
 * number for every system but SBAS (gpsd_json(5): svid is the
 * system's own satellite number); without one, the NMEA PRN ranges
 * gpsd uses stand in where they are unambiguous.
 *
 * A PRN is a signal assignment, not a satellite: a vehicle is retired
 * and its PRN given to another. The vehicle is looked up, at the time
 * of the record, in the IGS satellite metadata compiled in at build
 * (web/data/gnss/SOURCE.md, web/tools/gnssmeta_gen.c): the SVN, the
 * COSPAR international designator, the satellite catalogue (NORAD)
 * number - the one identifier unique to one object for its life - the
 * block, the launch date, the name, and its orbital plane and slot then.
 * SBAS and IMES are not in that file: their rows carry the identifier
 * alone. */
#ifndef SLOTHWEB_GNSSMETA_H
#define SLOTHWEB_GNSSMETA_H

#include "web_json.h"

typedef struct {
    const char *svn, *cospar;
    long        satcat;
    const char *block, *name, *launched;
} web_gnss_veh_t;
typedef struct { int veh; char sys; int num; long long from, to; } web_gnss_asg_t;
typedef struct { int veh; long long from, to; const char *plane, *slot; } web_gnss_plane_t;

/* build/web/web_gnssmeta_table.c */
extern const char             web_gnssmeta_release[];
extern const web_gnss_veh_t   web_gnss_vehs[];
extern const int              web_gnss_vehs_n;
extern const web_gnss_asg_t   web_gnss_asgs[];
extern const int              web_gnss_asgs_n;
extern const web_gnss_plane_t web_gnss_planes[];
extern const int              web_gnss_planes_n;

/* The RINEX system letter for gpsd's gnssid, or 0 (IMES, unknown). */
char web_gnss_sys_letter(int gnssid);

/* The system's own satellite number: svid when present, else derived
 * from the NMEA PRN where gpsd's ranges make it unambiguous; -1 when
 * neither gives one. */
int  web_gnss_sat_number(int gnssid, int svid, int prn);

/* "G05" and the like into out (8 bytes); "" when there is none. */
void web_gnss_rinex_id(int gnssid, int svid, int prn, char out[8]);

/* The vehicle transmitting (gnssid, svid / prn) at unix time ts, or
 * NULL; *plane / *slot set from its plane row then ("" none). */
const web_gnss_veh_t *web_gnss_vehicle(int gnssid, int svid, int prn, long long ts,
                                       const char **plane, const char **slot);

/* `,"id":"G05","veh":{...}|null` appended to an open JSON object. */
void web_gnss_ident_json(web_jw_t *w, int gnssid, int svid, int prn, long long ts);

#endif /* SLOTHWEB_GNSSMETA_H */
