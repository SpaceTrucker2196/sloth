#ifdef PLATFORM_LINUX

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <dirent.h>

#include "ntop.h"
#include "platform/linux_dhcp.h"

/* ── ISC dhclient.leases parser ──────────────────────────
   Format (one block per lease, last lease for an IP wins):
     lease {
       fixed-address 192.168.1.100;
       option host-name "myhostname";
       expire 2 2026/05/20 10:30:00;
     }
   ──────────────────────────────────────────────────────── */

static time_t parse_isc_expire(const char *line) {
    /* "  expire <wday> YYYY/MM/DD HH:MM:SS;" */
    int wday, yr, mo, dy, hr, mn, sc;
    if (sscanf(line, " expire %d %d/%d/%d %d:%d:%d",
               &wday, &yr, &mo, &dy, &hr, &mn, &sc) != 7)
        return 0;
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year  = yr - 1900;
    tm.tm_mon   = mo - 1;
    tm.tm_mday  = dy;
    tm.tm_hour  = hr;
    tm.tm_min   = mn;
    tm.tm_sec   = sc;
    tm.tm_isdst = -1;
    time_t t = mktime(&tm);
    return t < 0 ? 0 : t;
}

static int parse_isc_leases(const char *path, dhcp_lease_t *out, int max, int n) {
    FILE *f = fopen(path, "r");
    if (!f) return n;

    char line[256];
    char cur_ip[46]       = "";
    char cur_host[64]     = "";
    time_t cur_expire     = 0;

    while (n < max && fgets(line, sizeof(line), f)) {
        if (strncmp(line, "lease {", 7) == 0) {
            cur_ip[0]    = '\0';
            cur_host[0]  = '\0';
            cur_expire   = 0;
            continue;
        }
        if (line[0] == '}') {
            if (cur_ip[0] != '\0') {
                /* update existing or append */
                int found = 0;
                for (int i = 0; i < n; i++) {
                    if (strcmp(out[i].ip, cur_ip) == 0) {
                        snprintf(out[i].hostname, sizeof(out[i].hostname),
                                 "%s", cur_host);
                        out[i].expire = cur_expire;
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    snprintf(out[n].ip,       sizeof(out[n].ip),       "%s", cur_ip);
                    snprintf(out[n].hostname,  sizeof(out[n].hostname), "%s", cur_host);
                    out[n].expire = cur_expire;
                    n++;
                }
            }
            continue;
        }

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (strncmp(p, "fixed-address ", 14) == 0) {
            char *s = p + 14;
            char *end = strchr(s, ';');
            if (end) *end = '\0';
            /* strip trailing whitespace */
            char *ws = s + strlen(s) - 1;
            while (ws >= s && (*ws == ' ' || *ws == '\r' || *ws == '\n')) *ws-- = '\0';
            snprintf(cur_ip, sizeof(cur_ip), "%s", s);

        } else if (strncmp(p, "option host-name ", 17) == 0) {
            char *s = p + 17;
            /* strip leading/trailing quotes and semicolon */
            if (*s == '"') s++;
            char *end = strpbrk(s, "\";");
            if (end) *end = '\0';
            snprintf(cur_host, sizeof(cur_host), "%s", s);

        } else if (strncmp(p, "expire ", 7) == 0) {
            cur_expire = parse_isc_expire(p);
        }
    }
    fclose(f);
    return n;
}

/* ── systemd-networkd lease parser ───────────────────────
   Files in /run/systemd/netif/leases/<ifindex>
   KEY=VALUE format, one lease per file.
   ──────────────────────────────────────────────────────── */

static int parse_systemd_leases(const char *dir, dhcp_lease_t *out, int max, int n) {
    DIR *d = opendir(dir);
    if (!d) return n;

    struct dirent *de;
    while (n < max && (de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        char line[256];
        char ip[46]       = "";
        char hostname[64] = "";

        while (fgets(line, sizeof(line), f)) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            char *cr = strchr(line, '\r');
            if (cr) *cr = '\0';

            if (strncmp(line, "ADDRESS=", 8) == 0)
                snprintf(ip, sizeof(ip), "%s", line + 8);
            else if (strncmp(line, "HOSTNAME=", 9) == 0)
                snprintf(hostname, sizeof(hostname), "%s", line + 9);
        }
        fclose(f);

        if (ip[0] == '\0' || hostname[0] == '\0') continue;

        int found = 0;
        for (int i = 0; i < n; i++) {
            if (strcmp(out[i].ip, ip) == 0) { found = 1; break; }
        }
        if (!found) {
            snprintf(out[n].ip,       sizeof(out[n].ip),       "%s", ip);
            snprintf(out[n].hostname,  sizeof(out[n].hostname), "%s", hostname);
            out[n].expire = 0;  /* no reliable absolute expiry from LIFETIME= alone */
            n++;
        }
    }
    closedir(d);
    return n;
}

/* ── Public entry point ───────────────────────────────── */

int linux_get_dhcp(dhcp_lease_t *out, int max) {
    int n = 0;
    n = parse_isc_leases("/var/lib/dhcp/dhclient.leases",    out, max, n);
    n = parse_isc_leases("/var/lib/dhclient/dhclient.leases", out, max, n);
    n = parse_systemd_leases("/run/systemd/netif/leases",    out, max, n);
    return n;
}

#endif /* PLATFORM_LINUX */
