#include <dirent.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"

/*
 * sloth-rf's build (#213): the Makefile's gate on the linked binary,
 * held from the source side.
 *
 * check_rf_no_capture runs `nm` on sloth-rf and refuses a list of
 * symbols (MISSION.md section 2, ADR 0010). It is the authority: what
 * the linker did is what matters. Two things it cannot say for itself
 * are held here, where `make test` reaches them:
 *
 *   - a name on the list that no longer exists guards nothing, so every
 *     forbidden definition is held to being defined in the tree;
 *   - the files sloth-rf links by design must not include a capture
 *     header, so a new include is named by file and line in the suite
 *     before it is a link error in a build.
 *
 * Read as text from the tree, like tests/test_build_recipe.c.
 */

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = n >= 0 ? malloc((size_t)n + 1) : NULL;
    if (b) {
        size_t got = fread(b, 1, (size_t)n, f);
        b[got] = '\0';
    }
    fclose(f);
    return b;
}

/* The value of a Makefile variable, continuation lines joined, into
 * out. 0 when it is not there. */
static int mk_var(const char *mk, const char *name, char *out, size_t sz) {
    char key[64];
    snprintf(key, sizeof(key), "\n%s", name);
    const char *p = mk;
    out[0] = '\0';
    while ((p = strstr(p, key)) != NULL) {
        p += strlen(key);
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '=' || (*p == ':' && p[1] == '=')) break;
    }
    if (!p) return 0;
    p = strchr(p, '=') + 1;
    size_t off = 0;
    for (;;) {
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        int cont = len > 0 && p[len - 1] == '\\';
        if (cont) len--;
        if (off + len + 2 >= sz) return 0;
        memcpy(out + off, p, len);
        off += len;
        out[off++] = ' ';
        out[off] = '\0';
        if (!cont || !e) break;
        p = e + 1;
    }
    return 1;
}

/* Is `name` defined as a function or object at file scope in `src`?
 * A line that starts in column 0, holds the name as a whole word
 * followed by `(` or ` =`, and is not a declaration (no `;`). */
static int defines(const char *src, const char *name) {
    size_t nl = strlen(name);
    for (const char *p = src; (p = strstr(p, name)) != NULL; p += nl) {
        char before = p == src ? '\n' : p[-1];
        char after = p[nl];
        if (!(before == ' ' || before == '*')) continue;
        if (!(after == '(' || after == ' ')) continue;
        const char *ls = p;
        while (ls > src && ls[-1] != '\n') ls--;
        if (*ls == ' ' || *ls == '\t' || *ls == '#' || *ls == '/' || *ls == '*')
            continue;
        const char *le = strchr(p, '\n');
        size_t len = le ? (size_t)(le - ls) : strlen(ls);
        if (memchr(ls, ';', len)) continue;
        if (after == ' ' && !strstr(p + nl, "= {")) continue;
        return 1;
    }
    return 0;
}

static int defined_under(const char *dir, const char *name) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    int hit = 0;
    struct dirent *e;
    while (!hit && (e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if (n < 3 || strcmp(e->d_name + n - 2, ".c") != 0) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        char *src = slurp(path);
        if (src && defines(src, name)) hit = 1;
        free(src);
    }
    closedir(d);
    return hit;
}

/* Every name check_rf_no_capture refuses is a definition in the tree.
 * A rename would otherwise leave the gate refusing a symbol nothing
 * can link, green for the wrong reason. (Seen red with capture_open
 * misspelt capture_opne in RF_FORBID_DEFS.) */
static void test_every_forbidden_definition_exists(void) {
    char *mk = slurp("Makefile");
    ASSERT(mk != NULL);
    if (!mk) return;
    static char list[2048];
    ASSERT(mk_var(mk, "RF_FORBID_DEFS", list, sizeof(list)));
    static const char *const dirs[] = {
        "src", "src/capture", "src/platform", "src/alerts", "src/views"
    };
    int names = 0;
    for (char *tok = strtok(list, " \t"); tok; tok = strtok(NULL, " \t")) {
        names++;
        int hit = 0;
        for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]) && !hit; i++)
            hit = defined_under(dirs[i], tok);
        if (!hit)
            fprintf(stderr, "    RF_FORBID_DEFS names %s, which nothing under "
                            "src/ defines\n", tok);
        ASSERT(hit);
    }
    /* Each module the gate is for has a name on it. */
    ASSERT_GE(names, 40);
    free(mk);
}

/* The family patterns beside the names (review of #213). A pattern
 * cannot be held to "is defined", so each is held to a witness: a
 * definition in the tree today that it matches whole, and that no name
 * on the first list would have caught for it. A pattern with no
 * witness here fails the count, so adding one means naming what it is
 * for; a witness that is renamed away fails by name.
 * (Seen red with linux_[a-z0-9_]+ dropped from the Makefile's list,
 * and with the witness linux_neigh_parse misspelt.) */
static void test_every_forbidden_pattern_has_a_witness(void) {
    char *mk = slurp("Makefile");
    ASSERT(mk != NULL);
    if (!mk) return;
    static char pats[1024];
    ASSERT(mk_var(mk, "RF_FORBID_DEF_PATTERNS", pats, sizeof(pats)));
    static const struct { const char *pat, *witness; } w[] = {
        { "linux_[a-z0-9_]+",          "linux_neigh_parse" },
        { "dot11_[a-z0-9_]+",          "dot11_ie_ssid" },
        { "[a-z0-9_]+_observe_frame",  "frag_observe_frame" },
        { "[a-z0-9_]+_parse_frame",    "assoc_request_parse_frame" },
        { "bt_[a-z0-9_]+",             "bt_stream_feed" },
        { "ble_[a-z0-9_]+",            "ble_mon_ingest" },
        { "btle_[a-z0-9_]+",           "btle_ll_parse" },
        { "evidence_[a-z0-9_]+",       "evidence_ring_init" },
        { "eapol_[a-z0-9_]+",          "eapol_observe_frame" },
        { "discovery_[a-z0-9_]+",      "discovery_unpublish" },
        { "view_[a-z0-9_]+",           "view_mdns_draw" },
        { "tui_[a-z0-9_]+",            "tui_init" },
    };
    static const char *const dirs[] = {
        "src", "src/capture", "src/platform", "src/alerts", "src/views"
    };
    const size_t nw = sizeof(w) / sizeof(w[0]);
    for (size_t i = 0; i < nw; i++) {
        char want[96], re[96];
        snprintf(want, sizeof(want), " %s ", w[i].pat);
        if (!strstr(pats, want))
            fprintf(stderr, "    RF_FORBID_DEF_PATTERNS lost%s\n", want);
        ASSERT(strstr(pats, want) != NULL);
        /* Anchored as the Makefile anchors the whole alternation. */
        snprintf(re, sizeof(re), "^(%s)$", w[i].pat);
        regex_t rx;
        ASSERT_EQ(regcomp(&rx, re, REG_EXTENDED | REG_NOSUB), 0);
        ASSERT_EQ(regexec(&rx, w[i].witness, 0, NULL, 0), 0);
        /* And it is a family, not a name: what sloth-rf does link
         * stays outside it. */
        ASSERT(regexec(&rx, "wifi_downgrade_update", 0, NULL, 0) != 0);
        ASSERT(regexec(&rx, "capture_run_flag_get", 0, NULL, 0) != 0);
        ASSERT(regexec(&rx, "adsb_reader_run", 0, NULL, 0) != 0);
        regfree(&rx);
        int hit = 0;
        for (size_t d = 0; d < sizeof(dirs) / sizeof(dirs[0]) && !hit; d++)
            hit = defined_under(dirs[d], w[i].witness);
        if (!hit)
            fprintf(stderr, "    the witness %s for %s is defined nowhere "
                            "under src/\n", w[i].witness, w[i].pat);
        ASSERT(hit);
    }
    int listed = 0;
    for (char *tok = strtok(pats, " \t"); tok; tok = strtok(NULL, " \t"))
        listed++;
    ASSERT_EQ(listed, (int)nw);
    /* Both lists reach the expression the recipe matches against. */
    ASSERT(strstr(mk, "$(strip $(RF_FORBID_DEFS) $(RF_FORBID_DEF_PATTERNS))") != NULL);
    free(mk);
}

/* The list names what it claims to: the IP capture, the 802.11 monitor
 * and a frame decoder, both Bluetooth sources, the replay, the pcap
 * exporters, the nl80211 backend, the resolver and the terminal; and
 * the import list names libpcap and the resolver's call. */
static void test_the_lists_cover_each_module(void) {
    char *mk = slurp("Makefile");
    ASSERT(mk != NULL);
    if (!mk) return;
    static char defs[2048], imps[512];
    ASSERT(mk_var(mk, "RF_FORBID_DEFS", defs, sizeof(defs)));
    ASSERT(mk_var(mk, "RF_FORBID_IMPORTS", imps, sizeof(imps)));
    static const char *const want[] = {
        " capture_open ", " capture_run ", " probe_open ", " probe_run ",
        " dot11_frame_decode ", " radiotap_parse ", " bt_monitor_open ",
        " bt_capture_run ", " ble_mon_ingest ", " replay_run ",
        " alert_pcap_dump ", " evidence_export_pcap_unique ",
        " linux_wifi_scan ", " linux_wifi_set_channel ", " dns_resolve ",
        " tui_init ",
        /* The members that define none of the names above and need
         * none of them (review of #213): the INET_DIAG and rtnetlink
         * readers, the lease, pid and self-MAC readers, the mDNS
         * advertisement, and the frame decoders in files of their own. */
        " linux_tcpdiag_fill ", " linux_neigh6_fill ", " linux_get_dhcp ",
        " linux_get_self_macs ", " resolve_pids ", " discovery_publish ",
        " action_observe_frame ", " frag_observe_frame ",
        " ctrl_observe_frame ", " karma_observe_frame ",
        " assoc_request_parse_frame ", " pm_forge_observe_frame ",
        " mle_bss_observe_frame ", " dot11_ie_find ", " dot11_data_addrs ",
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        if (!strstr(defs, want[i]))
            fprintf(stderr, "    RF_FORBID_DEFS lost%s\n", want[i]);
        ASSERT(strstr(defs, want[i]) != NULL);
    }
    ASSERT(strstr(imps, " pcap_[a-z_]+ ") != NULL);
    ASSERT(strstr(imps, " getnameinfo ") != NULL);
    /* The forward resolver, and the calls a netlink or raw-socket
     * module is made of; sloth-rf's own sockets use none of them. */
    static const char *const want_imp[] = {
        " getaddrinfo ", " gethostbyname[0-9a-z_]* ", " sendto ",
        " sendmsg ", " recv ", " recvfrom ", " recvmsg ", " ioctl ",
        " if_nametoindex ", " initscr ", " newterm ",
    };
    for (size_t i = 0; i < sizeof(want_imp) / sizeof(want_imp[0]); i++) {
        if (!strstr(imps, want_imp[i]))
            fprintf(stderr, "    RF_FORBID_IMPORTS lost%s\n", want_imp[i]);
        ASSERT(strstr(imps, want_imp[i]) != NULL);
    }
    /* send() is not on it: gpsd's ?WATCH and the data socket's
     * writes are this daemon's, announced. */
    ASSERT(strstr(imps, " send ") == NULL);
    free(mk);
}

/* The recipe: sloth-rf is linked from its own three objects and the
 * core archive, with no libpcap or ncurses on the line, and both `nm`
 * gates run on it; `make` builds it and `make clean` removes it. */
static void test_recipe_links_and_gates_sloth_rf(void) {
    char *mk = slurp("Makefile");
    ASSERT(mk != NULL);
    if (!mk) return;
    static char v[1024];
    ASSERT(mk_var(mk, "RF_APP_SRCS", v, sizeof(v)));
    ASSERT_STR(v, " src/rf/main.c src/rf/rf_args.c src/rf/platform_rf.c ");
    ASSERT(mk_var(mk, "RF_LDFLAGS", v, sizeof(v)));
    ASSERT(strstr(v, "$(filter-out -lpcap -lncursesw -lncurses,$(LDFLAGS))") != NULL);

    const char *rule = strstr(mk, "\n$(RF_TARGET): $(RF_APP_OBJS) $(CORE_LIB) $(RF_LINK_STAMP)\n");
    ASSERT(rule != NULL);
    if (rule) {
        const char *end = strstr(rule + 1, "\n\n");
        ASSERT(end != NULL);
        const char *hci = strstr(rule, "\t$(check_no_hci_builder)\n");
        const char *cap = strstr(rule, "\t$(check_rf_no_capture)\n");
        const char *lnk = strstr(rule, "$(RF_LDFLAGS)\n");
        ASSERT(hci != NULL && end && hci < end);
        ASSERT(cap != NULL && end && cap < end);
        ASSERT(lnk != NULL && end && lnk < end);
        /* The app objects are not $(LDFLAGS)-linked by mistake. */
        ASSERT(strstr(rule, " $(LDFLAGS)\n") == NULL ||
               strstr(rule, " $(LDFLAGS)\n") > end);
    }
    /* The HCI-builder gate's include scan reads sloth-rf's own three
     * sources too, not only sloth's and the archive's. */
    ASSERT(strstr(mk, "$(APP_SRCS) $(RF_APP_SRCS) $(CORE_SRCS) /dev/null") != NULL);
    ASSERT(strstr(mk, "\nall: $(RF_TARGET)\n") != NULL);
    ASSERT(strstr(mk, "\n\trm -f sloth-rf\n") != NULL);
    /* A failed gate removes the binary, so the next make cannot call it
     * up to date. */
    const char *def = strstr(mk, "\ndefine check_rf_no_capture\n");
    ASSERT(def != NULL);
    if (def) {
        const char *end = strstr(def, "\nendef\n");
        ASSERT(end != NULL);
        int removals = 0;
        for (const char *p = def; end && (p = strstr(p, "rm -f $@; exit 1;")) != NULL && p < end; p++)
            removals++;
        ASSERT_EQ(removals, 3);
    }
    free(mk);
}

/* ── sloth-wifi's gate, the mirror (#216) ─────────────────────────────
 *
 * check_wifi_no_rf refuses the decoders, their records, their rules and
 * sloth-rf's own tables in the Wi-Fi daemon. It is all patterns, so each
 * is held to a witness: a definition in the tree today that it matches
 * whole. A pattern with no witness fails the count; a witness renamed
 * away fails by name. And each is held to NOT matching what sloth-wifi
 * keeps and must go on linking: the receiver, its view, its poll
 * stages, its health block, and this daemon's own refusal of the six
 * flags.
 * (Seen red with adsb_[a-z0-9_]+ dropped from the Makefile's list, and
 * with the witness rule_gnss_jamming misspelt.) */
static void test_wifi_gate_patterns_have_witnesses(void) {
    char *mk = slurp("Makefile");
    ASSERT(mk != NULL);
    if (!mk) return;
    static char pats[1024];
    ASSERT(mk_var(mk, "WIFI_FORBID_DEF_PATTERNS", pats, sizeof(pats)));
    static const struct { const char *pat, *witness; } w[] = {
        { "adsb_[a-z0-9_]+",          "adsb_health_poll" },
        { "aprs_[a-z0-9_]+",          "aprs_health_poll" },
        { "rtl433_[a-z0-9_]+",        "rtl433_health_poll" },
        { "victron_[a-z0-9_]+",       "victron_health_poll" },
        { "rule_adsb_[a-z0-9_]+",     "rule_adsb_emergency" },
        { "rule_gnss_[a-z0-9_]+",     "rule_gnss_jamming" },
        { "rules_adsb_[a-z0-9_]+",    "rules_adsb_forget" },
        { "rules_gnss_[a-z0-9_]+",    "rules_gnss_forget" },
        { "jsonl_emit_(gnss|adsb|aprs|rtl433|victron)", "jsonl_emit_gnss" },
        { "jsonl_sh_(adsb|aprs|rtl433|victron|rf)[a-z0-9_]*", "jsonl_sh_aprs_region" },
        { "jsonl_emit_state_rf",      "jsonl_emit_state_rf" },
        { "jsonl_emit_sensor_health_rf", "jsonl_emit_sensor_health_rf" },
        { "poll_st_[a-z0-9_]+_rf",    "poll_st_health_rf" },
        { "g_poll_rf",                "g_poll_rf" },
        { "g_alert_table_rf",         "g_alert_table_rf" },
        { "rf_flags_[a-z0-9_]+",      "rf_flags_check" },
        { "rf_flag_[a-z0-9_]+",       "rf_flag_aprs_freq" },
        { "rf_side_install",          "rf_side_install" },
        { "rf_trim_[a-z0-9_]+",       "rf_trim_apply" },
        { "sys_status_rf_fill",       "sys_status_rf_fill" },
    };
    static const char *const dirs[] = {
        "src", "src/capture", "src/platform", "src/alerts", "src/views"
    };
    /* What sloth-wifi keeps: none of it is on the list. */
    static const char *const kept[] = {
        "gps_reader_run", "gps_health_poll", "gps_location_current",
        "postrack_tick", "view_gnss_draw", "poll_st_health_gnss",
        "poll_st_sensors_gnss", "poll_st_positions", "jsonl_sh_gps",
        "jsonl_sh_gnss_sig", "gnss_flags_check", "rf_moved_flag",
        "rf_moved_message", "rule_sensor_source_down", "sys_status_capture_fill",
        "g_poll_wifi", "g_alert_table_wifi", "jsonl_emit_sensor_health",
        "jsonl_emit_state_snapshots",
    };
    const size_t nw = sizeof(w) / sizeof(w[0]);
    for (size_t i = 0; i < nw; i++) {
        char want[96], re[128];
        snprintf(want, sizeof(want), " %s ", w[i].pat);
        if (!strstr(pats, want))
            fprintf(stderr, "    WIFI_FORBID_DEF_PATTERNS lost%s\n", want);
        ASSERT(strstr(pats, want) != NULL);
        snprintf(re, sizeof(re), "^(%s)$", w[i].pat);
        regex_t rx;
        ASSERT_EQ(regcomp(&rx, re, REG_EXTENDED | REG_NOSUB), 0);
        ASSERT_EQ(regexec(&rx, w[i].witness, 0, NULL, 0), 0);
        for (size_t k = 0; k < sizeof(kept) / sizeof(kept[0]); k++) {
            if (regexec(&rx, kept[k], 0, NULL, 0) == 0)
                fprintf(stderr, "    %s matches %s, which sloth-wifi keeps\n",
                        w[i].pat, kept[k]);
            ASSERT(regexec(&rx, kept[k], 0, NULL, 0) != 0);
        }
        regfree(&rx);
        int hit = 0;
        for (size_t d = 0; d < sizeof(dirs) / sizeof(dirs[0]) && !hit; d++)
            hit = defined_under(dirs[d], w[i].witness);
        if (!hit)
            fprintf(stderr, "    the witness %s for %s is defined nowhere "
                            "under src/\n", w[i].witness, w[i].pat);
        ASSERT(hit);
    }
    /* What it keeps is there to be kept. */
    for (size_t k = 0; k < sizeof(kept) / sizeof(kept[0]); k++) {
        int hit = 0;
        for (size_t d = 0; d < sizeof(dirs) / sizeof(dirs[0]) && !hit; d++)
            hit = defined_under(dirs[d], kept[k]);
        if (!hit) fprintf(stderr, "    %s is defined nowhere under src/\n", kept[k]);
        ASSERT(hit);
    }
    int listed = 0;
    for (char *tok = strtok(pats, " \t"); tok; tok = strtok(NULL, " \t"))
        listed++;
    ASSERT_EQ(listed, (int)nw);
    ASSERT(strstr(mk, "$(strip $(WIFI_FORBID_DEF_PATTERNS))") != NULL);
    free(mk);
}

/* The recipe: the Wi-Fi daemon is sloth-wifi, both `nm` gates run on
 * it, a failed one removes the binary, `sloth` is a symlink target of
 * `all` beside it, `make clean` removes both, and `make install` puts
 * the binary and the link in place. */
static void test_recipe_names_and_gates_sloth_wifi(void) {
    char *mk = slurp("Makefile");
    ASSERT(mk != NULL);
    if (!mk) return;
    static char v[256];
    ASSERT(mk_var(mk, "TARGET", v, sizeof(v)));
    ASSERT_STR(v, " sloth-wifi ");
    ASSERT(mk_var(mk, "TARGET_ALIAS", v, sizeof(v)));
    ASSERT_STR(v, " sloth ");
    const char *rule = strstr(mk, "\n$(TARGET): $(OBJS) $(LINK_STAMP)\n");
    ASSERT(rule != NULL);
    if (rule) {
        const char *end = strstr(rule + 1, "\n\n");
        const char *hci = strstr(rule, "\t$(check_no_hci_builder)\n");
        const char *rf  = strstr(rule, "\t$(check_wifi_no_rf)\n");
        ASSERT(end != NULL);
        ASSERT(hci != NULL && end && hci < end);
        ASSERT(rf != NULL && end && rf < end);
    }
    const char *def = strstr(mk, "\ndefine check_wifi_no_rf\n");
    ASSERT(def != NULL);
    if (def) {
        const char *end = strstr(def, "\nendef\n");
        ASSERT(end != NULL);
        int removals = 0;
        for (const char *p = def; end && (p = strstr(p, "rm -f $@; exit 1;")) != NULL && p < end; p++)
            removals++;
        ASSERT_EQ(removals, 2);
    }
    ASSERT(strstr(mk, "\nall: check-deps $(TARGET) $(TARGET_ALIAS)\n") != NULL);
    ASSERT(strstr(mk, "\n$(TARGET_ALIAS): FORCE_ALIAS | $(TARGET)\n") != NULL);
    ASSERT(strstr(mk, "\n\trm -f $(TARGET) $(TARGET_ALIAS) $(TEST_BIN)") != NULL);
    ASSERT(strstr(mk, "\n\tinstall -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)\n"
                      "\tln -sfn $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET_ALIAS)\n") != NULL);
    /* The RF group is not a second link list: it is in the archive, and
     * the gate is what keeps it out of this binary. */
    ASSERT(strstr(mk, "\nCORE_COMMON_SRCS = $(CORE_BASE_SRCS) $(GNSS_SRCS) $(RF_SRCS)\n") != NULL);
    free(mk);
}

/* Does `path` have an #include of `hdr`? The line number, or 0. */
static int includes(const char *path, const char *hdr) {
    char *src = slurp(path);
    if (!src) return -1;
    int line = 1, at = 0;
    for (const char *p = src; *p && !at; ) {
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        if (len > 8 && strncmp(p, "#include", 8) == 0) {
            char buf[256];
            snprintf(buf, sizeof(buf), "%.*s", (int)(len < 255 ? len : 255), p);
            if (strstr(buf, hdr)) at = line;
        }
        if (!e) break;
        p = e + 1;
        line++;
    }
    free(src);
    return at;
}

/* The files sloth-rf is linked from by design include no capture
 * header: not the IP capture or the monitor's, not a Bluetooth
 * source's, not the resolver's, the pcap exporters', the handshake
 * log's, the terminal's or libpcap's own. An include is not a link,
 * but a call cannot be written without one, so this names the file
 * and line in `make test` before `make` fails at the gate.
 *
 * src/alerts/engine.c is on the list with one exemption it states at
 * the include: evidence_export.h, for the EVX_REFUSED constant only.
 *
 * (Seen red with #include "dns.h" put back in src/sensor_health.c.) */
static void test_shared_files_include_no_capture_header(void) {
    static const char *const files[] = {
        "src/rf/main.c", "src/rf/rf_args.c", "src/rf/platform_rf.c",
        "src/poll_core.c", "src/poll_gnss.c", "src/poll_rf.c",
        "src/jsonl_core.c", "src/jsonl_rf.c", "src/sys_status.c",
        "src/sensor_health.c", "src/libver.c", "src/daemon_start.c",
        "src/gnss_flags.c", "src/rf_flags.c", "src/alerts/engine.c",
        "src/alerts/rules_table_rf.c", "src/alerts/rules_sensor.c",
        "src/alerts/rules_gnss.c", "src/alerts/rules_adsb.c",
        "src/db.c", "src/data_socket.c", "src/position_track.c",
    };
    static const char *const headers[] = {
        "capture/capture.h", "capture/probe.h", "capture/replay.h",
        "capture/bt_monitor.h", "capture/bt_capture.h", "capture_side.h",
        "\"dns.h\"", "alert_pcap.h", "eapol_log.h", "evidence_ring.h",
        "\"tui.h\"", "<pcap", "ble_hci.h", "bt_stream.h", "wifi_chanhop.h",
        "platform/linux", "\"discovery.h\"",
    };
    for (size_t f = 0; f < sizeof(files) / sizeof(files[0]); f++) {
        ASSERT_GE(includes(files[f], "#include"), 0);       /* it is there to read */
        for (size_t h = 0; h < sizeof(headers) / sizeof(headers[0]); h++) {
            int at = includes(files[f], headers[h]);
            if (at > 0)
                fprintf(stderr, "    %s:%d includes %s; sloth-rf links this "
                                "file and must not link that module\n",
                        files[f], at, headers[h]);
            ASSERT(at <= 0);
        }
    }
    /* The one exemption is spelled where it is taken. */
    char *eng = slurp("src/alerts/engine.c");
    ASSERT(eng != NULL);
    if (eng) {
        ASSERT(strstr(eng, "#include \"evidence_export.h\"   /* EVX_REFUSED only") != NULL);
        /* Its comments name the exporters; its code calls neither. */
        ASSERT(strstr(eng, "alert_pcap_enabled()") == NULL);
        ASSERT(strstr(eng, "evidence_export_enabled()") == NULL);
        ASSERT(strstr(eng, "x->ip_dump(") != NULL);
        free(eng);
    }
    /* And the scanner sees an include when there is one. */
    ASSERT_GT(includes("src/capture_side.c", "\"dns.h\""), 0);
    ASSERT_GT(includes("src/main.c", "capture/capture.h"), 0);
}

void run_rf_build_tests(void) {
    TEST_SUITE("sloth-rf: the build and its nm gate (#213)");
    RUN_TEST(test_every_forbidden_definition_exists);
    RUN_TEST(test_every_forbidden_pattern_has_a_witness);
    RUN_TEST(test_the_lists_cover_each_module);
    RUN_TEST(test_recipe_links_and_gates_sloth_rf);
    RUN_TEST(test_wifi_gate_patterns_have_witnesses);
    RUN_TEST(test_recipe_names_and_gates_sloth_wifi);
    RUN_TEST(test_shared_files_include_no_capture_header);
}
