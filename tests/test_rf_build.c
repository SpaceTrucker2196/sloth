#include <dirent.h>
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
    ASSERT_GE(names, 20);
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
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        if (!strstr(defs, want[i]))
            fprintf(stderr, "    RF_FORBID_DEFS lost%s\n", want[i]);
        ASSERT(strstr(defs, want[i]) != NULL);
    }
    ASSERT(strstr(imps, " pcap_[a-z_]+ ") != NULL);
    ASSERT(strstr(imps, " getnameinfo ") != NULL);
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
    RUN_TEST(test_the_lists_cover_each_module);
    RUN_TEST(test_recipe_links_and_gates_sloth_rf);
    RUN_TEST(test_shared_files_include_no_capture_header);
}
