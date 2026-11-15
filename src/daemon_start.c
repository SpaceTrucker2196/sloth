#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "daemon_start.h"
#include "data_socket.h"
#include "db.h"
#include "jsonl.h"
#include "tune.h"

/* src/daemon_start.h. Each body is the block src/main.c carried inline
 * before #213, moved with its comments and its text unchanged. */

int daemon_flag_tune(const char *arg) {
    if (!arg) {
        fprintf(stderr, "sloth: --tune needs name=value "
                        "(see --tune-list)\n");
        return 2;
    }
    char terr[160];
    if (tune_set(arg, terr, sizeof(terr)) != 0) {
        /* A mistyped knob exits rather than running with the
         * default the operator thought they had changed (#82). */
        fprintf(stderr, "sloth: --tune %s\n", terr);
        return 2;
    }
    return 0;
}

int daemon_flag_ticks(const char *arg, long *out) {
    /* Strict, like --tune: a batch job that ran forever because
     * "3x" parsed as 0 would hang the CI step it was written for. */
    char *end = NULL;
    long v = strtol(arg, &end, 10);
    if (!end || *end || end == arg || v < 1 || v > 1000000) {
        fprintf(stderr, "sloth: --ticks %s: want 1..1000000\n", arg);
        return 2;
    }
    *out = v;
    return 0;
}

int daemon_privdrop_plan(const char **user, int no_privdrop, int hop,
                         int allow_active, privdrop_req_t *req,
                         privdrop_plan_t *plan) {
    memset(req, 0, sizeof(*req));
    privdrop_probe(req);
    req->hop          = hop;
    req->allow_active = allow_active;
    req->no_privdrop  = no_privdrop;
    req->user_given   = *user != NULL;
    if (!*user) *user = PRIVDROP_DEFAULT_USER;
    {
        /* The reentrant form: nothing is threaded yet, but nothing here
         * should depend on that staying true. A lookup error (not just
         * "no such account") reads as unresolved, which refuses an
         * explicit --user and announces the default case. */
        static char pwbuf[16384];
        struct passwd pwd, *pw = NULL;
        if (getpwnam_r(*user, &pwd, pwbuf, sizeof(pwbuf), &pw) != 0)
            pw = NULL;
        if (pw) {
            req->user_resolved = 1;
            req->uid           = pw->pw_uid;
            req->gid           = pw->pw_gid;
        }
    }
    privdrop_resolve(req, plan);
    if (plan->exit_code != 0)
        fprintf(stderr, "sloth: %s (--user %s)\n", plan->reason, *user);
    return plan->exit_code;
}

int daemon_privdrop_apply(const privdrop_req_t *req,
                          const privdrop_plan_t *plan, const char *user) {
    char pd_err[160];
    if (privdrop_apply(plan, pd_err, sizeof(pd_err)) != 0) {
        fprintf(stderr, "sloth: privilege drop failed: %s — refusing "
                        "to run (--no-privdrop to keep privileges)\n",
                pd_err);
        return 2;
    }
    char pd_msg[320];
    privdrop_describe(req, plan, user, pd_msg, sizeof(pd_msg));
    if (pd_msg[0]) fprintf(stderr, "%s\n", pd_msg);
    return 0;
}

const char *daemon_data_socket_default(const char *dir, const char *spec,
                                       const char *runtime_dir) {
    char why[256];
    if (data_socket_default_dir_ok(dir, why, sizeof(why))) return spec;
    char msg[768];
    data_socket_default_refusal_at(spec, dir, runtime_dir, why, geteuid(),
                                   msg, sizeof(msg));
    fputs(msg, stderr);
    return NULL;
}

void daemon_strict_socket_refusal(const char *spec) {
    /* #84, owner ruling 2026-10-06. The loopback default
     * (tcp:127.0.0.1:8765) and a unix: path keep working, because
     * neither leaves the host and README has published bare
     * `--strict --data-socket` as usable.
     *
     * --data-socket-allow-remote does not override this: that flag
     * is how an operator says "expose this to the LAN", --strict is
     * how they say "not on this run", and a lock another flag can
     * override is not a lock. */
    fprintf(stderr,
            "sloth: --strict refuses a routable --data-socket (%s).\n"
            "       A routable listener transmits to whoever connects, "
            "which is what\n"
            "       --strict declines for this run. Bind loopback "
            "(tcp:127.0.0.1:PORT)\n"
            "       or a unix: path, or drop --strict.\n",
            spec);
}

int daemon_open_jsonl(const char *path) {
    if (!jsonl_open(path)) {
        fprintf(stderr, "sloth: could not open jsonl output %s\n",
                jsonl_error());
        return 1;
    }
    return 0;
}

int daemon_open_db(const char *path, const char *site_label,
                   time_t session_start) {
    if (!db_open(path)) {
        /* Diagnostic already printed. A DB the operator explicitly
         * asked for and which cannot be opened is a startup error,
         * not something to silently continue without. */
        return 1;
    }
    fprintf(stderr,
            "sloth: db %s (schema v%d, every %ds, retain %dd, max %dMiB)\n",
            path, DB_SCHEMA_VERSION, db_interval(),
            db_retain_days(), db_max_mb());
    /* Record the visit so a later run can answer "what is new since
     * last time" (#56). --site-label already carries the operator's
     * name for the site, so reuse it rather than inventing one. */
    db_session_begin(site_label, session_start);
    if (db_previous_session_end() > 0)
        fprintf(stderr, "sloth: previous visit ended %ld\n",
                (long)db_previous_session_end());
    return 0;
}

int daemon_open_data_socket(const char *spec, int allow_remote,
                            const char *preferred) {
    if (data_socket_init_ex(spec, allow_remote) != 0) {
        /* error already printed by data_socket_init_ex */
        return 1;
    }
    fprintf(stderr, "sloth: data-socket listening on %s\n", spec);
    /* #135: a loopback TCP listener authenticates nobody — every
     * local account can connect to 127.0.0.1 (CWE-306) — where a
     * unix: path is created 0600 and the kernel vouches for the
     * peer's uid. Announced, not changed: the bare-flag default
     * is #136's ruling, and MISSION §2 asks that an exposure
     * be said out loud rather than silently inherited. */
    if (strncmp(spec, "tcp:", 4) == 0 &&
        data_socket_spec_is_remote(spec) == 0)
        fprintf(stderr,
                "sloth: data-socket %s is readable by every local account; "
                "prefer %s (0600, kernel-checked peer)\n",
                spec, preferred);
    return 0;
}

void daemon_wait(int timeout_ms, int wake_fd) {
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (wake_fd < 0) { select(0, NULL, NULL, NULL, &tv); return; }
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(wake_fd, &rfds);
    select(wake_fd + 1, &rfds, NULL, NULL, &tv);
}
