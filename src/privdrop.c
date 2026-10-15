/* setresuid/setresgid/setgroups and syscall() are declared by glibc only
 * under _GNU_SOURCE, which -std=c99 -D_DEFAULT_SOURCE does not imply.
 * Declarations only — no GNU language extension is used. Same gate as
 * src/data_socket.c. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "privdrop.h"

#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <errno.h>
#include <grp.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#endif

/* ── Plan (pure) ─────────────────────────────────────────── */

void privdrop_resolve(const privdrop_req_t *req, privdrop_plan_t *plan) {
    memset(plan, 0, sizeof(*plan));
    /* NNP is unconditional: it costs sloth nothing (it never execs a
     * setuid helper) and closes the one route back up — an exec that
     * regains privilege through file capabilities or the setuid bit. */
    plan->set_no_new_privs = 1;
    /* CAP_NET_RAW is never kept. pcap_activate() creates the AF_PACKET
     * sockets at open and reading them needs no capability; the one
     * consumer that would reopen, the interactive [m] retarget, is
     * documented as needing a privileged run (see monitor-mode.md). */
    plan->keep_net_raw = 0;
    /* CAP_NET_ADMIN only for the two flags that write nl80211 for the
     * whole run, and only if the process holds it — capset cannot
     * grant a capability the permitted set lacks. */
    int want_admin = req->hop || req->allow_active;
    plan->keep_net_admin = want_admin && req->have_cap_net_admin;

    if (req->user_given && req->no_privdrop) {
        plan->action    = PRIVDROP_REFUSE_CANNOT;
        plan->exit_code = 2;
        plan->reason    = "--user and --no-privdrop contradict each other";
        return;
    }
    if (req->user_given && !req->user_resolved) {
        plan->action    = PRIVDROP_REFUSE_NO_SUCH_USER;
        plan->exit_code = 2;
        plan->reason    = "--user names no account on this host";
        return;
    }
    if (req->no_privdrop) {
        /* Nothing shed, so the plan describes what stays: everything. */
        plan->action         = PRIVDROP_DISABLED;
        plan->keep_net_admin = req->have_cap_net_admin;
        plan->keep_net_raw   = req->have_cap_net_raw;
        return;
    }

    int can_switch = req->user_resolved && req->have_cap_setuid;
    if (req->user_given && !can_switch) {
        /* Asked for by name and impossible: a refusal, never a quiet
         * fallback to whatever uid the process already has. */
        plan->action    = PRIVDROP_REFUSE_CANNOT;
        plan->exit_code = 2;
        plan->reason    = "--user needs root (CAP_SETUID and CAP_SETGID) "
                          "to switch accounts";
        return;
    }

    plan->shed_caps     = 1;
    plan->drop_bounding = req->have_cap_setpcap;

    if (req->euid_is_root) {
        if (can_switch && req->uid != 0) {
            plan->action     = PRIVDROP_DROP;
            plan->change_uid = 1;
            plan->uid        = req->uid;
            plan->gid        = req->gid;
        } else {
            /* No account to drop to (or it is uid 0 itself): keep the
             * uid, shed the capabilities. Root without CAP_DAC_OVERRIDE
             * and friends is still owner of root's files, but no longer
             * everyone's. */
            plan->action = PRIVDROP_ROOT_KEEP_UID;
        }
        return;
    }

    if (req->user_given) {
        /* Not root but holding CAP_SETUID/CAP_SETGID (can_switch held
         * above) — an explicit request is honoured. */
        plan->action     = PRIVDROP_DROP;
        plan->change_uid = 1;
        plan->uid        = req->uid;
        plan->gid        = req->gid;
        return;
    }
    /* A non-root run never switches to the default account on its own:
     * the operator already chose the identity by starting it. */
    plan->action = PRIVDROP_NONE_UNPRIVILEGED;
}

/* "CAP_NET_ADMIN for --hop" / "... for --hop and --allow-active". */
static void kept_text(const privdrop_req_t *req, const privdrop_plan_t *plan,
                      char *buf, size_t sz) {
    if (plan->keep_net_admin)
        snprintf(buf, sz, "CAP_NET_ADMIN for %s",
                 req->hop && req->allow_active ? "--hop and --allow-active"
                 : req->hop                    ? "--hop"
                                               : "--allow-active");
    else
        snprintf(buf, sz, "none");
}

void privdrop_describe(const privdrop_req_t *req, const privdrop_plan_t *plan,
                       const char *user, char *buf, size_t sz) {
    if (sz == 0) return;
    buf[0] = '\0';
    char kept[64];
    kept_text(req, plan, kept, sizeof(kept));
    if (!user) user = PRIVDROP_DEFAULT_USER;

    switch (plan->action) {
    case PRIVDROP_DROP:
        snprintf(buf, sz,
                 "sloth: dropped to uid %lu (%s) after capture opened; "
                 "caps kept: %s; no_new_privs on",
                 (unsigned long)plan->uid, user, kept);
        break;
    case PRIVDROP_ROOT_KEEP_UID:
        snprintf(buf, sz,
                 "sloth: no '%s' account to drop to — staying uid 0 with "
                 "every capability dropped; caps kept: %s; no_new_privs on. "
                 "Create the account (packaging/systemd/sloth.sysusers.conf) "
                 "or pass --user NAME",
                 user, kept);
        break;
    case PRIVDROP_DISABLED:
        snprintf(buf, sz,
                 "sloth: --no-privdrop: privileges NOT dropped — this run "
                 "keeps %s for its whole life",
                 req->euid_is_root ? "uid 0 and every capability"
                                   : "every capability it was started with");
        break;
    case PRIVDROP_NONE_UNPRIVILEGED:
        /* Said only when there was something to shed; an ordinary
         * unprivileged dev run prints nothing. */
        if (req->have_cap_net_raw || req->have_cap_net_admin)
            snprintf(buf, sz,
                     "sloth: capabilities dropped after capture opened; "
                     "caps kept: %s; no_new_privs on", kept);
        break;
    case PRIVDROP_REFUSE_NO_SUCH_USER:
    case PRIVDROP_REFUSE_CANNOT:
        break;
    }
}

/* ── Apply (syscalls) ────────────────────────────────────── */

#ifdef __linux__

/* Raw capget/capset with the v3 structs: two 32-bit words per set. No
 * libcap (track X "do not"). */
static int caps_get(struct __user_cap_data_struct d[2]) {
    struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
    memset(d, 0, 2 * sizeof(d[0]));
    return (int)syscall(SYS_capget, &h, d);
}

static int caps_set(struct __user_cap_data_struct d[2]) {
    struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
    return (int)syscall(SYS_capset, &h, d);
}

static int cap_in(unsigned int word0, int cap) {
    return (word0 >> cap) & 1u;
}

int privdrop_probe(privdrop_req_t *req) {
    req->euid_is_root       = geteuid() == 0;
    req->have_cap_setuid    = 0;
    req->have_cap_setpcap   = 0;
    req->have_cap_net_admin = 0;
    req->have_cap_net_raw   = 0;
    struct __user_cap_data_struct d[2];
    if (caps_get(d) != 0) return -1;
    req->have_cap_setuid    = cap_in(d[0].effective, CAP_SETUID) &&
                              cap_in(d[0].effective, CAP_SETGID);
    req->have_cap_setpcap   = cap_in(d[0].effective, CAP_SETPCAP);
    req->have_cap_net_admin = cap_in(d[0].permitted, CAP_NET_ADMIN);
    req->have_cap_net_raw   = cap_in(d[0].permitted, CAP_NET_RAW);
    return 0;
}

static int kept(const privdrop_plan_t *p, int cap) {
    return (cap == CAP_NET_ADMIN && p->keep_net_admin) ||
           (cap == CAP_NET_RAW   && p->keep_net_raw);
}

#define FAIL(...) do { snprintf(err, errsz, __VA_ARGS__); return -1; } while (0)

int privdrop_apply(const privdrop_plan_t *plan, char *err, size_t errsz) {
    if (errsz) err[0] = '\0';
    if (plan->action == PRIVDROP_REFUSE_NO_SUCH_USER ||
        plan->action == PRIVDROP_REFUSE_CANNOT)
        FAIL("refusal plan is not applicable");

    if (plan->shed_caps) {
        /* Bounding set first, while CAP_SETPCAP is still effective — the
         * capset below sheds it, and a setresuid away from 0 clears the
         * effective set. Bits past the kernel's last cap read EINVAL. */
        if (plan->drop_bounding) {
            for (int c = 0; c < 64; c++) {
                int r = prctl(PR_CAPBSET_READ, (unsigned long)c, 0, 0, 0);
                if (r < 0) break;
                if (r == 1 && !kept(plan, c) &&
                    prctl(PR_CAPBSET_DROP, (unsigned long)c, 0, 0, 0) != 0)
                    FAIL("PR_CAPBSET_DROP(%d): %s", c, strerror(errno));
            }
        }
        if (plan->change_uid) {
            /* Keep the permitted set across the uid change so the one
             * capability the run still needs survives it. */
            if (prctl(PR_SET_KEEPCAPS, 1UL, 0, 0, 0) != 0)
                FAIL("PR_SET_KEEPCAPS: %s", strerror(errno));
            if (setgroups(0, NULL) != 0)
                FAIL("setgroups: %s", strerror(errno));
            if (setresgid(plan->gid, plan->gid, plan->gid) != 0)
                FAIL("setresgid(%lu): %s", (unsigned long)plan->gid,
                     strerror(errno));
            if (setresuid(plan->uid, plan->uid, plan->uid) != 0)
                FAIL("setresuid(%lu): %s", (unsigned long)plan->uid,
                     strerror(errno));
            if (prctl(PR_SET_KEEPCAPS, 0UL, 0, 0, 0) != 0)
                FAIL("PR_SET_KEEPCAPS: %s", strerror(errno));
        }

        struct __user_cap_data_struct d[2];
        memset(d, 0, sizeof(d));
        unsigned int want = 0;
        if (plan->keep_net_admin) want |= 1u << CAP_NET_ADMIN;
        if (plan->keep_net_raw)   want |= 1u << CAP_NET_RAW;
        d[0].effective = d[0].permitted = want;
        if (caps_set(d) != 0)
            FAIL("capset: %s%s", strerror(errno),
                 errno == EPERM ? " (a seccomp filter denying capset? "
                                  "see docs/wiki/deployment.md)" : "");
        /* Ambient caps would otherwise ride along into any child. EINVAL
         * is a kernel older than 4.3, which has no ambient set at all. */
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 &&
            errno != EINVAL)
            FAIL("PR_CAP_AMBIENT_CLEAR_ALL: %s", strerror(errno));
    }

    if (plan->set_no_new_privs &&
        prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0, 0, 0) != 0)
        FAIL("PR_SET_NO_NEW_PRIVS: %s", strerror(errno));

    /* ── Readback: fail closed on any mismatch. ─────────────── */
    if (plan->change_uid) {
        uid_t r, e, s;
        gid_t rg, eg, sg;
        if (getresuid(&r, &e, &s) != 0 || r != plan->uid ||
            e != plan->uid || s != plan->uid)
            FAIL("uid readback does not match %lu", (unsigned long)plan->uid);
        if (getresgid(&rg, &eg, &sg) != 0 || rg != plan->gid ||
            eg != plan->gid || sg != plan->gid)
            FAIL("gid readback does not match %lu", (unsigned long)plan->gid);
        if (getgroups(0, NULL) != 0)
            FAIL("supplementary groups survived setgroups(0)");
    }
    if (plan->shed_caps) {
        struct __user_cap_data_struct d[2];
        if (caps_get(d) != 0)
            FAIL("capget: %s", strerror(errno));
        unsigned int want = 0;
        if (plan->keep_net_admin) want |= 1u << CAP_NET_ADMIN;
        if (plan->keep_net_raw)   want |= 1u << CAP_NET_RAW;
        if (d[0].effective != want || d[0].permitted != want ||
            d[0].inheritable != 0 || d[1].effective != 0 ||
            d[1].permitted != 0 || d[1].inheritable != 0)
            FAIL("capability readback %08x/%08x, wanted %08x",
                 d[0].effective, d[0].permitted, want);
        if (plan->drop_bounding) {
            for (int c = 0; c < 64; c++) {
                int r = prctl(PR_CAPBSET_READ, (unsigned long)c, 0, 0, 0);
                if (r < 0) break;
                if (r == 1 && !kept(plan, c))
                    FAIL("bounding set still holds cap %d", c);
            }
        }
    }
    if (plan->set_no_new_privs &&
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        FAIL("no_new_privs readback is not 1");
    return 0;
}

#undef FAIL

#else /* !__linux__ */

/* Non-Linux platforms have no capability model to shed; the plan still
 * resolves (refusals still apply) and apply performs nothing. */
int privdrop_probe(privdrop_req_t *req) {
    req->euid_is_root       = 0;
    req->have_cap_setuid    = 0;
    req->have_cap_setpcap   = 0;
    req->have_cap_net_admin = 0;
    req->have_cap_net_raw   = 0;
    return 0;
}

int privdrop_apply(const privdrop_plan_t *plan, char *err, size_t errsz) {
    if (errsz) err[0] = '\0';
    if (plan->action == PRIVDROP_REFUSE_NO_SUCH_USER ||
        plan->action == PRIVDROP_REFUSE_CANNOT) {
        snprintf(err, errsz, "refusal plan is not applicable");
        return -1;
    }
    return 0;
}

#endif
