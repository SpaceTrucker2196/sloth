#ifndef SLOTH_EXPOSURE_H
#define SLOTH_EXPOSURE_H

#include <stdio.h>
#include <time.h>
#include "sloth.h"
#include "rule_coverage.h"

/* ── What this site reveals (#243) ───────────────────────────────────
 *
 * sloth has many exposure findings, each on its own. This module groups
 * them by what an observer outside the site learns (FM 2-0 1-30: the
 * information to protect; 1-111: how an observer could collect it):
 * network names, device makes and presence, clear-text credentials,
 * self-announcing devices, weak encryption lanes, devices in setup mode.
 * The table that puts each alert kind in at most one group is
 * include/sloth_exposure.def.
 *
 * Scope: the operator's own site only, the designated networks and the
 * rostered devices (src/ownership.h). With nothing designated there is
 * no site to report on, and the section says which flags name one
 * rather than listing the neighbourhood. A finding that cannot be tied
 * to a designation is counted as `outside` and not listed.
 *
 * Every group carries the coverage status of its rules
 * (rule_coverage_live.h), so an empty group says whether the rules
 * could have seen anything: "nothing found" is never read as "none".
 *
 * Reads only the alert snapshot in the state, the designations and the
 * coverage status. Receive-only, like everything it summarises. */

typedef enum {
    EXP_G_NONE = 0,
    EXP_G_NAMES,        /* network names and their history */
    EXP_G_DEVICES,      /* device makes, models and presence times */
    EXP_G_CREDS,        /* credentials and user names in clear text */
    EXP_G_ANNOUNCE,     /* cameras and other self-announcing devices */
    EXP_G_LANES,        /* weak encryption lanes a device can be moved to */
    EXP_G_SETUP,        /* devices in setup mode */
    EXP_G_COUNT
} exp_group_t;

typedef enum {
    EXP_S_NA = 0,
    EXP_S_OWN,          /* the rule fires only about a designated network */
    EXP_S_AIR,          /* heard over the air: an address or SSID in the key */
    EXP_S_LAN           /* the IP capture: a rostered address, or the
                         * managed link on a designated network */
} exp_scope_t;

/* The table's row for `t`; EXP_G_NONE / EXP_S_NA / "" out of range. */
exp_group_t exp_group_of(alert_type_t t);
exp_scope_t exp_scope_of(alert_type_t t);
/* The first Fix step of the kind's docs/wiki/alert-remediation.md
 * section (tests/test_exposure.c holds it there). */
const char *exp_remedy(alert_type_t t);

/* "network_names", "devices", "credentials", "self_announcing",
 * "weak_lanes", "setup_mode"; "" for NONE or out of range. The `group`
 * of the exposure_summary record. */
const char *exp_group_name(exp_group_t g);
/* The report's heading for the group. */
const char *exp_group_title(exp_group_t g);

/* 1 when the operator designated a network or rostered a device. */
int exp_designated(void);

/* 1 when `a` is about the operator's own site (its kind's SCOPE). */
int exp_in_scope(const sloth_state_t *s, const alert_t *a);

/* One group's statement. */
typedef enum {
    EXP_ST_NEEDS_DESIGNATION = 0, /* nothing designated: no site */
    EXP_ST_FOUND,                 /* at least one finding in scope */
    EXP_ST_NONE_OBSERVABLE,       /* nothing found, every rule observable */
    EXP_ST_NONE_PARTLY,           /* nothing found, some rules partly or blind */
    EXP_ST_NOT_OBSERVABLE,        /* nothing found, every rule blind */
    EXP_ST_NOT_ASSESSED           /* nothing found, no coverage status yet */
} exp_state_t;
const char *exp_state_name(exp_state_t st);

#define EXP_KINDS_MAX 16

typedef struct {
    alert_type_t kind;
    int          findings;    /* incidents (distinct keys) in scope */
    long         evidence;    /* their observations, summed */
    time_t       first_seen;
    time_t       last_seen;
} exp_line_t;

typedef struct {
    exp_group_t g;
    exp_state_t state;
    int         nlines;               /* kinds with a finding in scope */
    exp_line_t  line[EXP_KINDS_MAX];  /* in sloth_alerts.def order */
    int         findings;
    long        evidence;
    time_t      first_seen, last_seen;
    int         outside;              /* findings of the group not in scope */
    int         assessed;             /* the coverage counts below are real */
    int         rules;                /* the group's kinds */
    int         observable, partly, blind;
    unsigned    why;                  /* 1u << cov_reason_t, the kinds not observable */
} exp_group_sum_t;

/* Summarise every group into out[1 .. EXP_G_COUNT-1] (out[0] unused). */
void exp_summarise(const sloth_state_t *s, exp_group_sum_t out[EXP_G_COUNT]);

/* Comma-joined reason words of a `why` mask, in cov_reason_t order. */
int exp_why_str(unsigned why, char *out, size_t sz);

/* The posture report's section (src/posture.c): Markdown `## What this
 * site reveals`; JSON the member `  "exposure": {...}`, a comma and a
 * newline. */
void exp_report_md(FILE *out, const sloth_state_t *s);
void exp_report_json(FILE *out, const sloth_state_t *s);

/* The exposure_summary JSONL records (sloth-wifi's stream): one per
 * group, change-only with the heartbeat. Kinds, counts, times and
 * words only: never an address, a name or a user name. */
void exp_emit(const sloth_state_t *s);

#endif /* SLOTH_EXPOSURE_H */
