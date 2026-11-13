/* sloth-sdrsweep — sweep an SDR across its range for about a minute and
 * write what it heard, for slothweb's Spectrum tab.
 *
 * Why it exists: sloth and slothweb never drive a radio. The operator
 * dedicates a receiver; a separate helper, run by a unit the operator
 * installs (packaging/systemd/sloth-sdrsweep.service), tunes it. Like
 * sloth-ble-scan for the BLE controller and sloth-monitor-up for the
 * 802.11 radio: a separate binary, not linked into `sloth` or
 * `slothweb`, which link no SoapySDR.
 *
 * Why this is consistent with MISSION.md §2:
 *   - It only receives. The SoapySDR calls below are device open, the
 *     receive chain's settings (antenna, rate, bandwidth, gain), the
 *     tuner frequency and a receive stream. No transmit stream is set
 *     up and nothing is written to the device: the transmit direction
 *     constant and the stream-write call are named nowhere in this
 *     file (tests/test_sdrsweep.c holds that). A tuner retune is the kind of
 *     change §2 allows: "Sloth only tunes a receiver already in [its
 *     mode], and only its own."
 *   - Opt-in and announced: nothing runs until the operator installs
 *     the unit and someone presses "Run" (or starts it by hand); the
 *     run is a oneshot, logs what it tunes on stderr, and stops.
 *   - It takes no parameter from the request slothweb writes; the path
 *     unit only starts it. Everything it does is this file's defaults,
 *     the operator's /etc/default/sloth-sdrsweep, and its own argv.
 *
 * It must stop cleanly: a client killed with the stream open wedges the
 * SDRplay API service until `systemctl restart sdrplay` (measured on
 * the RSPdx-R2, 2026-11-13). SIGTERM, SIGINT and SIGHUP only set a
 * flag; the loop notices within one read timeout, deactivates and
 * closes the stream and unmakes the device, and the unit's
 * TimeoutStopSec leaves room for that.
 *
 * The arithmetic and the file formats are src/sdrsweep/sdrsweep_dsp.c,
 * tested without a radio.
 *
 * Usage: sloth-sdrsweep [options]; --help lists them. Settings come
 * from SLOTH_SDRSWEEP_* in the environment (the unit's EnvironmentFile)
 * and are overridden by the command line.
 * Exit: 0 done or stopped by a signal, 1 failure, 2 usage, 3 refused
 * (the cooldown since the last run has not passed). */

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <SoapySDR/Device.h>
#include <SoapySDR/Formats.h>
#include <SoapySDR/Errors.h>

#include "sdrsweep/sdrsweep_dsp.h"
#include "sloth_clock.h"

#define ME "sloth-sdrsweep"

static volatile sig_atomic_t g_stop;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

typedef struct {
    char   device[256];
    char   antenna[64];
    char   gain[128];
    char   out[1024];
    double f_lo, f_hi, rate, bw, keep, dc_guard, disp;
    int    nfft, frames, settle_ms;
    double duration, cooldown;
    int    calibrate;
} opts_t;

/* Through the clock seam, like every file under src/
 * (tests/test_clock_seam.c). */
static double now_s(void) { return sloth_wall_ms() / 1e3; }
static double mono_s(void) { return sloth_mono_ms() / 1e3; }

static void usage(FILE *f) {
    fprintf(f,
        "usage: " ME " [options]\n"
        "  --device ARGS      SoapySDR device string (driver=sdrplay)\n"
        "  --antenna NAME     receive port (Antenna A; Antenna B with --calibrate)\n"
        "  --gain K=V,...     fixed gain elements, gain mode off (IFGR=40,RFGR=3)\n"
        "  --f-lo MHZ         lowest frequency (0.5)\n"
        "  --f-hi MHZ         highest frequency (2000; clamped to the device)\n"
        "  --rate SPS         sample rate (8e6)\n"
        "  --bandwidth HZ     IF bandwidth (7e6)\n"
        "  --keep HZ          centre width kept per step (6e6)\n"
        "  --dc-guard HZ      dropped either side of each centre (25e3)\n"
        "  --nfft N           FFT size, a power of two (8192)\n"
        "  --frames N         FFT frames per step (16)\n"
        "  --settle-ms MS     samples discarded after each retune (30)\n"
        "  --duration S       repeat whole sweeps until this passes (60)\n"
        "  --cooldown S       refuse within this long of the last run (600; 0 off)\n"
        "  --out DIR          state directory (/var/lib/sloth-sdrsweep)\n"
        "  --calibrate        one sweep of an unconnected port: writes spurs.json\n"
        "Each setting also reads SLOTH_SDRSWEEP_<NAME> from the environment\n"
        "(DEVICE, ANTENNA, GAIN, F_LO_MHZ, F_HI_MHZ, DURATION, COOLDOWN, OUT).\n");
}

static int set_str(char *dst, size_t cap, const char *v, const char *what) {
    if (!v || !v[0] || strlen(v) >= cap) {
        fprintf(stderr, ME ": %s: empty or too long\n", what);
        return -1;
    }
    snprintf(dst, cap, "%s", v);
    return 0;
}

static int set_num(double *dst, const char *v, double lo, double hi, const char *what) {
    char *end;
    errno = 0;
    double d = v ? strtod(v, &end) : NAN;
    if (!v || end == v || *end || errno || !(d >= lo && d <= hi)) {
        fprintf(stderr, ME ": %s: want a number in %g..%g\n", what, lo, hi);
        return -1;
    }
    *dst = d;
    return 0;
}

static int set_int(int *dst, const char *v, int lo, int hi, const char *what) {
    double d;
    if (set_num(&d, v, lo, hi, what) != 0) return -1;
    if (d != floor(d)) { fprintf(stderr, ME ": %s: want an integer\n", what); return -1; }
    *dst = (int)d;
    return 0;
}

/* One setting by name, from argv or the environment. */
static int apply(opts_t *o, const char *name, const char *v) {
    if (!strcmp(name, "device"))    return set_str(o->device, sizeof(o->device), v, name);
    if (!strcmp(name, "antenna"))   return set_str(o->antenna, sizeof(o->antenna), v, name);
    if (!strcmp(name, "gain"))      return set_str(o->gain, sizeof(o->gain), v, name);
    if (!strcmp(name, "out"))       return set_str(o->out, sizeof(o->out), v, name);
    if (!strcmp(name, "f-lo")) {
        double m;
        if (set_num(&m, v, 0.001, 100000, name)) return -1;
        o->f_lo = m * 1e6;
        return 0;
    }
    if (!strcmp(name, "f-hi")) {
        double m;
        if (set_num(&m, v, 0.001, 100000, name)) return -1;
        o->f_hi = m * 1e6;
        return 0;
    }
    if (!strcmp(name, "rate"))      return set_num(&o->rate, v, 1e5, 1e8, name);
    if (!strcmp(name, "bandwidth")) return set_num(&o->bw, v, 0, 1e8, name);
    if (!strcmp(name, "keep"))      return set_num(&o->keep, v, 1e4, 1e8, name);
    if (!strcmp(name, "dc-guard"))  return set_num(&o->dc_guard, v, 0, 1e7, name);
    if (!strcmp(name, "nfft"))      return set_int(&o->nfft, v, SDRS_NFFT_MIN, SDRS_NFFT_MAX, name);
    if (!strcmp(name, "frames"))    return set_int(&o->frames, v, 1, 256, name);
    if (!strcmp(name, "settle-ms")) return set_int(&o->settle_ms, v, 0, 1000, name);
    if (!strcmp(name, "duration"))  return set_num(&o->duration, v, 1, 3600, name);
    if (!strcmp(name, "cooldown"))  return set_num(&o->cooldown, v, 0, 86400, name);
    fprintf(stderr, ME ": unknown option --%s\n", name);
    return -1;
}

static int parse_opts(opts_t *o, int argc, char **argv) {
    memset(o, 0, sizeof(*o));
    snprintf(o->device, sizeof(o->device), "driver=sdrplay");
    snprintf(o->gain, sizeof(o->gain), "IFGR=40,RFGR=3");
    snprintf(o->out, sizeof(o->out), "/var/lib/sloth-sdrsweep");
    o->f_lo = 0.5e6; o->f_hi = 2000e6;
    o->rate = 8e6; o->bw = 7e6; o->keep = 6e6; o->dc_guard = 25e3; o->disp = 100e3;
    o->nfft = 8192; o->settle_ms = 30;
    /* 16 frames, one 16 ms capture per step: the frame mean of 4 would
     * cross the +6 dB average threshold on ~3e-4 of noise-only bins
     * (the tail of a gamma(4) at 3.65x its mean), several hundred false
     * bins a sweep; of 16, on none (docs/wiki/sdr-sweep.md). */
    o->frames = 16;
    o->duration = 60; o->cooldown = 600;
    static const struct { const char *env, *name; } E[] = {
        { "SLOTH_SDRSWEEP_DEVICE", "device" }, { "SLOTH_SDRSWEEP_ANTENNA", "antenna" },
        { "SLOTH_SDRSWEEP_GAIN", "gain" }, { "SLOTH_SDRSWEEP_F_LO_MHZ", "f-lo" },
        { "SLOTH_SDRSWEEP_F_HI_MHZ", "f-hi" }, { "SLOTH_SDRSWEEP_DURATION", "duration" },
        { "SLOTH_SDRSWEEP_COOLDOWN", "cooldown" }, { "SLOTH_SDRSWEEP_OUT", "out" },
    };
    for (size_t i = 0; i < sizeof(E) / sizeof(E[0]); i++) {
        const char *v = getenv(E[i].env);
        if (v && v[0] && apply(o, E[i].name, v) != 0) return -1;
    }
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) { usage(stdout); return 1; }
        if (!strcmp(a, "--calibrate")) { o->calibrate = 1; continue; }
        if (strncmp(a, "--", 2) != 0 || i + 1 >= argc) {
            fprintf(stderr, ME ": %s: unexpected\n", a);
            return -1;
        }
        if (apply(o, a + 2, argv[++i]) != 0) return -1;
    }
    /* Everything that can be refused without the device is refused
     * before it is opened: a usage error must never tune anything. */
    if (!sdrs_is_pow2(o->nfft)) {
        fprintf(stderr, ME ": nfft: want a power of two\n");
        return -1;
    }
    if (o->keep > o->rate || o->dc_guard * 2 >= o->keep || !(o->f_hi > o->f_lo)) {
        fprintf(stderr, ME ": want keep <= rate, dc-guard < keep/2 and f-lo < f-hi\n");
        return -1;
    }
    /* The unconnected port, unless the operator named one. */
    if (!o->antenna[0])
        snprintf(o->antenna, sizeof(o->antenna), "%s", o->calibrate ? "Antenna B" : "Antenna A");
    return 0;
}

/* ── the state directory ── */

static char *slurp(const char *path, size_t max) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (size_t)st.st_size > max) {
        close(fd);
        return NULL;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    size_t n = 0;
    while (buf && n < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + n, (size_t)st.st_size - n);
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    if (buf) buf[n] = '\0';
    return buf;
}

/* path.tmp, written by fn, then renamed over path: a reader sees the
 * old file or the new one, never half of either. */
typedef int (*writer_fn)(FILE *f, void *ctx);

static int write_atomic(const char *dir, const char *name, writer_fn fn, void *ctx,
                        const char *keep_prev) {
    char tmp[1200], dst[1200], prev[1200];
    snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", dir, name);
    snprintf(dst, sizeof(dst), "%s/%s", dir, name);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) { fprintf(stderr, ME ": %s: %s\n", tmp, strerror(errno)); return -1; }
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return -1; }
    int rc = fn(f, ctx);
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) rc = -1;
    if (fclose(f) != 0) rc = -1;
    if (rc != 0) { fprintf(stderr, ME ": writing %s failed\n", tmp); unlink(tmp); return -1; }
    if (keep_prev) {
        snprintf(prev, sizeof(prev), "%s/%s", dir, keep_prev);
        if (rename(dst, prev) != 0 && errno != ENOENT)
            fprintf(stderr, ME ": keeping %s: %s\n", prev, strerror(errno));
    }
    if (rename(tmp, dst) != 0) {
        fprintf(stderr, ME ": %s: %s\n", dst, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

typedef struct {
    const char *state;      /* running, done, stopped, failed */
    double started, updated, ended, cooldown;
    int    row, step, steps;
    const char *antenna, *mode, *error;
} status_t;

static int status_writer(FILE *f, void *ctx) {
    const status_t *s = ctx;
    fprintf(f, "{\"version\":1,\"state\":");
    sdrs_json_str(f, s->state);
    fprintf(f, ",\"mode\":");
    sdrs_json_str(f, s->mode);
    fprintf(f, ",\"pid\":%ld,\"started\":%.3f,\"updated\":%.3f", (long)getpid(),
            s->started, s->updated);
    if (s->ended > 0)
        fprintf(f, ",\"ended\":%.3f,\"next_allowed\":%.3f", s->ended, s->ended + s->cooldown);
    fprintf(f, ",\"cooldown\":%.0f,\"row\":%d,\"step\":%d,\"steps\":%d,\"antenna\":",
            s->cooldown, s->row, s->step, s->steps);
    sdrs_json_str(f, s->antenna);
    if (s->error) { fputs(",\"error\":", f); sdrs_json_str(f, s->error); }
    fputs("}\n", f);
    return ferror(f) ? -1 : 0;
}

static void put_status(const opts_t *o, status_t *s) {
    s->updated = now_s();
    (void)write_atomic(o->out, "status.json", status_writer, s, NULL);
}

typedef struct {
    const sdrs_meta_t *m;
    const sdrs_run_t  *r;
    const sdrs_row_t  *rows;
    int nrows;
    const sdrs_peak_t *peaks;
    int npeaks;
} doc_t;

static int doc_writer(FILE *f, void *ctx) {
    const doc_t *d = ctx;
    return sdrs_write_json(f, d->m, d->r, d->rows, d->nrows, d->peaks, d->npeaks);
}

/* ── the radio ── */

static SoapySDRDevice *open_device(const char *args) {
    /* The device can still be held for a moment by the client that had
     * it (the unit stops that one first on a host that shares it). */
    for (int attempt = 0; attempt < 10 && !g_stop; attempt++) {
        SoapySDRDevice *d = SoapySDRDevice_makeStrArgs(args);
        if (d) return d;
        fprintf(stderr, ME ": open %s: %s (attempt %d)\n", args,
                SoapySDRDevice_lastError(), attempt + 1);
        sleep(1);
    }
    return NULL;
}

static int set_gains(SoapySDRDevice *d, const char *spec) {
    if (SoapySDRDevice_setGainMode(d, SOAPY_SDR_RX, 0, false) != 0)
        fprintf(stderr, ME ": gain mode off: %s\n", SoapySDRDevice_lastError());
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", spec);
    for (char *save = NULL, *t = strtok_r(buf, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        char *eq = strchr(t, '=');
        char *end;
        if (!eq) { fprintf(stderr, ME ": gain: %s is not NAME=VALUE\n", t); return -1; }
        *eq = '\0';
        double v = strtod(eq + 1, &end);
        if (end == eq + 1 || *end) { fprintf(stderr, ME ": gain %s: not a number\n", t); return -1; }
        if (SoapySDRDevice_setGainElement(d, SOAPY_SDR_RX, 0, t, v) != 0) {
            fprintf(stderr, ME ": gain %s=%g: %s\n", t, v, SoapySDRDevice_lastError());
            return -1;
        }
    }
    return 0;
}

/* Read exactly n samples into buf (CF32), or fail: -1 an error, -2 a
 * stop request. An overflow means a gap in the samples, so the caller's
 * capture starts over. */
static int read_n(SoapySDRDevice *d, SoapySDRStream *st, float *buf, size_t n, size_t mtu) {
    size_t got = 0;
    int timeouts = 0;
    while (got < n) {
        if (g_stop) return -2;
        void *bufs[1] = { buf + 2 * got };
        size_t want = n - got < mtu ? n - got : mtu;
        int flags = 0;
        long long t = 0;
        int r = SoapySDRDevice_readStream(d, st, bufs, want, &flags, &t, 200000);
        if (r > 0) { got += (size_t)r; timeouts = 0; continue; }
        if (r == SOAPY_SDR_OVERFLOW) return -3;
        if (r == SOAPY_SDR_TIMEOUT && ++timeouts < 10) continue;
        fprintf(stderr, ME ": readStream: %s\n", SoapySDR_errToStr(r));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    opts_t o;
    int pr = parse_opts(&o, argc, argv);
    if (pr > 0) return 0;
    if (pr < 0) { usage(stderr); return 2; }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;     /* no SA_RESTART: a blocked read returns */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    umask(022);   /* slothweb, another account, reads what is written here */

    /* The cooldown, from the last run's own record. slothweb applies it
     * too; this is the second line, for a start that did not come from
     * slothweb. */
    char path[1200];
    snprintf(path, sizeof(path), "%s/status.json", o.out);
    char *prev = slurp(path, 65536);
    if (prev && !o.calibrate && o.cooldown > 0) {
        double ended = sdrs_json_num(prev, "ended", 0);
        double wait = ended + o.cooldown - now_s();
        if (ended > 0 && wait > 0) {
            fprintf(stderr, ME ": refused: the last run ended %.0f s ago; next allowed in %.0f s\n",
                    now_s() - ended, wait);
            free(prev);
            return 3;
        }
    }
    free(prev);

    /* The calibration, when there is one and this is not it. */
    sdrs_peak_t *cal = NULL;
    int ncal = 0;
    if (!o.calibrate) {
        snprintf(path, sizeof(path), "%s/spurs.json", o.out);
        char *ct = slurp(path, 4u << 20);
        if (ct) {
            cal = calloc(SDRS_PEAKS_MAX, sizeof(*cal));
            if (cal) ncal = sdrs_parse_cal(ct, cal, SDRS_PEAKS_MAX);
            free(ct);
            fprintf(stderr, ME ": %d calibration spurs from %s\n", ncal, path);
        }
    }

    status_t stt;
    memset(&stt, 0, sizeof(stt));
    stt.state = "running";
    stt.mode = o.calibrate ? "calibrate" : "sweep";
    stt.started = now_s();
    stt.cooldown = o.cooldown;
    stt.antenna = o.antenna;
    put_status(&o, &stt);

    int rc = 1;
    const char *fail = NULL;
    SoapySDRDevice *dev = NULL;
    SoapySDRStream *st = NULL;
    char *driver = NULL, *hardware = NULL;
    char serial[128] = "";
    float *iq = NULL, *win = NULL, *re = NULL, *im = NULL, *pw = NULL;
    float *mean = NULL, *mx = NULL, *mean_db = NULL, *max_db = NULL;
    sdrs_row_t rows[SDRS_ROWS_MAX];
    int nrows = 0;
    sdrs_run_t run;
    memset(&run, 0, sizeof(run));
    memset(rows, 0, sizeof(rows));

    fprintf(stderr, ME ": %s, %s, receive only: %s, gain %s, %.3f-%.3f MHz for %.0f s\n",
            stt.mode, o.device, o.antenna, o.gain, o.f_lo / 1e6, o.f_hi / 1e6, o.duration);
    dev = open_device(o.device);
    if (!dev) { fail = g_stop ? NULL : "open"; goto out; }
    driver = SoapySDRDevice_getDriverKey(dev);
    hardware = SoapySDRDevice_getHardwareKey(dev);
    SoapySDRKwargs hw = SoapySDRDevice_getHardwareInfo(dev);
    const char *ser = SoapySDRKwargs_get(&hw, "serial");
    if (!ser) {
        const char *p = strstr(o.device, "serial=");
        if (p) {
            snprintf(serial, sizeof(serial), "%s", p + 7);
            serial[strcspn(serial, ",")] = '\0';
        }
    } else {
        snprintf(serial, sizeof(serial), "%s", ser);
    }
    SoapySDRKwargs_clear(&hw);

    if (SoapySDRDevice_setAntenna(dev, SOAPY_SDR_RX, 0, o.antenna) != 0) {
        fprintf(stderr, ME ": antenna %s: %s\n", o.antenna, SoapySDRDevice_lastError());
        fail = "antenna"; goto out;
    }
    if (SoapySDRDevice_setSampleRate(dev, SOAPY_SDR_RX, 0, o.rate) != 0) {
        fprintf(stderr, ME ": rate %g: %s\n", o.rate, SoapySDRDevice_lastError());
        fail = "rate"; goto out;
    }
    if (o.bw > 0 && SoapySDRDevice_setBandwidth(dev, SOAPY_SDR_RX, 0, o.bw) != 0)
        fprintf(stderr, ME ": bandwidth %g: %s\n", o.bw, SoapySDRDevice_lastError());
    if (set_gains(dev, o.gain) != 0) { fail = "gain"; goto out; }

    size_t nr = 0;
    SoapySDRRange *rg = SoapySDRDevice_getFrequencyRange(dev, SOAPY_SDR_RX, 0, &nr);
    sdrs_plan_t plan = { o.f_lo, o.f_hi, o.rate, o.keep, o.dc_guard, 0, 0, o.nfft };
    for (size_t i = 0; i < nr; i++) {
        if (i == 0 || rg[i].minimum < plan.dev_min) plan.dev_min = rg[i].minimum;
        if (i == 0 || rg[i].maximum > plan.dev_max) plan.dev_max = rg[i].maximum;
    }
    free(rg);
    const char *why = NULL;
    if (sdrs_plan_check(&plan, &why) != 0) {
        fprintf(stderr, ME ": %s\n", why);
        fail = "plan"; goto out;
    }
    if (sdrs_run_init(&run, &plan, o.disp) != 0) { fail = "memory"; goto out; }
    stt.steps = run.nsteps;
    fprintf(stderr, ME ": %d steps of %.1f MHz over %.3f-%.3f MHz (device %.3f-%.3f)\n",
            run.nsteps, o.keep / 1e6, plan.f_lo / 1e6, plan.f_hi / 1e6,
            plan.dev_min / 1e6, plan.dev_max / 1e6);

    st = SoapySDRDevice_setupStream(dev, SOAPY_SDR_RX, SOAPY_SDR_CF32, NULL, 0, NULL);
    if (!st) {
        fprintf(stderr, ME ": setupStream: %s\n", SoapySDRDevice_lastError());
        fail = "stream"; goto out;
    }
    size_t mtu = SoapySDRDevice_getStreamMTU(dev, st);
    if (mtu == 0) mtu = 4096;
    size_t n = (size_t)o.nfft;
    size_t settle = (size_t)(o.rate * o.settle_ms / 1000.0);
    size_t cap = n * (size_t)o.frames > settle ? n * (size_t)o.frames : settle;
    if (cap < mtu) cap = mtu;
    iq = malloc(cap * 2 * sizeof(float));
    win = malloc(n * sizeof(float));
    re = malloc(n * sizeof(float));
    im = malloc(n * sizeof(float));
    pw = malloc(n * sizeof(float));
    mean = malloc(n * sizeof(float));
    mx = malloc(n * sizeof(float));
    mean_db = malloc(n * sizeof(float));
    max_db = malloc(n * sizeof(float));
    if (!iq || !win || !re || !im || !pw || !mean || !mx || !mean_db || !max_db) {
        fail = "memory"; goto out;
    }
    double wsum = sdrs_hann(win, o.nfft);
    if (SoapySDRDevice_activateStream(dev, st, 0, 0, 0) != 0) {
        fprintf(stderr, ME ": activateStream: %s\n", SoapySDRDevice_lastError());
        fail = "stream"; goto out;
    }

    double t0 = mono_s(), last_row = 0, last_status = 0;
    while (!g_stop && nrows < SDRS_ROWS_MAX) {
        double elapsed = mono_s() - t0;
        /* Another whole sweep only if it should end inside the
         * duration; the first always runs, and a calibration is one. */
        if (nrows > 0 && (o.calibrate || elapsed + last_row > o.duration + 2)) break;
        double row_t0 = mono_s();
        rows[nrows].t = now_s();
        rows[nrows].q = malloc((size_t)run.ndisp);
        if (!rows[nrows].q) { fail = "memory"; break; }
        sdrs_run_row_begin(&run);
        int s;
        for (s = 0; s < run.nsteps && !g_stop; s++) {
            if (SoapySDRDevice_setFrequency(dev, SOAPY_SDR_RX, 0, run.centres[s], NULL) != 0) {
                fprintf(stderr, ME ": tune %.3f MHz: %s\n", run.centres[s] / 1e6,
                        SoapySDRDevice_lastError());
                fail = "tune";
                break;
            }
            int r = -3;
            for (int tries = 0; tries < 4 && r == -3; tries++) {
                /* Samples from before the retune are still queued:
                 * read and drop the settle time's worth. */
                r = settle ? read_n(dev, st, iq, settle, mtu) : 0;
                if (r == 0) r = read_n(dev, st, iq, n * (size_t)o.frames, mtu);
            }
            if (r == -2) break;
            if (r != 0) { fail = "read"; break; }
            for (size_t k = 0; k < n; k++) { mean[k] = 0; mx[k] = 0; }
            for (int fr = 0; fr < o.frames; fr++) {
                sdrs_frame_power(iq + 2 * n * (size_t)fr, o.nfft, win, re, im, pw);
                for (size_t k = 0; k < n; k++) {
                    mean[k] += pw[k] / o.frames;
                    if (pw[k] > mx[k]) mx[k] = pw[k];
                }
            }
            for (size_t k = 0; k < n; k++) {
                mean_db[k] = sdrs_pow_dbfs(mean[k], wsum);
                max_db[k] = sdrs_pow_dbfs(mx[k], wsum);
            }
            sdrs_run_step(&run, s, mean_db, max_db);
            if (mono_s() - last_status >= 1.0) {
                stt.row = nrows; stt.step = s + 1;
                put_status(&o, &stt);
                last_status = mono_s();
            }
        }
        if (fail) break;
        /* A row the stop cut short is kept only if it is the only one:
         * a partial picture beats none, but not a complete one. */
        if (s < run.nsteps && nrows > 0) break;
        rows[nrows].floor = sdrs_run_row_end(&run, rows[nrows].q);
        nrows++;
        last_row = mono_s() - row_t0;
        fprintf(stderr, ME ": row %d: %.1f s, floor %.1f dBFS\n", nrows, last_row,
                rows[nrows - 1].floor);
    }

out:
    /* The clean stop the SDRplay API needs, whatever happened above. */
    if (st) {
        SoapySDRDevice_deactivateStream(dev, st, 0, 0);
        SoapySDRDevice_closeStream(dev, st);
    }
    /* A run that never had the device has not used the radio, and
     * starts no cooldown: "ended" is what the next start measures. */
    if (dev) {
        SoapySDRDevice_unmake(dev);
        stt.ended = now_s();
    }

    if (nrows > 0) {
        sdrs_peak_t *peaks = calloc(SDRS_PEAKS_MAX, sizeof(*peaks));
        int np = peaks ? sdrs_run_peaks(&run, peaks, SDRS_PEAKS_MAX) : -1;
        if (np < 0) {
            fail = "memory";
        } else {
            sdrs_label(peaks, np, cal, ncal);
            sdrs_meta_t m = {
                stt.mode, !g_stop && !fail, stt.started, now_s(), o.device,
                driver ? driver : "", hardware ? hardware : "", serial, o.antenna, o.gain,
                o.rate, o.bw, o.keep, o.dc_guard, o.nfft, o.frames, o.duration, ncal > 0,
            };
            doc_t d = { &m, &run, rows, nrows, peaks, np };
            if (o.calibrate ? write_atomic(o.out, "spurs.json", doc_writer, &d, NULL)
                            : write_atomic(o.out, "latest.json", doc_writer, &d, "prev.json"))
                fail = "write";
            else
                fprintf(stderr, ME ": wrote %d rows, %d peaks to %s/%s\n", nrows, np, o.out,
                        o.calibrate ? "spurs.json" : "latest.json");
        }
        free(peaks);
    }
    stt.state = fail ? "failed" : g_stop ? "stopped" : "done";
    stt.error = fail;
    stt.row = nrows;
    put_status(&o, &stt);
    rc = fail ? 1 : 0;

    for (int i = 0; i < SDRS_ROWS_MAX; i++) free(rows[i].q);
    sdrs_run_free(&run);
    free(iq); free(win); free(re); free(im); free(pw);
    free(mean); free(mx); free(mean_db); free(max_db);
    free(driver); free(hardware); free(cal);
    return rc;
}
