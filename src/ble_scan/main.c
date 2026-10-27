/* sloth-ble-scan — hold a PASSIVE LE scan on hciN for as long as it runs.
 *
 * Why it exists: sloth --bt-monitor is receive-only and sends no HCI or
 * MGMT command (MISSION.md §2), so the scan it decodes has to be started
 * by the operator. BlueZ offers no passive-scan command a service can
 * hold: `bluetoothctl scan on` and MGMT Start Discovery are active, and
 * `hcitool lescan --passive` fails with EIO on a kernel that manages the
 * device (the command never reaches the controller). The HCI user
 * channel works: with bluetoothd stopped and hciN down, the kernel hands
 * the controller to one socket, and this helper sends it five commands.
 *
 * Why this is consistent with MISSION.md §2:
 *   - A passive scan puts no frame on the air. Core Spec v5.4 Vol 6
 *     Part B §4.4.3.1: in passive scanning the Link Layer only receives
 *     and sends no SCAN_REQ. LE_Scan_Type is a builder constant, 0x00,
 *     and every packet passes bles_cmd_allowed() — an independent check
 *     of opcode, length and scan type — before it is written; the tests
 *     pin both byte for byte (tests/test_ble_scan.c).
 *   - The command set is fixed: HCI_Reset, Set Event Mask, LE Set Event
 *     Mask, LE Set (Extended) Scan Parameters with the scan type passive,
 *     LE Set (Extended) Scan Enable. No advertising, connection,
 *     inquiry, page or vendor command exists in its vocabulary.
 *   - sloth itself still sends no HCI command. This is an operator tool,
 *     like sloth-monitor-up for the 802.11 radio: a separate binary, not
 *     linked into `sloth`, run by a unit the operator enables
 *     (packaging/systemd/sloth-ble-scan.service). sloth, listening on
 *     the monitor channel, sees every command this helper sends and
 *     checks it: ble_scan_mode reads `passive`, and BT_OWN_TRANSMIT
 *     fires if the controller is ever told to transmit.
 *
 * What the kernel does on its own is not this helper's: binding the user
 * channel opens the device (hci_dev_open), and releasing it or `--down`
 * closes it, which runs the driver's own open/shutdown path. None of
 * that is an over-the-air transmission either.
 *
 * Advertising reports are read and discarded unopened — the socket has
 * to be drained or the controller stalls — and never printed: sloth is
 * the decoder. Needs CAP_NET_ADMIN (the kernel's check for
 * HCI_CHANNEL_USER and HCIDEVDOWN in net/bluetooth/hci_sock.c), nothing
 * else.
 *
 * Usage:
 *   sloth-ble-scan [--delay SECS] [hciN]   hold the scan (default hci0)
 *   sloth-ble-scan --down [hciN]           bring hciN down (HCIDEVDOWN)
 * Exit: 0 stopped by SIGTERM/SIGINT/SIGHUP, 1 failure, 2 usage. */

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "ble_scan/ble_scan_cmd.h"
#include "sloth_clock.h"

/* From the kernel's include/net/bluetooth/{bluetooth,hci,hci_sock}.h,
 * spelled out so the helper builds without libbluetooth-dev. */
#ifndef AF_BLUETOOTH
#define AF_BLUETOOTH 31
#endif
#define BLES_BTPROTO_HCI       1
#define BLES_HCI_CHANNEL_USER  1
#define BLES_HCIDEVDOWN        _IOW('H', 202, int)

struct bles_sockaddr_hci {
    sa_family_t    hci_family;
    unsigned short hci_dev;
    unsigned short hci_channel;
};

#define ME "sloth-ble-scan"
#define CMD_TIMEOUT_MS 2000

static volatile sig_atomic_t g_stop;

static void on_signal(int sig) { (void)sig; g_stop = 1; }

static void usage(void) {
    fprintf(stderr,
            "usage: " ME " [--delay SECS] [hciN]   hold a passive LE scan (default hci0)\n"
            "       " ME " --down [hciN]           bring hciN down\n");
}

/* "hci3" or "3" → 3; -1 when it is neither. */
static int parse_dev(const char *s) {
    if (strncmp(s, "hci", 3) == 0) s += 3;
    if (!*s) return -1;
    long v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        v = v * 10 + (*p - '0');
        if (v > 0xfffe) return -1;
    }
    return (int)v;
}

static int bt_socket(void) {
    return socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BLES_BTPROTO_HCI);
}

/* Builds, gates and writes one command. The gate failing is a bug in
 * this file, so it is fatal, not a skip. */
static int send_cmd(int fd, int c) {
    uint8_t b[BLES_CMD_MAX];
    size_t n = bles_build(c, b, sizeof(b));
    if (n == 0 || !bles_cmd_allowed(b, n)) {
        fprintf(stderr, ME ": internal: command %d refused by the allow-list\n", c);
        abort();
    }
    ssize_t w = send(fd, b, n, MSG_NOSIGNAL);
    return w == (ssize_t)n ? 0 : -1;
}

/* Waits for the Command Complete or Command Status answering `op`,
 * discarding everything else. 0 and *status on an answer, -1 on a read
 * error or timeout, -2 when a Hardware Error arrives first. */
static int await(int fd, uint16_t op, uint8_t *status) {
    uint64_t end = sloth_mono_ms() + CMD_TIMEOUT_MS;
    uint8_t buf[1100];
    for (;;) {
        uint64_t now = sloth_mono_ms();
        if (now >= end) { errno = ETIMEDOUT; return -1; }
        struct pollfd pf = { fd, POLLIN, 0 };
        int r = poll(&pf, 1, (int)(end - now));
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) continue;
        ssize_t got = recv(fd, buf, sizeof(buf), 0);
        if (got < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return -1;
        }
        bles_ev_t ev;
        switch (bles_parse_event(buf, (size_t)got, &ev)) {
        case BLES_EV_CMD_COMPLETE:
            if (ev.opcode == op) { *status = ev.has_status ? ev.status : 0; return 0; }
            break;
        case BLES_EV_CMD_STATUS:
            if (ev.opcode == op) { *status = ev.status; return 0; }
            break;
        case BLES_EV_HW_ERROR:
            *status = ev.hw_code;
            return -2;
        default:
            break;
        }
    }
}

/* One command, answered with status 0. Returns the controller status
 * (>0), or -1 on I/O failure, -2 on Hardware Error. */
static int run_cmd(int fd, int c, const char *what) {
    uint8_t st = 0;
    if (send_cmd(fd, c) != 0) {
        fprintf(stderr, ME ": %s: send: %s\n", what, strerror(errno));
        return -1;
    }
    int r = await(fd, bles_opcode(c), &st);
    if (r == -1) {
        fprintf(stderr, ME ": %s: no answer: %s\n", what, strerror(errno));
        return -1;
    }
    if (r == -2) {
        fprintf(stderr, ME ": %s: Hardware Error 0x%02x\n", what, st);
        return -2;
    }
    return st;
}

typedef enum { MODE_LEGACY, MODE_EXTENDED } scan_mode_t;

/* Reset → event masks → passive parameters → enable. Legacy commands
 * first: after a Reset no extended command has been issued, so a
 * controller that has both accepts them (it may not mix the two sets
 * between resets, Vol 4 Part E §3.1.1), and only one that refuses the
 * legacy parameters as unknown or unsupported is moved to the extended
 * pair. 0 on success. */
static int establish(int fd, scan_mode_t *mode) {
    static const struct { int c; const char *what; } pre[] = {
        { BLES_CMD_RESET,             "HCI_Reset" },
        { BLES_CMD_SET_EVENT_MASK,    "Set Event Mask" },
        { BLES_CMD_LE_SET_EVENT_MASK, "LE Set Event Mask" },
    };
    for (size_t i = 0; i < sizeof(pre) / sizeof(pre[0]); i++) {
        int st = run_cmd(fd, pre[i].c, pre[i].what);
        if (st != 0) {
            if (st > 0) fprintf(stderr, ME ": %s: status 0x%02x\n", pre[i].what, st);
            return -1;
        }
    }
    int st = run_cmd(fd, BLES_CMD_LE_SCAN_PARAMS, "LE Set Scan Parameters");
    if (st == 0) {
        st = run_cmd(fd, BLES_CMD_LE_SCAN_ENABLE, "LE Set Scan Enable");
        if (st == 0) { *mode = MODE_LEGACY; return 0; }
        if (st > 0) fprintf(stderr, ME ": LE Set Scan Enable: status 0x%02x\n", st);
        return -1;
    }
    if (st < 0) return -1;
    if (!bles_status_wants_extended((uint8_t)st)) {
        fprintf(stderr, ME ": LE Set Scan Parameters: status 0x%02x\n", st);
        return -1;
    }
    st = run_cmd(fd, BLES_CMD_LE_EXT_SCAN_PARAMS, "LE Set Extended Scan Parameters");
    if (st == 0)
        st = run_cmd(fd, BLES_CMD_LE_EXT_SCAN_ENABLE, "LE Set Extended Scan Enable");
    if (st == 0) { *mode = MODE_EXTENDED; return 0; }
    if (st > 0) fprintf(stderr, ME ": extended scan: status 0x%02x\n", st);
    return -1;
}

static void announce(int dev, scan_mode_t mode, const char *why) {
    fprintf(stderr, ME ": passive LE scan %s on hci%d (%s commands, "
            "interval = window = %d ms; passive: no SCAN_REQ is sent)\n",
            why, dev, mode == MODE_LEGACY ? "legacy" : "extended",
            BLES_SCAN_INTERVAL * 5 / 8);
}

static int take_channel(int dev) {
    int fd = bt_socket();
    if (fd < 0) {
        fprintf(stderr, ME ": socket(AF_BLUETOOTH): %s%s\n", strerror(errno),
                errno == EAFNOSUPPORT
                    ? " (no Bluetooth in this kernel, or the unit's "
                      "RestrictAddressFamilies/PrivateNetwork excludes it)"
                    : "");
        return -1;
    }
    struct bles_sockaddr_hci a;
    memset(&a, 0, sizeof(a));
    a.hci_family  = AF_BLUETOOTH;
    a.hci_dev     = (unsigned short)dev;
    a.hci_channel = BLES_HCI_CHANNEL_USER;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0) return fd;
    int e = errno;
    close(fd);
    switch (e) {
    case EBUSY:
        fprintf(stderr, ME ": hci%d is busy: bluetoothd or the kernel holds "
                "the device. Mask bluetooth.service and bring hci%d down "
                "(systemctl mask --now bluetooth.service; " ME " --down hci%d)\n",
                dev, dev, dev);
        break;
    case EUSERS:
        fprintf(stderr, ME ": another process already holds the user "
                "channel on hci%d\n", dev);
        break;
    case ENODEV:
        fprintf(stderr, ME ": no controller hci%d\n", dev);
        break;
    case EPERM:
    case EACCES:
        fprintf(stderr, ME ": the HCI user channel needs CAP_NET_ADMIN\n");
        break;
    case ERFKILL:
        fprintf(stderr, ME ": hci%d is rfkill-blocked (rfkill unblock bluetooth)\n", dev);
        break;
    default:
        fprintf(stderr, ME ": bind hci%d user channel: %s\n", dev, strerror(e));
        break;
    }
    return -1;
}

static int do_down(int dev) {
    int fd = bt_socket();
    if (fd < 0) {
        fprintf(stderr, ME ": socket(AF_BLUETOOTH): %s\n", strerror(errno));
        return 1;
    }
    int r = ioctl(fd, BLES_HCIDEVDOWN, dev);
    int e = errno;
    close(fd);
    if (r == 0) {
        fprintf(stderr, ME ": hci%d is down\n", dev);
        return 0;
    }
    if (e == EBUSY)
        fprintf(stderr, ME ": hci%d: its user channel is held by another process\n", dev);
    else if (e == ENODEV)
        fprintf(stderr, ME ": no controller hci%d\n", dev);
    else if (e == EPERM || e == EACCES)
        fprintf(stderr, ME ": bringing hci%d down needs CAP_NET_ADMIN\n", dev);
    else
        fprintf(stderr, ME ": HCIDEVDOWN hci%d: %s\n", dev, strerror(e));
    return 1;
}

int main(int argc, char **argv) {
    int dev = 0, down = 0;
    long delay = 0;
    int have_dev = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--down")) {
            down = 1;
        } else if (!strcmp(argv[i], "--delay") && i + 1 < argc) {
            char *end = NULL;
            delay = strtol(argv[++i], &end, 10);
            if (!end || *end || delay < 0 || delay > 60) {
                fprintf(stderr, ME ": --delay takes 0..60 seconds\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage();
            return 0;
        } else if (!have_dev && argv[i][0] != '-' && parse_dev(argv[i]) >= 0) {
            dev = parse_dev(argv[i]);
            have_dev = 1;
        } else {
            usage();
            return 2;
        }
    }
    if (down) return do_down(dev);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;   /* no SA_RESTART: poll() must return */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /* Lets a sensor started in the same transaction open the monitor
     * channel first, so it sees the Reset and the passive parameters. */
    if (delay > 0) {
        uint64_t end = sloth_mono_ms() + (uint64_t)delay * 1000u;
        while (!g_stop) {
            uint64_t now = sloth_mono_ms();
            if (now >= end) break;
            (void)poll(NULL, 0, (int)(end - now));
        }
        if (g_stop) return 0;
    }

    int fd = take_channel(dev);
    if (fd < 0) return 1;

    scan_mode_t mode = MODE_LEGACY;
    if (establish(fd, &mode) != 0) {
        fprintf(stderr, ME ": could not establish the scan on hci%d\n", dev);
        close(fd);
        return 1;
    }
    announce(dev, mode, "held");

    bles_rearm_t budget;
    memset(&budget, 0, sizeof(budget));
    uint8_t buf[1100];
    int rc = 0;
    while (!g_stop) {
        struct pollfd pf = { fd, POLLIN, 0 };
        int r = poll(&pf, 1, 1000);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, ME ": poll: %s\n", strerror(errno));
            rc = 1;
            break;
        }
        if (r == 0) continue;
        ssize_t got = recv(fd, buf, sizeof(buf), 0);
        if (got < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            /* The device unregistered (unplug, driver reset): the kernel
             * fails the socket. systemd's Restart= takes it from here. */
            fprintf(stderr, ME ": hci%d went away: %s\n", dev, strerror(errno));
            rc = 1;
            break;
        }
        bles_ev_t ev;
        (void)bles_parse_event(buf, (size_t)got, &ev);
        if (!bles_ev_lost_scan(&ev)) continue;   /* reports: discarded */
        if (ev.kind == BLES_EV_HW_ERROR)
            fprintf(stderr, ME ": hci%d Hardware Error 0x%02x\n", dev, ev.hw_code);
        else
            fprintf(stderr, ME ": hci%d controller restarted\n", dev);
        if (!bles_rearm_take(&budget, sloth_mono_ms())) {
            fprintf(stderr, ME ": hci%d lost the scan %d times in %u s; giving up\n",
                    dev, BLES_REARM_MAX, BLES_REARM_WINDOW_MS / 1000u);
            rc = 1;
            break;
        }
        if (establish(fd, &mode) != 0) {
            fprintf(stderr, ME ": could not re-establish the scan on hci%d\n", dev);
            rc = 1;
            break;
        }
        announce(dev, mode, "re-established");
    }

    /* Disable before release. Closing the socket would end the scan
     * anyway (the kernel closes the device), but the disable crossing
     * the monitor channel is what tells sloth the scan stopped. */
    if (rc == 0) {
        (void)run_cmd(fd, mode == MODE_LEGACY ? BLES_CMD_LE_SCAN_DISABLE
                                              : BLES_CMD_LE_EXT_SCAN_DISABLE,
                      "scan disable");
        fprintf(stderr, ME ": scan disabled, hci%d released\n", dev);
    }
    close(fd);
    return rc;
}
