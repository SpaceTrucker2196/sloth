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

static int bt_socket(void) {
    return socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BLES_BTPROTO_HCI);
}

/* The helper's only write to the controller. It is reached only as the
 * writer bles_send() calls after the gate, and must stay the one send()
 * in this file: tests/test_ble_scan.c fails otherwise. */
static ssize_t hci_write(void *ctx, const uint8_t *pkt, size_t len) {
    return send(*(const int *)ctx, pkt, len, MSG_NOSIGNAL);
}

/* One command, built, gated and written by bles_send(). A refusal is a
 * bug in the builder or the gate, so it is fatal, not a skip. */
static int send_cmd(int fd, int c) {
    int r = bles_send(c, hci_write, &fd);
    if (r == BLES_SEND_REFUSED) {
        fprintf(stderr, ME ": internal: command %d refused by the allow-list\n", c);
        abort();
    }
    return r == BLES_SEND_OK ? 0 : -1;
}

/* Reads events until the step function has an answer for the command
 * in flight, or CMD_TIMEOUT_MS passes. The decision is
 * bles_est_feed()'s; this only does the I/O. */
static bles_step_t await_step(int fd, bles_est_t *est) {
    uint64_t end = sloth_mono_ms() + CMD_TIMEOUT_MS;
    uint8_t buf[1100];
    for (;;) {
        uint64_t now = sloth_mono_ms();
        if (now >= end) { errno = ETIMEDOUT; return BLES_STEP_IO_ERROR; }
        struct pollfd pf = { fd, POLLIN, 0 };
        int r = poll(&pf, 1, (int)(end - now));
        if (r < 0) { if (errno == EINTR) continue; return BLES_STEP_IO_ERROR; }
        if (r == 0) continue;
        ssize_t got = recv(fd, buf, sizeof(buf), 0);
        if (got < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return BLES_STEP_IO_ERROR;
        }
        bles_ev_t ev;
        (void)bles_parse_event(buf, (size_t)got, &ev);
        bles_step_t st = bles_est_feed(est, &ev);
        if (st != BLES_STEP_WAIT) return st;
    }
}

static const char *cmd_name(int c) {
    switch (c) {
    case BLES_CMD_RESET:               return "HCI_Reset";
    case BLES_CMD_SET_EVENT_MASK:      return "Set Event Mask";
    case BLES_CMD_LE_SET_EVENT_MASK:   return "LE Set Event Mask";
    case BLES_CMD_LE_SCAN_PARAMS:      return "LE Set Scan Parameters";
    case BLES_CMD_LE_SCAN_ENABLE:      return "LE Set Scan Enable";
    case BLES_CMD_LE_SCAN_DISABLE:     return "LE Set Scan Enable (disable)";
    case BLES_CMD_LE_EXT_SCAN_PARAMS:  return "LE Set Extended Scan Parameters";
    case BLES_CMD_LE_EXT_SCAN_ENABLE:  return "LE Set Extended Scan Enable";
    case BLES_CMD_LE_EXT_SCAN_DISABLE: return "LE Set Extended Scan Enable (disable)";
    default:                           return "?";
    }
}

/* Runs the sequence in ble_scan_cmd.h to its end. */
static bles_step_t establish(int fd, bles_mode_t *mode) {
    bles_est_t est;
    bles_est_begin(&est);
    for (;;) {
        if (send_cmd(fd, est.cmd) != 0) {
            fprintf(stderr, ME ": %s: send: %s\n", cmd_name(est.cmd), strerror(errno));
            return BLES_STEP_IO_ERROR;
        }
        bles_step_t st = await_step(fd, &est);
        switch (st) {
        case BLES_STEP_SEND:
            continue;
        case BLES_STEP_DONE:
            *mode = est.mode;
            return st;
        case BLES_STEP_FAIL:
            fprintf(stderr, ME ": %s: status 0x%02x\n", cmd_name(est.cmd), est.status);
            return st;
        case BLES_STEP_HW_ERROR:
            fprintf(stderr, ME ": %s: Hardware Error 0x%02x\n", cmd_name(est.cmd), est.status);
            return st;
        default:
            fprintf(stderr, ME ": %s: no answer: %s\n", cmd_name(est.cmd), strerror(errno));
            return BLES_STEP_IO_ERROR;
        }
    }
}

/* The disable, answered or not: closing the socket ends the scan anyway. */
static void disable(int fd, bles_mode_t mode) {
    int c = bles_disable_cmd(mode);
    if (send_cmd(fd, c) != 0) return;
    uint64_t end = sloth_mono_ms() + CMD_TIMEOUT_MS;
    uint16_t op = bles_opcode(c);
    uint8_t buf[1100];
    while (sloth_mono_ms() < end) {
        struct pollfd pf = { fd, POLLIN, 0 };
        if (poll(&pf, 1, 100) <= 0) continue;
        ssize_t got = recv(fd, buf, sizeof(buf), 0);
        if (got < 0) { if (errno == EINTR || errno == EAGAIN) continue; return; }
        bles_ev_t ev;
        if (bles_parse_event(buf, (size_t)got, &ev) == BLES_EV_CMD_COMPLETE &&
            ev.opcode == op) return;
    }
}

static void announce(int dev, bles_mode_t mode, const char *why) {
    fprintf(stderr, ME ": passive LE scan %s on hci%d (%s commands, "
            "interval = window = %d ms; passive: no SCAN_REQ is sent)\n",
            why, dev, mode == BLES_MODE_LEGACY ? "legacy" : "extended",
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
    /* At boot the sensor, and so this, can start before hciN registers
     * (ENODEV) or while the kernel still sets a USB controller up
     * (EBUSY). Waited out here, bounded, rather than through systemd's
     * Restart=, whose StartLimitBurst would leave the unit failed with
     * nothing to restart it before the sensor next does. */
    uint64_t end = sloth_mono_ms() + (uint64_t)BLES_BIND_WAIT_S * 1000u;
    int e, waited = 0;
    for (;;) {
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            if (waited) fprintf(stderr, ME ": hci%d is ready\n", dev);
            return fd;
        }
        e = errno;
        if (g_stop || !bles_bind_transient(e) || sloth_mono_ms() >= end) break;
        if (!waited)
            fprintf(stderr, ME ": hci%d not ready (%s); waiting up to %d s\n",
                    dev, strerror(e), BLES_BIND_WAIT_S);
        waited = 1;
        (void)poll(NULL, 0, 1000);
    }
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
    else if (e == ENODEV) {
        /* Not registered yet (boot): nothing to bring down, and the
         * main run waits BLES_BIND_WAIT_S for it, then names it. */
        fprintf(stderr, ME ": no controller hci%d yet; nothing to bring down\n", dev);
        return 0;
    } else if (e == EPERM || e == EACCES)
        fprintf(stderr, ME ": bringing hci%d down needs CAP_NET_ADMIN\n", dev);
    else
        fprintf(stderr, ME ": HCIDEVDOWN hci%d: %s\n", dev, strerror(e));
    return 1;
}

int main(int argc, char **argv) {
    bles_args_t args;
    switch (bles_parse_args(argc, argv, &args)) {
    case BLES_ARGS_RUN:
        break;
    case BLES_ARGS_HELP:
        usage();
        return 0;
    case BLES_ARGS_BAD_DELAY:
        fprintf(stderr, ME ": --delay takes 0..%d seconds\n", BLES_DELAY_MAX);
        return 2;
    default:
        usage();
        return 2;
    }
    int dev = args.dev;
    if (args.down) return do_down(dev);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;   /* no SA_RESTART: poll() must return */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /* Lets a sensor started in the same transaction open the monitor
     * channel first, so it sees the Reset and the passive parameters. */
    if (args.delay > 0) {
        uint64_t end = sloth_mono_ms() + (uint64_t)args.delay * 1000u;
        while (!g_stop) {
            uint64_t now = sloth_mono_ms();
            if (now >= end) break;
            (void)poll(NULL, 0, (int)(end - now));
        }
        if (g_stop) return 0;
    }

    int fd = take_channel(dev);
    if (fd < 0) return g_stop ? 0 : 1;

    bles_rearm_t budget;
    memset(&budget, 0, sizeof(budget));
    bles_mode_t mode = BLES_MODE_LEGACY;
    int held = 0, rc = 0, first = 1;
    uint8_t buf[1100];
    while (!g_stop) {
        if (!held) {
            bles_step_t r = establish(fd, &mode);
            bles_next_t next = bles_after_establish(r, &budget, sloth_mono_ms());
            if (next == BLES_NEXT_HOLD) {
                announce(dev, mode, first ? "held" : "re-established");
                held = 1;
                first = 0;
                continue;
            }
            if (next == BLES_NEXT_RETRY) {
                fprintf(stderr, ME ": hci%d: retrying from HCI_Reset\n", dev);
                continue;
            }
            fprintf(stderr, ME ": could not %s the scan on hci%d\n",
                    first ? "establish" : "re-establish", dev);
            rc = 1;
            break;
        }
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
        if (!bles_ev_lost_scan(&ev)) continue;   /* reports, No-Ops: discarded */
        fprintf(stderr, ME ": hci%d Hardware Error 0x%02x\n", dev, ev.hw_code);
        if (!bles_rearm_take(&budget, sloth_mono_ms())) {
            fprintf(stderr, ME ": hci%d lost the scan %d times in %u s; giving up\n",
                    dev, BLES_REARM_MAX, BLES_REARM_WINDOW_MS / 1000u);
            rc = 1;
            break;
        }
        held = 0;
    }

    /* Disable before release. Closing the socket would end the scan
     * anyway (the kernel closes the device), but the disable crossing
     * the monitor channel is what tells sloth the scan stopped. */
    if (rc == 0 && held) {
        disable(fd, mode);
        fprintf(stderr, ME ": scan disabled, hci%d released\n", dev);
    }
    close(fd);
    return rc;
}
