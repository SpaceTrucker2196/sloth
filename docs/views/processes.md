# Processes  `[5]`

Process tree built from `/proc/<pid>/{stat,cmdline,status}`.

## Source

`/proc/[1-9]*` — pid, parent pid, comm, command line. Tree is built
by linking each PID to its parent and rendering DFS pre-order.

## View

```
 ── Process tree ──────────────────────────────────────────────
   1   systemd
     342 NetworkManager
     400 wpa_supplicant
     512 chronyd
     743 sshd
       1024 sshd: spacetrucker [priv]
         1100 sshd: spacetrucker@pts/0
           1102 bash
             1500 sloth
   2   kthreadd
     3 rcu_gp                  [kthread]
     ...
   1200 firefox
     1234 (chrome-content)
```

`[d]` toggles whether kernel threads are shown. Indentation = depth.

## What's normal

- The usual `init/systemd` → `getty` / `sshd` / `dbus-daemon` tree.
- One process per browser tab (Chrome's process-per-tab model).
- Kernel threads in square brackets if shown.

## What's suspicious

- **Process running from `/tmp`, `/dev/shm`, or `/var/tmp`** —
  malware staging area. Look at the cmdline.
- **Process named after a system binary but in a wrong location**
  — `/tmp/systemd` is not systemd.
- **Process with mismatched comm vs argv[0]** — common with
  packers/crypters renaming themselves.
- **Orphaned with PPID 1** that wasn't started by systemd-style boot
  scripts — possibly a daemonised malicious process.
- **Shell with elevated privs from a network-facing parent** —
  `httpd` → `bash` is classic webshell.

## Tips

- Use `[2] Connections` to map a suspicious process to its outbound
  flows. PID matches across views.
- Sloth shows processes you have permission to enumerate. Run with
  `sudo` for full visibility.

## See also

- Backend: [`src/platform/linux_pid.c`](../../src/platform/linux_pid.c).
