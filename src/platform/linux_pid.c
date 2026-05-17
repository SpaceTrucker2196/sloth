#ifdef PLATFORM_LINUX

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#include "sloth.h"
#include "platform/linux_pid.h"

/* ── inode → pid map ─────────────────────────────────────── */

typedef struct {
    unsigned long inode;
    int           pid;
    char          comm[16];
} inode_entry_t;

/* Static map rebuilt each poll; sized for a busy system */
#define IMAP_MAX 4096
static inode_entry_t g_imap[IMAP_MAX];
static int           g_imap_n = 0;

static void read_comm(int pid, char *comm, int len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) { comm[0] = '\0'; return; }
    if (fgets(comm, len, f)) {
        /* strip newline */
        for (int i = 0; comm[i]; i++)
            if (comm[i] == '\n') { comm[i] = '\0'; break; }
    }
    fclose(f);
}

static void build_inode_map(void) {
    g_imap_n = 0;

    DIR *proc = opendir("/proc");
    if (!proc) return;

    struct dirent *de;
    while ((de = readdir(proc)) != NULL && g_imap_n < IMAP_MAX) {
        /* only numeric directory names are PIDs */
        int pid = 0;
        int is_pid = 1;
        for (int i = 0; de->d_name[i]; i++) {
            if (de->d_name[i] < '0' || de->d_name[i] > '9') { is_pid = 0; break; }
            pid = pid * 10 + (de->d_name[i] - '0');
        }
        if (!is_pid || pid == 0) continue;

        char fddir[64];
        snprintf(fddir, sizeof(fddir), "/proc/%d/fd", pid);
        DIR *fds = opendir(fddir);
        if (!fds) continue;

        char comm[16] = "";
        read_comm(pid, comm, (int)sizeof(comm));

        struct dirent *fd;
        while ((fd = readdir(fds)) != NULL && g_imap_n < IMAP_MAX) {
            char lpath[280], target[128]; /* lpath: "/proc/<pid>/fd/<name>", d_name up to 255 */
            snprintf(lpath, sizeof(lpath), "/proc/%d/fd/%s", pid, fd->d_name);
            ssize_t len = readlink(lpath, target, sizeof(target) - 1);
            if (len <= 0) continue;
            target[len] = '\0';

            unsigned long inode = 0;
            if (sscanf(target, "socket:[%lu]", &inode) != 1) continue;

            g_imap[g_imap_n].inode = inode;
            g_imap[g_imap_n].pid   = pid;
            memcpy(g_imap[g_imap_n].comm, comm, sizeof(g_imap[g_imap_n].comm));
            g_imap_n++;
        }
        closedir(fds);
    }
    closedir(proc);
}

/* ── public API ──────────────────────────────────────────── */

void resolve_pids(conn_t *conns, int count) {
    if (count == 0) return;
    build_inode_map();

    for (int i = 0; i < count; i++) {
        if (conns[i].inode == 0) continue;
        for (int j = 0; j < g_imap_n; j++) {
            if (g_imap[j].inode != conns[i].inode) continue;
            conns[i].pid = g_imap[j].pid;
            memcpy(conns[i].proc, g_imap[j].comm, sizeof(conns[i].proc));
            break;
        }
    }
}

#endif /* PLATFORM_LINUX */
