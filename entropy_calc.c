/*
 * entropy_calc.c - High-performance entropy + inotify syscall monitor
 * Compile: gcc -O2 -shared -fPIC -o entropy_calc.so entropy_calc.c -lm
 *
 * Linux-only: uses inotify, /proc filesystem, ptrace constants
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>

/* ─── ENTROPY ─────────────────────────────────────────────────── */

double calculate_entropy(const unsigned char *data, size_t len) {
    if (len == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / (double)len;
        entropy -= p * log2(p);
    }
    return entropy;
}

double file_entropy(const char *filepath) {
    int fd = open(filepath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1.0;

    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(fd); return -1.0;
    }

    size_t max_read = 524288; /* 512KB sample */
    unsigned char *buf = (unsigned char *)malloc(max_read);
    if (!buf) { close(fd); return -1.0; }

    ssize_t n = read(fd, buf, max_read);
    close(fd);
    if (n <= 0) { free(buf); return 0.0; }

    double e = calculate_entropy(buf, (size_t)n);
    free(buf);
    return e;
}

/* ─── BYTE DISTRIBUTION (for visualization) ───────────────────── */

/*
 * Fills out[256] with normalized byte frequencies (0.0–1.0)
 * Returns number of bytes sampled, or -1 on error
 */
long file_byte_distribution(const char *filepath, double *out) {
    int fd = open(filepath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;

    size_t max_read = 131072; /* 128KB */
    unsigned char *buf = (unsigned char *)malloc(max_read);
    if (!buf) { close(fd); return -1; }

    ssize_t n = read(fd, buf, max_read);
    close(fd);
    if (n <= 0) { free(buf); return 0; }

    size_t freq[256] = {0};
    for (ssize_t i = 0; i < n; i++) freq[buf[i]]++;
    free(buf);

    for (int i = 0; i < 256; i++)
        out[i] = (double)freq[i] / (double)n;

    return (long)n;
}

/* ─── /proc PROCESS INSPECTOR ────────────────────────────────── */

typedef struct {
    pid_t  pid;
    char   comm[64];
    char   exe[256];
    char   state;
    long   fd_count;
    long   vm_rss_kb;
} ProcInfo;

/*
 * Fills ProcInfo for a given PID from /proc
 * Returns 0 on success, -1 on failure
 */
int get_proc_info(pid_t pid, ProcInfo *info) {
    memset(info, 0, sizeof(*info));
    info->pid = pid;

    /* comm */
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(info->comm, sizeof(info->comm), f)) {
            size_t l = strlen(info->comm);
            if (l > 0 && info->comm[l-1] == '\n') info->comm[l-1] = '\0';
        }
        fclose(f);
    }

    /* exe symlink */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t r = readlink(path, info->exe, sizeof(info->exe)-1);
    if (r > 0) info->exe[r] = '\0';
    else strncpy(info->exe, "(unknown)", sizeof(info->exe));

    /* state + VmRSS from status */
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    f = fopen(path, "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "State:", 6) == 0)
                sscanf(line + 7, " %c", &info->state);
            else if (strncmp(line, "VmRSS:", 6) == 0)
                sscanf(line + 6, " %ld", &info->vm_rss_kb);
        }
        fclose(f);
    }

    /* fd count */
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    DIR *d = opendir(path);
    if (d) {
        long cnt = 0;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL)
            if (ent->d_name[0] != '.') cnt++;
        closedir(d);
        info->fd_count = cnt;
    }

    return 0;
}

/*
 * Find PID that most recently accessed a file path via /proc/PID/fd
 * Returns PID or -1 if not found. Expensive – use sparingly.
 */
pid_t find_pid_for_file(const char *filepath) {
    DIR *slash_proc = opendir("/proc");
    if (!slash_proc) return -1;

    char link_target[512];
    char fd_path[256];
    struct dirent *ent;
    pid_t found = -1;

    while ((ent = readdir(slash_proc)) != NULL) {
        /* Only numeric entries = PIDs */
        char *endp;
        long pid = strtol(ent->d_name, &endp, 10);
        if (*endp != '\0' || pid <= 0) continue;

        snprintf(fd_path, sizeof(fd_path), "/proc/%ld/fd", pid);
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;

        struct dirent *fd_ent;
        while ((fd_ent = readdir(fd_dir)) != NULL) {
            if (fd_ent->d_name[0] == '.') continue;
            char full_fd[512];
            snprintf(full_fd, sizeof(full_fd), "/proc/%ld/fd/%s", pid, fd_ent->d_name);
            ssize_t r = readlink(full_fd, link_target, sizeof(link_target)-1);
            if (r > 0) {
                link_target[r] = '\0';
                if (strcmp(link_target, filepath) == 0) {
                    found = (pid_t)pid;
                    closedir(fd_dir);
                    goto done;
                }
            }
        }
        closedir(fd_dir);
    }

done:
    closedir(slash_proc);
    return found;
}

/* ─── PROCESS KILL ────────────────────────────────────────────── */

/*
 * Send SIGKILL to pid. Returns 0 on success, -1 on error (check errno).
 * Caller must have appropriate privileges.
 */
int kill_process(pid_t pid) {
    return kill(pid, SIGKILL);
}

int suspend_process(pid_t pid) {
    return kill(pid, SIGSTOP);
}

int resume_process(pid_t pid) {
    return kill(pid, SIGCONT);
}

/* ─── FILE HASH (SHA-256 via /dev/stdin trick w/ kernel read) ─── */

/*
 * Simple non-cryptographic 64-bit hash for allow-listing (FNV-1a).
 * Use Python's hashlib for SHA-256; this is for fast C-side checks.
 */
uint64_t fnv1a_file(const char *filepath) {
    int fd = open(filepath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return 0;

    uint64_t hash = 14695981039346656037ULL;
    unsigned char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            hash ^= buf[i];
            hash *= 1099511628211ULL;
        }
    }
    close(fd);
    return hash;
}

/* ─── NETWORK CONNECTION READER via /proc/net/tcp ────────────── */

typedef struct {
    uint32_t local_addr;
    uint16_t local_port;
    uint32_t remote_addr;
    uint16_t remote_port;
    int      state;
    uint32_t inode;
} TcpConn;

/*
 * Reads /proc/net/tcp into conns[] array.
 * Returns number of connections read, or -1 on error.
 * max_conns = size of the conns[] buffer.
 */
int read_tcp_connections(TcpConn *conns, int max_conns) {
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return -1;

    char line[256];
    int count = 0;
    fgets(line, sizeof(line), f); /* skip header */

    while (fgets(line, sizeof(line), f) && count < max_conns) {
        unsigned int la, lp, ra, rp, st, inode;
        int r = sscanf(line,
            " %*d: %8X:%4X %8X:%4X %2X %*s %*s %*s %*s %*s %u",
            &la, &lp, &ra, &rp, &st, &inode);
        if (r == 6) {
            conns[count].local_addr  = la;
            conns[count].local_port  = lp;
            conns[count].remote_addr = ra;
            conns[count].remote_port = rp;
            conns[count].state       = st;
            conns[count].inode       = inode;
            count++;
        }
    }
    fclose(f);
    return count;
}
