/* hsp record: sample one GHC process into an HSPREC01 capture.
 *
 *   hsp record [-F hz] [-e event] [-d depth] [-t secs] [-r ring_mb] [--no-label]
 *              [--no-alloc] [--no-thunk] -o FILE (-p PID | -- program args...)
 *
 * The sampler itself is sampler.c; this writes its records to a file.
 * Needs CAP_BPF + CAP_PERFMON (root). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sampler.h"

static volatile sig_atomic_t stop_requested;
static void on_signal(int sig) { (void)sig; stop_requested = 1; }

static int die(const char *what)
{
    fprintf(stderr, "hsp record: %s: %s\n", what, strerror(errno));
    return 2;
}

struct sink { FILE *fp; uint64_t records, bytes; int failed; };

/* The target's executable mappings, as the capture header carries them
 * (hsp_abi.h): what `hsp fold' needs to name a pc in a shared library.
 * Snapshots are merged, so a library loaded during the capture is there
 * too.  Entries are packed into `buf' (HS_FILE_MAPS_ROOM bytes). */
struct maps { unsigned char *buf; uint32_t n, bytes, dropped; };

static int maps_has(const struct maps *m, const struct hs_file_map *e, const char *path)
{
    for (uint32_t off = 0, i = 0; i < m->n; i++) {
        const struct hs_file_map *x = (const struct hs_file_map *)(m->buf + off);
        if (x->start == e->start && x->end == e->end && x->offset == e->offset && x->path_len == e->path_len &&
            !memcmp(x + 1, path, e->path_len)) return 1;
        off += sizeof *x + ((x->path_len + 7) & ~7u);
    }
    return 0;
}

static int maps_snapshot(struct maps *m, pid_t pid, const char *exe)
{
    char path[64], line[PATH_MAX + 128], now[PATH_MAX];
    /* a spawned child is hsp's own image until it execs */
    snprintf(path, sizeof path, "/proc/%d/exe", pid);
    ssize_t len = readlink(path, now, sizeof now - 1);
    if (len < 0) return 0;
    now[len] = 0;
    if (strcmp(now, exe)) return 0;
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    while (fgets(line, sizeof line, fp)) {
        unsigned long lo, hi, off;
        char perms[8];
        int at = 0;
        if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %n", &lo, &hi, perms, &off, &at) < 4 || perms[2] != 'x') continue;
        char *name = line + at;
        name[strcspn(name, "\n")] = 0;
        struct hs_file_map e = { .start = lo, .end = hi, .offset = off, .path_len = strlen(name) };
        uint32_t need = sizeof e + ((e.path_len + 7) & ~7u);
        if (maps_has(m, &e, name)) continue;
        if (m->bytes + need > HS_FILE_MAPS_ROOM) { m->dropped++; continue; }
        memset(m->buf + m->bytes, 0, need);
        memcpy(m->buf + m->bytes, &e, sizeof e);
        memcpy(m->buf + m->bytes + sizeof e, name, e.path_len);
        m->bytes += need; m->n++;
    }
    fclose(fp);
    return 1;
}

/* The header and the mappings after it; the room is fixed, so they can be
 * rewritten in place when the capture ends. */
static int write_header(FILE *fp, struct hs_file_hdr *fh, const struct maps *m)
{
    fh->n_maps = m->n; fh->maps_bytes = m->bytes;
    if (fseek(fp, 0, SEEK_SET)) return -1;
    if (fwrite(fh, sizeof *fh, 1, fp) != 1) return -1;
    if (fwrite(m->buf, 1, HS_FILE_MAPS_ROOM, fp) != HS_FILE_MAPS_ROOM) return -1;
    return 0;
}

static int on_record(void *ctx, const struct hs_rec *r, size_t len)
{
    struct sink *s = ctx;
    if (!s->failed && fwrite(r, 1, len, s->fp) != len) s->failed = errno;
    s->records++;
    s->bytes += len;
    return 0;
}

static void usage(void)
{
    fputs("usage: hsp record [-F hz] [-e event] [-d depth] [-t secs] [-r ring_mb] [--no-label] [--no-alloc] [--no-thunk]\n"
          "                  [--no-task] [--text-only] -o FILE (-p PID | -- program args...)\n"
          "  -F hz        sample frequency per CPU (default 99)\n"
          "  -e event     what drives sampling: cpu-clock (default, works anywhere), cycles (needs a PMU),\n"
          "               ibs (AMD Instruction-Based Sampling: exact leaf addresses; needs the ibs_op PMU)\n"
          "  -d depth     max frames per sample (default 512, cap 1024)\n"
          "  -t secs      stop after this long (default: until the target exits / SIGINT)\n"
          "  -r mb        ring buffer MiB, power of two (default 8)\n"
          "  --no-label   do not read the green thread's label (rid:...)\n"
          "  --no-alloc   do not read the allocation counter\n"
          "  --no-thunk   do not name update frames' thunks by their creator (2 reads per update frame)\n"
          "  --no-task    do not identify the thread behind C code through the RTS's Task (r13 only)\n"
          "  --text-only  drop ticks whose pc is outside the executable (shared libraries, vdso)\n"
          "  -o FILE      the capture (HSPREC01); `hsp fold' reads it\n", stderr);
}

/* Resolve argv[0] like execvp would, so the ELF can be read before exec. */
static int resolve_exe(const char *arg, char *exe)
{
    if (strchr(arg, '/')) return realpath(arg, exe) ? 0 : -1;
    const char *p = getenv("PATH");
    char buf[PATH_MAX];
    for (const char *s = p ? p : ""; *s; ) {
        const char *e = strchrnul(s, ':');
        snprintf(buf, sizeof buf, "%.*s/%s", (int)(e - s), s, arg);
        if (access(buf, X_OK) == 0 && realpath(buf, exe)) return 0;
        s = *e ? e + 1 : e;
    }
    return -1;
}

/* ELF e_type at byte 16: 3 = ET_DYN (a PIE) */
static int is_pie(const char *exe)
{
    unsigned char id[18] = {0};
    FILE *f = fopen(exe, "rb");
    if (!f) return 0;
    size_t n = fread(id, 1, sizeof id, f);
    fclose(f);
    return n == sizeof id && id[16] == 3;
}

int cmd_record(int argc, char **argv)
{
    struct hs_sampler_opts o = { .freq_hz = 99, .max_depth = 512, .ring_mb = 8, .outside_text = 1 };
    double duration = 0;
    const char *out = NULL;
    pid_t pid = 0;
    char **cmd = NULL;
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) { cmd = argv + i + 1; break; }
        else if (!strcmp(a, "-F") && i + 1 < argc) o.freq_hz = atoi(argv[++i]);
        else if (!strcmp(a, "-e") && i + 1 < argc) o.event = argv[++i];
        else if (!strcmp(a, "-d") && i + 1 < argc) o.max_depth = atoi(argv[++i]);
        else if (!strcmp(a, "-t") && i + 1 < argc) duration = atof(argv[++i]);
        else if (!strcmp(a, "-r") && i + 1 < argc) o.ring_mb = atoi(argv[++i]);
        else if (!strcmp(a, "-p") && i + 1 < argc) pid = atoi(argv[++i]);
        else if (!strcmp(a, "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(a, "--no-label")) o.no_label = 1;
        else if (!strcmp(a, "--no-alloc")) o.no_alloc = 1;
        else if (!strcmp(a, "--no-thunk")) o.no_thunk = 1;
        else if (!strcmp(a, "--no-task")) o.no_task = 1;
        else if (!strcmp(a, "--text-only")) o.outside_text = 0;
        else { usage(); return 2; }
    }
    int spawn = cmd && *cmd;
    if (!out || (pid == 0) == (spawn == 0) || o.freq_hz == 0) { usage(); return 2; }

    /* spawn: the child waits on a pipe so the sampler is attached before
     * exec.  A non-PIE has fixed addresses: attach, then release.  A PIE's
     * load base is only known after exec: release, then attach (the attach
     * waits for the mapping); its startup goes unsampled. */
    char exe[PATH_MAX] = "";
    int gate[2] = {-1, -1};
    if (spawn) {
        if (resolve_exe(cmd[0], exe)) { fprintf(stderr, "hsp record: %s: not found\n", cmd[0]); return 2; }
        if (pipe2(gate, O_CLOEXEC)) return die("pipe");
        pid = fork();
        if (pid < 0) return die("fork");
        if (pid == 0) {
            char c;
            close(gate[1]);
            if (read(gate[0], &c, 1) != 1) _exit(127);
            execvp(cmd[0], cmd);
            perror("hsp record: exec"); _exit(127);
        }
        close(gate[0]);
        if (is_pie(exe)) {
            if (write(gate[1], "g", 1) != 1) return die("write gate");
            close(gate[1]); gate[1] = -1;
        }
    }

    struct sink sink = { .fp = fopen(out, "wb") };
    if (!sink.fp) return die(out);
    setvbuf(sink.fp, NULL, _IOFBF, 1 << 20);
    char err[512];
    struct hs_sampler *s = hs_sampler_attach(pid, spawn ? exe : NULL, &o, on_record, &sink, err, sizeof err);
    if (!s) { fprintf(stderr, "hsp record: %s\n", err); return 2; }
    const struct hs_sampler_info *in = hs_sampler_info(s);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    struct maps maps = { .buf = calloc(1, HS_FILE_MAPS_ROOM) };
    int have_maps = maps_snapshot(&maps, pid, in->exe);
    struct hs_file_hdr fh = {
        .version = 1, .hdr_size = sizeof fh + HS_FILE_MAPS_ROOM, .pid = pid, .freq_hz = in->freq_hz,
        .text_lo = in->text_lo, .text_hi = in->text_hi,
        .t0_ns = (uint64_t)t0.tv_sec * 1000000000ull + t0.tv_nsec,
    };
    memcpy(fh.magic, HS_FILE_MAGIC, 8);
    if (write_header(sink.fp, &fh, &maps)) return die(out);
    if (gate[1] >= 0) { if (write(gate[1], "g", 1) != 1) return die("write gate"); close(gate[1]); }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    fprintf(stderr, "hsp record: pid %d, %s, GHC %d.%d, %u Hz %s x %d CPUs, depth %u, text %#lx-%#lx -> %s\n",
            pid, in->exe, in->ghc_major, in->ghc_minor, in->freq_hz, in->event, in->cpus, in->max_depth,
            (unsigned long)in->text_lo, (unsigned long)in->text_hi, out);

    int child_status = 0;
    struct timespec maps_at = t0;
    for (;;) {
        if (hs_sampler_poll(s, 100) < 0) break;
        /* the mappings again every second: the target may exit before the
         * capture ends, and libraries come and go */
        struct timespec tn;
        clock_gettime(CLOCK_MONOTONIC, &tn);
        if (!have_maps || tn.tv_sec > maps_at.tv_sec) {
            if (maps_snapshot(&maps, pid, in->exe)) have_maps = 1;
            maps_at = tn;
        }
        if (stop_requested || sink.failed) break;
        if (spawn) {
            if (waitpid(pid, &child_status, WNOHANG) == pid) break;
        } else if (!hs_sampler_alive(s)) {
            break;
        }
        if (duration > 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if ((now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9 >= duration) break;
        }
    }
    hs_sampler_poll(s, 0);
    maps_snapshot(&maps, pid, in->exe);
    if (!sink.failed && write_header(sink.fp, &fh, &maps)) sink.failed = errno;
    if (maps.dropped) fprintf(stderr, "hsp record: %u executable mappings did not fit in the capture header\n", maps.dropped);
    if (fclose(sink.fp) != 0 && !sink.failed) sink.failed = errno;
    if (spawn && !WIFEXITED(child_status) && !WIFSIGNALED(child_status)) {
        kill(pid, SIGTERM);
        waitpid(pid, &child_status, 0);
    }
    uint64_t st[HS_ST_COUNT];
    hs_sampler_stats(s, st);
    fprintf(stderr,
            "hsp record: records=%lu bytes=%lu | ticks=%lu outside_text=%lu kernel=%lu tso=%lu "
            "walked=%lu stop=%lu broken=%lu truncated=%lu dropped=%lu | via_task=%lu (safe=%lu) gc=%lu "
            "stale_r13=%lu no_task_route=%lu task_route=%s\n",
            (unsigned long)sink.records, (unsigned long)sink.bytes,
            (unsigned long)st[HS_ST_TICKS], (unsigned long)st[HS_ST_OUTSIDE_TEXT], (unsigned long)st[HS_ST_KERNEL],
            (unsigned long)st[HS_ST_TSO], (unsigned long)st[HS_ST_WALKED], (unsigned long)st[HS_ST_STOP],
            (unsigned long)st[HS_ST_BROKEN], (unsigned long)st[HS_ST_TRUNCATED], (unsigned long)st[HS_ST_DROPPED],
            (unsigned long)st[HS_ST_VIA_TASK], (unsigned long)st[HS_ST_SAFE], (unsigned long)st[HS_ST_GC],
            (unsigned long)st[HS_ST_STALE_R13], (unsigned long)st[HS_ST_NO_TASK_ROUTE],
            in->task_route > 0 ? "on" : in->task_route < 0 ? "off" : "undecided");
    hs_sampler_close(s);
    if (sink.failed) { errno = sink.failed; return die(out); }
    return spawn && WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 0;
}
