/* The sampler library (sampler.h): ELF facts, load base, BPF load, perf
 * events, ring buffer.  C: the bpftool skeleton is a C header. */
#define _GNU_SOURCE
#include "sampler.h"
#include "ghcver.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "hsp.skel.h"

/* What the Task route needs from the ELF (addresses unrelocated). */
struct task_syms {
    int have_tls_sym;            /* my_task is a TLS symbol */
    uint64_t my_task;            /* its offset in the TLS segment */
    uint64_t tls_vaddr, tls_memsz, tls_align;   /* PT_TLS; align 0 = none */
    uint64_t all_tasks, capabilities, capabilities_size, n_capabilities, gc_threads;
};

struct hs_sampler {
    struct hs_sampler_info info;
    struct task_syms ts;
    uint64_t base;               /* load base (0 for a non-PIE) */
    uint64_t stg_tso_info;       /* relocated */
    int task_tries, task_bad, task_none;
    struct timespec task_next;
    struct hsp_bpf *skel;
    struct ring_buffer *rb;
    struct bpf_link **links;
    int nlinks;
    hs_sampler_cb cb;
    void *ctx;
    int cb_rc;
};

static void seterr(char *err, size_t n, const char *fmt, const char *a, const char *b)
{
    if (err && n) snprintf(err, n, fmt, a, b);
}

/* ---- ELF: text range, stg_TSO_info, GHC version ------------------------- */

struct elf_facts {
    int is_dyn;
    uint64_t text_lo, text_hi;
    uint64_t stg_tso_info;
    int ghc_major, ghc_minor;
    struct task_syms ts;
};

/* The version string lives in .rodata; src/ghcver.h does the scanning, and
 * `hsp symmap' reads it the same way. */
static void find_ghc_version(const unsigned char *m, const Elf64_Ehdr *eh, struct elf_facts *f)
{
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(m + eh->e_shoff);
    const char *names = (const char *)(m + sh[eh->e_shstrndx].sh_offset);
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_PROGBITS || strncmp(names + sh[i].sh_name, ".rodata", 7)) continue;
        const char *p = (const char *)(m + sh[i].sh_offset);
        if (ghcver_find(p, p + sh[i].sh_size, &f->ghc_major, &f->ghc_minor)) return;
    }
}

static int read_elf(const char *path, struct elf_facts *f, uint64_t *size, char *err, size_t errlen)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { seterr(err, errlen, "%s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st)) { close(fd); seterr(err, errlen, "%s: %s", path, strerror(errno)); return -1; }
    *size = st.st_size;
    unsigned char *m = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { seterr(err, errlen, "%s: mmap failed%s", path, ""); return -1; }
    memset(f, 0, sizeof *f);
    f->text_lo = UINT64_MAX;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)m;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_X86_64) {
        seterr(err, errlen, "%s is not an x86-64 ELF64 file%s", path, ""); munmap(m, st.st_size); return -1;
    }
    f->is_dyn = eh->e_type == ET_DYN;
    Elf64_Phdr *ph = (Elf64_Phdr *)(m + eh->e_phoff);
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_TLS) {
            f->ts.tls_vaddr = ph[i].p_vaddr; f->ts.tls_memsz = ph[i].p_memsz;
            f->ts.tls_align = ph[i].p_align ? ph[i].p_align : 1;
        }
        if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X)) continue;
        if (ph[i].p_vaddr < f->text_lo) f->text_lo = ph[i].p_vaddr;
        if (ph[i].p_vaddr + ph[i].p_memsz > f->text_hi) f->text_hi = ph[i].p_vaddr + ph[i].p_memsz;
    }
    Elf64_Shdr *sh = (Elf64_Shdr *)(m + eh->e_shoff);
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_SYMTAB) continue;
        Elf64_Sym *sym = (Elf64_Sym *)(m + sh[i].sh_offset);
        const char *str = (const char *)(m + sh[sh[i].sh_link].sh_offset);
        size_t n = sh[i].sh_size / sizeof(Elf64_Sym);
        for (size_t k = 0; k < n; k++) {
            const char *nm = str + sym[k].st_name;
            switch (nm[0]) {            /* millions of symbols: most fail on the first byte */
            case 's': if (!strcmp(nm, "stg_TSO_info")) f->stg_tso_info = sym[k].st_value; break;
            case 'm':
                if (!strcmp(nm, "my_task")) {
                    f->ts.have_tls_sym = ELF64_ST_TYPE(sym[k].st_info) == STT_TLS;
                    f->ts.my_task = sym[k].st_value;
                }
                break;
            case 'a': if (!strcmp(nm, "all_tasks")) f->ts.all_tasks = sym[k].st_value; break;
            case 'c':
                if (!strcmp(nm, "capabilities")) { f->ts.capabilities = sym[k].st_value; f->ts.capabilities_size = sym[k].st_size; }
                break;
            case 'n': if (!strcmp(nm, "n_capabilities")) f->ts.n_capabilities = sym[k].st_value; break;
            case 'g': if (!strcmp(nm, "gc_threads")) f->ts.gc_threads = sym[k].st_value; break;
            }
        }
    }
    find_ghc_version(m, eh, f);
    munmap(m, st.st_size);
    if (f->text_lo == UINT64_MAX) { seterr(err, errlen, "%s has no executable PT_LOAD segment%s", path, ""); return -1; }
    if (!f->stg_tso_info) {
        seterr(err, errlen, "%s: stg_TSO_info not in .symtab (stripped, or not a GHC program?)%s", path, ""); return -1;
    }
    return 0;
}

/* Load base of `exe' in `pid' (its mapping at file offset 0), for PIEs. */
static int load_base(pid_t pid, const char *exe, uint64_t *base)
{
    char path[64], line[PATH_MAX + 128];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    int rc = -1;
    while (fgets(line, sizeof line, fp)) {
        unsigned long lo, hi, off, inode;
        char perms[8], dev[16], mapped[PATH_MAX] = "";
        if (sscanf(line, "%lx-%lx %7s %lx %15s %lu %s", &lo, &hi, perms, &off, dev, &inode, mapped) < 7) continue;
        if (off == 0 && !strcmp(mapped, exe)) { *base = lo; rc = 0; break; }
    }
    fclose(fp);
    return rc;
}

/* ---- the Task route: offsets, and their proof on the live process -------- */

static int rd(pid_t pid, uint64_t addr, void *buf, size_t n)
{
    struct iovec l = { buf, n }, r = { (void *)(uintptr_t)addr, n };
    return process_vm_readv(pid, &l, 1, &r, 1, 0) == (ssize_t)n ? 0 : -1;
}
static int rd64(pid_t pid, uint64_t addr, uint64_t *v) { return rd(pid, addr, v, 8); }

/* my_task's address relative to the thread pointer (fs base).  x86-64 is TLS
 * variant II: the executable's TLS block ends at the thread pointer, at an
 * offset rounded for its alignment (glibc's _dl_determine_tlsoffset; musl
 * computes the same for the main program). */
static int64_t tls_offset_of(const struct task_syms *t)
{
    uint64_t align = t->tls_align, first = (0 - (t->tls_vaddr & (align - 1))) & (align - 1);
    uint64_t block = (t->tls_memsz - first + align - 1) / align * align + first;
    return (int64_t)t->my_task - (int64_t)block;
}

enum { TASK_NOT_YET = 0, TASK_OK = 1, TASK_BAD = -1, TASK_NONE = -2 };

/* Follow, from outside, the chain the BPF program will follow, for every
 * Task the RTS has (all_tasks), with the offsets in `c':
 *
 *   *(task->id + tls_my_task) == task      the TLS slot, and that a pthread_t
 *                                          is the fs base
 *   capabilities[task->cap->no] == task->cap
 *   task->incall->task == task
 *   task->incall->suspended_tso            NULL or a TSO, and set exactly when
 *                                          suspended_cap is (a capability)
 *   cap->running_task                      NULL or a Task (its incall->task is it)
 *   cap->in_haskell                        0 or 1; 1 implies a running_task and
 *                                          that rCurrentTSO is a TSO
 *   gc_threads[cap->no]->cap == cap
 *
 * The process is running, so one pass can catch a structure mid-update: the
 * caller retries a BAD verdict a few times.  NOT_YET: no Task exists (the
 * RTS has not started).  NONE: Tasks exist but not one has a thread-local
 * slot and a capability where these offsets put them.  `why' gets the first
 * contradiction. */
static int task_check(struct hs_sampler *s, const struct hs_task_cfg *c, int *ntasks, char *why, size_t whylen)
{
    pid_t pid = s->info.pid;
    uint64_t b = s->base, task = 0, caps = s->ts.capabilities + b;
    uint32_t ncap = 0;
    int ok = 0, seen = 0;
#define BAD(...) do { snprintf(why, whylen, __VA_ARGS__); return TASK_BAD; } while (0)
    char link[64], exe[sizeof s->info.exe];
    ssize_t len;
    *ntasks = 0;
    /* a spawned child is still hsp's own image until it execs */
    snprintf(link, sizeof link, "/proc/%d/exe", pid);
    if ((len = readlink(link, exe, sizeof exe - 1)) < 0) return TASK_NOT_YET;
    exe[len] = 0;
    if (strcmp(exe, s->info.exe)) return TASK_NOT_YET;
    if (rd64(pid, s->ts.all_tasks + b, &task)) {
        if (errno == EPERM) BAD("cannot read the target's memory (CAP_SYS_PTRACE)%s", "");
        return TASK_NOT_YET;
    }
    if (!task) return TASK_NOT_YET;
    if (rd(pid, s->ts.n_capabilities + b, &ncap, 4) || ncap == 0 || ncap > 4096) return TASK_NOT_YET;
    /* `capabilities' is an array of pointers in some releases and a pointer
     * to one in others; the symbol's size says which */
    if (s->ts.capabilities_size == 8 && (rd64(pid, caps, &caps) || !caps)) return TASK_NOT_YET;
    for (int i = 0; task && i < 4096; i++) {
        uint64_t id = 0, slot = 0, cap = 0, incall = 0, it = 0, susp = 0, hdr = 0, at = 0, run = 0, next = 0;
        uint32_t no = 0;
        uint8_t in_haskell = 0;
        if (rd64(pid, task + HS_DEF_OFF_TASK_ID, &id)) BAD("Task %#lx is unreadable", (unsigned long)task);
        if (rd64(pid, task + HS_DEF_OFF_TASK_ALL_NEXT, &next)) next = 0;
        rd64(pid, task + c->off_task_cap, &cap);
        seen++;
        /* a Task being set up has no OS thread or capability yet; one whose
         * OS thread has gone has an id nothing is mapped at */
        if (id && cap && rd64(pid, id + c->tls_my_task, &slot) == 0) {
            if (slot != task) BAD("my_task of thread %#lx is %#lx, not its Task %#lx", (unsigned long)id, (unsigned long)slot, (unsigned long)task);
            if (rd(pid, cap + c->off_cap_no, &no, 4) || no >= ncap || rd64(pid, caps + 8ull * no, &at) || at != cap)
                BAD("Task.cap %#lx is not capabilities[%u]", (unsigned long)cap, no);
            if (rd64(pid, task + c->off_task_incall, &incall)) BAD("Task.incall is unreadable%s", "");
            if (incall) {
                if (rd64(pid, incall + HS_DEF_OFF_INCALL_TASK, &it) || it != task) BAD("Task.incall->task is not the Task%s", "");
                if (rd64(pid, incall + c->off_incall_susp_tso, &susp)) BAD("InCall.suspended_tso is unreadable%s", "");
                if (susp && (rd64(pid, susp, &hdr) || hdr != s->stg_tso_info)) BAD("InCall.suspended_tso %#lx is not a TSO", (unsigned long)susp);
                uint64_t scap = 0, sat = 0;
                uint32_t sno = 0;
                if (rd64(pid, incall + HS_DEF_OFF_INCALL_SUSP_CAP, &scap) || !scap != !susp)
                    BAD("InCall.suspended_tso and suspended_cap are not set together%s", "");
                if (scap && (rd(pid, scap + c->off_cap_no, &sno, 4) || sno >= ncap || rd64(pid, caps + 8ull * sno, &sat) || sat != scap))
                    BAD("InCall.suspended_cap %#lx is not a capability", (unsigned long)scap);
            }
            if (rd64(pid, cap + c->off_cap_running_task, &run)) BAD("Capability.running_task is unreadable%s", "");
            if (run && run != task) {
                uint64_t ri = 0, rt = 0;
                if (rd64(pid, run + c->off_task_incall, &ri) || !ri || rd64(pid, ri + HS_DEF_OFF_INCALL_TASK, &rt) || rt != run)
                    BAD("Capability.running_task %#lx is not a Task", (unsigned long)run);
            }
            if (rd(pid, cap + c->off_cap_in_haskell, &in_haskell, 1) || in_haskell > 1) BAD("Capability.in_haskell is %u", in_haskell);
            /* the scheduler sets rCurrentTSO and in_haskell around running a
             * thread and clears both after (a few instructions apart) */
            uint64_t cur = 0;
            int cur_tso = rd64(pid, cap + c->off_cap_r + s->skel->rodata->cfg.off_curtso, &cur) == 0 && cur &&
                          rd64(pid, cur, &hdr) == 0 && hdr == s->stg_tso_info;
            if (in_haskell && !run) BAD("in_haskell set on capability %u without a running_task", no);
            if (in_haskell && !cur_tso) BAD("in_haskell set on capability %u without a current TSO", no);
            if (!in_haskell && cur_tso) BAD("capability %u has a current TSO but in_haskell is not set", no);
            if (c->gc_threads) {
                uint64_t arr = 0, g = 0, gcap = 0;
                if (rd64(pid, c->gc_threads, &arr) == 0 && arr &&
                    (rd64(pid, arr + 8ull * no, &g) || !g || rd64(pid, g + HS_OFF_GCTHREAD_CAP, &gcap) || gcap != cap))
                    BAD("gc_threads[%u] does not belong to its capability", no);
            }
            ok++;
        }
        task = next;
    }
#undef BAD
    *ntasks = ok;
    if (!ok) snprintf(why, whylen, "none of the RTS's %d Tasks has a thread-local slot and a capability at the expected offsets", seen);
    return ok ? TASK_OK : TASK_NONE;
}

static void task_off(struct hs_sampler *s, const char *why)
{
    s->info.task_route = -1;
    fprintf(stderr, "hsp: threads in C code are not identified (as before this route existed): %s\n", why);
}

/* Try to switch the Task route on.  Called at attach and from the poll loop:
 * a spawned program has no RTS yet when the sampler attaches.  Once on, the
 * check is repeated every second (a state the first pass did not meet, such
 * as a capability in Haskell code, may contradict the layout later) and the
 * route is switched off for good if it stops holding. */
static void task_route_try(struct hs_sampler *s)
{
    struct timespec now;
    char why[256] = "";
    if (s->info.task_route < 0) return;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec < s->task_next.tv_sec || (now.tv_sec == s->task_next.tv_sec && now.tv_nsec < s->task_next.tv_nsec)) return;
    s->task_next = now;
    s->task_next.tv_nsec += 5 * 1000000;
    if (s->task_next.tv_nsec >= 1000000000) { s->task_next.tv_sec++; s->task_next.tv_nsec -= 1000000000; }

    struct hs_task_cfg c = {
        .off_task_cap = HS_DEF_OFF_TASK_CAP, .off_task_incall = HS_DEF_OFF_TASK_INCALL,
        .off_incall_susp_tso = HS_DEF_OFF_INCALL_SUSP_TSO,
        .off_cap_r = HS_DEF_OFF_CAP_R, .off_cap_no = HS_DEF_OFF_CAP_NO,
        .off_cap_running_task = HS_DEF_OFF_CAP_RUNNING_TASK, .off_cap_in_haskell = HS_DEF_OFF_CAP_IN_HASKELL,
        .tls_my_task = tls_offset_of(&s->ts),
        .gc_threads = s->ts.gc_threads ? s->ts.gc_threads + s->base : 0,
    };
    int n = 0, rc = task_check(s, &c, &n, why, sizeof why);
    volatile struct hs_task_cfg *t = (volatile struct hs_task_cfg *)&s->skel->bss->tcfg;
    s->task_tries++;
    if (rc == TASK_OK) {
        s->task_bad = s->task_none = 0;
        if (s->info.task_route == 1) {       /* in use: look again in a second */
            s->task_next = now;
            s->task_next.tv_sec++;
            return;
        }
        t->off_task_cap = c.off_task_cap; t->off_task_incall = c.off_task_incall;
        t->off_incall_susp_tso = c.off_incall_susp_tso;
        t->off_cap_r = c.off_cap_r; t->off_cap_no = c.off_cap_no;
        t->off_cap_running_task = c.off_cap_running_task; t->off_cap_in_haskell = c.off_cap_in_haskell;
        t->tls_my_task = c.tls_my_task; t->gc_threads = c.gc_threads;
        __sync_synchronize();
        t->enabled = 1;
        s->info.task_route = 1;
    } else if (rc == TASK_BAD) {
        /* a running process can show one inconsistent pass; ten in a row is the layout */
        if (++s->task_bad >= 10) {
            char msg[400];
            t->enabled = 0;
            snprintf(msg, sizeof msg, "the RTS's Task/Capability layout is not the expected one (%s)", why);
            task_off(s, msg);
        }
    } else if (rc == TASK_NONE) {
        /* Tasks without a capability exist for a moment while the RTS starts; not for a second */
        if (++s->task_none >= 200) { t->enabled = 0; task_off(s, why); }
    } else if (s->info.task_route == 0 && s->task_tries >= 6000) {
        task_off(s, "no Task of the RTS could be checked in 30 s");
    }
}

static int pmu_type(const char *pmu)
{
    char path[128]; int t = -1;
    snprintf(path, sizeof path, "/sys/bus/event_source/devices/%s/type", pmu);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (fscanf(fp, "%d", &t) != 1) t = -1;
    fclose(fp);
    return t;
}

/* Which event drives the sampling.  All three are opened in frequency mode,
 * so -F means the same thing and a sample is still ~1/freq s of CPU.
 *
 *   cpu-clock  an hrtimer.  Works everywhere, including a guest with no PMU,
 *              but the IP is wherever the timer interrupt happened to land.
 *   cycles     the CPU's cycle counter.  Needs a (virtual) PMU.
 *   ibs        AMD Instruction-Based Sampling, op sampling counting cycles
 *              (config 0: IbsOpCntCtl clear).  The kernel replaces the
 *              interrupt IP with the tagged op's own address, so the leaf is
 *              exact rather than skidded.  The other registers are still the
 *              interrupt's, a few instructions later, so a sample whose stack
 *              pointer has already moved to another TSO fails the walk and is
 *              counted as broken rather than misattributed.  Needs the ibs_op
 *              PMU: bare metal, or a guest the host passes IBS through to.
 */
static int perf_attr_for(const char *ev, unsigned freq, struct perf_event_attr *attr,
                         char *err, size_t errlen)
{
    memset(attr, 0, sizeof *attr);
    attr->size = sizeof *attr;
    attr->sample_freq = freq;
    attr->freq = 1;
    if (!ev || !strcmp(ev, "cpu-clock")) {
        attr->type = PERF_TYPE_SOFTWARE; attr->config = PERF_COUNT_SW_CPU_CLOCK;
    } else if (!strcmp(ev, "cycles")) {
        attr->type = PERF_TYPE_HARDWARE; attr->config = PERF_COUNT_HW_CPU_CYCLES;
    } else if (!strcmp(ev, "ibs")) {
        int t = pmu_type("ibs_op");
        if (t < 0) {
            seterr(err, errlen, "-e ibs: no ibs_op PMU here (AMD only; in a VM the host must pass IBS through)%s%s", "", "");
            return -1;
        }
        attr->type = t; attr->config = 0;
    } else {
        seterr(err, errlen, "-e %s: unknown event (cpu-clock, cycles, ibs)%s", ev, "");
        return -1;
    }
    return 0;
}

static int perf_open_cpu(int cpu, const struct perf_event_attr *attr)
{
    struct perf_event_attr a = *attr;
    return syscall(SYS_perf_event_open, &a, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
}

static int on_record(void *ctx, void *data, size_t len)
{
    struct hs_sampler *s = ctx;
    if (s->cb_rc == 0) s->cb_rc = s->cb(s->ctx, data, len);
    return 0;
}

struct hs_sampler *hs_sampler_attach(pid_t pid, const char *exe, const struct hs_sampler_opts *o,
                                     hs_sampler_cb cb, void *ctx, char *err, size_t errlen)
{
    struct hs_sampler *s = calloc(1, sizeof *s);
    s->cb = cb; s->ctx = ctx;
    s->info.pid = pid;
    s->info.freq_hz = o->freq_hz ? o->freq_hz : 99;
    struct perf_event_attr attr;
    if (perf_attr_for(o->event, s->info.freq_hz, &attr, err, errlen)) { free(s); return NULL; }
    snprintf(s->info.event, sizeof s->info.event, "%s", o->event ? o->event : "cpu-clock");
    s->info.max_depth = o->max_depth && o->max_depth <= HS_MAX_DEPTH ? o->max_depth : 512;
    if (exe) {
        snprintf(s->info.exe, sizeof s->info.exe, "%s", exe);
    } else {
        char link[64]; ssize_t n;
        snprintf(link, sizeof link, "/proc/%d/exe", pid);
        if ((n = readlink(link, s->info.exe, sizeof s->info.exe - 1)) < 0) {
            seterr(err, errlen, "%s: %s", link, strerror(errno)); free(s); return NULL;
        }
        s->info.exe[n] = 0;
    }
    struct elf_facts ef;
    if (read_elf(s->info.exe, &ef, &s->info.exe_size, err, errlen)) { free(s); return NULL; }
    s->info.ghc_major = ef.ghc_major; s->info.ghc_minor = ef.ghc_minor;
    uint64_t base = 0;
    if (ef.is_dyn) {
        int i;
        for (i = 0; i < 200 && load_base(pid, s->info.exe, &base); i++) usleep(10000);
        if (!base) { seterr(err, errlen, "PIE load base of %s not found in /proc/%d/maps", s->info.exe, ""); free(s); return NULL; }
    }
    s->info.text_lo = ef.text_lo + base; s->info.text_hi = ef.text_hi + base;
    s->ts = ef.ts; s->base = base; s->stg_tso_info = ef.stg_tso_info + base;

    s->skel = hsp_bpf__open();
    if (!s->skel) { seterr(err, errlen, "hsp_bpf__open failed%s%s", "", ""); free(s); return NULL; }
    struct hs_cfg *c = (struct hs_cfg *)&s->skel->rodata->cfg;
    c->tgid = pid;
    c->max_depth = s->info.max_depth;
    c->text_lo = s->info.text_lo; c->text_hi = s->info.text_hi;
    c->stg_tso_info = ef.stg_tso_info + base;
    c->off_curtso = HS_DEF_OFF_REGTABLE_CURTSO;
    c->off_nursery = HS_DEF_OFF_REGTABLE_NURSERY;
    c->off_stackobj = HS_DEF_OFF_TSO_STACKOBJ;
    /* StgTSO field offsets (8-byte header included) differ by GHC version;
     * from each compiler's DerivedConstants.h:
     *   9.2.8   id 40  (no label field)   alloc_limit 96   -> 48 / -  / 104
     *   9.8.4   id 40  label 80           alloc_limit 104  -> 48 / 88 / 112
     *   9.10.3  id 48  label 88           alloc_limit 112  -> 56 / 96 / 120
     * Register table, stackobj and the stack chunk are the same in all three.
     * Thread labels live in the TSO only since 9.6 (threadLabel): a 9.2
     * program is sampled without them. */
    int has_label = 1;
    if (ef.ghc_major == 9 && ef.ghc_minor == 2) {
        c->off_id = 48; c->off_label = 0; c->off_alloc_limit = 104; has_label = 0;
    } else if (ef.ghc_major == 9 && ef.ghc_minor == 8) {
        c->off_id = 48; c->off_label = 88; c->off_alloc_limit = 112;
    } else if (ef.ghc_major == 9 && ef.ghc_minor == 10) {
        c->off_id = 56; c->off_label = 96; c->off_alloc_limit = 120;
    } else {
        c->off_id = HS_DEF_OFF_TSO_ID; c->off_label = HS_DEF_OFF_TSO_LABEL; c->off_alloc_limit = HS_DEF_OFF_TSO_ALLOC_LIMIT;
        fprintf(stderr, "hsp: GHC version %s in %s; using 9.8 thread-object offsets (labels/ids/allocation may be wrong)\n",
                ef.ghc_major ? "not 9.2/9.8/9.10" : "not found", s->info.exe);
    }
    if (!has_label && !o->no_label)
        fprintf(stderr, "hsp: GHC %d.%d keeps no thread label in the TSO (added in 9.6): sampling without labels\n", ef.ghc_major, ef.ghc_minor);
    c->want_label = has_label && !o->no_label; c->want_alloc = !o->no_alloc; c->want_thunk = !o->no_thunk;
    c->want_outside = o->outside_text;
    bpf_map__set_max_entries(s->skel->maps.rb, (size_t)(o->ring_mb ? o->ring_mb : 8) << 20);
    if (hsp_bpf__load(s->skel)) {
        seterr(err, errlen, "BPF load failed (verifier log above; root or CAP_BPF+CAP_PERFMON needed)%s%s", "", "");
        hsp_bpf__destroy(s->skel); free(s); return NULL;
    }
    int ncpu = sysconf(_SC_NPROCESSORS_CONF);
    s->links = calloc(ncpu, sizeof *s->links);
    s->nlinks = ncpu;
    for (int cpu = 0; cpu < ncpu; cpu++) {
        int fd = perf_open_cpu(cpu, &attr);
        if (fd < 0) {
            /* ENODEV is an offline CPU for cpu-clock, but for a hardware event
             * it is also "this machine has no such counter" on every CPU */
            if (errno == ENODEV && attr.type == PERF_TYPE_SOFTWARE) continue;
            if (errno == ENODEV && cpu > 0 && s->info.cpus > 0) continue;
            seterr(err, errlen, "perf_event_open (%s): %s (no such counter here, or CAP_PERFMON / perf_event_paranoid?)", s->info.event, strerror(errno));
            hs_sampler_close(s); return NULL;
        }
        s->links[cpu] = bpf_program__attach_perf_event(s->skel->progs.hsp_sample, fd);
        if (!s->links[cpu]) { seterr(err, errlen, "attach_perf_event: %s%s", strerror(errno), ""); hs_sampler_close(s); return NULL; }
        s->info.cpus++;
    }
    s->rb = ring_buffer__new(bpf_map__fd(s->skel->maps.rb), on_record, s, NULL);
    if (!s->rb) { seterr(err, errlen, "ring_buffer__new: %s%s", strerror(errno), ""); hs_sampler_close(s); return NULL; }

    /* threads in C code: needs the threaded RTS's per-OS-thread Task */
    if (o->no_task)
        s->info.task_route = -1;
    else if (!s->ts.have_tls_sym || !s->ts.tls_align)
        task_off(s, s->ts.my_task || s->ts.all_tasks ? "my_task is not thread-local (non-threaded RTS)" : "no my_task symbol (the RTS is not in this executable?)");
    else if (!s->ts.all_tasks || !s->ts.capabilities || !s->ts.n_capabilities)
        task_off(s, "all_tasks / capabilities / n_capabilities not in .symtab");
    else
        task_route_try(s);
    return s;
}

const struct hs_sampler_info *hs_sampler_info(const struct hs_sampler *s) { return &s->info; }

int hs_sampler_poll(struct hs_sampler *s, int timeout_ms)
{
    task_route_try(s);
    int n = ring_buffer__poll(s->rb, timeout_ms);
    if (n < 0 && errno == EINTR) return 0;
    return s->cb_rc ? -1 : n;
}

int hs_sampler_alive(const struct hs_sampler *s)
{
    return !(kill(s->info.pid, 0) && errno == ESRCH);
}

void hs_sampler_stats(const struct hs_sampler *s, uint64_t out[HS_ST_COUNT])
{
    for (int i = 0; i < HS_ST_COUNT; i++) out[i] = s->skel->bss->stats[i];
}

void hs_sampler_close(struct hs_sampler *s)
{
    if (!s) return;
    if (s->rb) { ring_buffer__consume(s->rb); ring_buffer__free(s->rb); }
    for (int i = 0; i < s->nlinks; i++) if (s->links[i]) bpf_link__destroy(s->links[i]);
    free(s->links);
    if (s->skel) hsp_bpf__destroy(s->skel);
    free(s);
}
