/* The sampler library (sampler.h): ELF facts, load base, BPF load, perf
 * events, ring buffer.  C: the bpftool skeleton is a C header. */
#define _GNU_SOURCE
#include "sampler.h"

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
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "hsp.skel.h"

struct hs_sampler {
    struct hs_sampler_info info;
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
};

/* The GHC version the binary was built with: the RTS info table (what
 * `+RTS --info' prints) keeps it in .rodata as a bare "9.x.y" string. */
static void find_ghc_version(const unsigned char *m, const Elf64_Ehdr *eh, struct elf_facts *f)
{
    const Elf64_Shdr *sh = (const Elf64_Shdr *)(m + eh->e_shoff);
    const char *names = (const char *)(m + sh[eh->e_shstrndx].sh_offset);
    for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type != SHT_PROGBITS || strncmp(names + sh[i].sh_name, ".rodata", 7)) continue;
        const char *p = (const char *)(m + sh[i].sh_offset), *end = p + sh[i].sh_size;
        for (const char *q = p; q + 8 < end; q++) {
            if (q[0] != '9' || q[1] != '.') continue;
            if (q > p && q[-1] != 0) continue;
            int a, b, c;
            if (sscanf(q, "%d.%d.%d", &a, &b, &c) == 3 && a == 9 && b < 20) {
                const char *z = q; while (z < end && *z) z++;
                if (z - q <= 8) { f->ghc_major = a; f->ghc_minor = b; return; }
            }
        }
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
        for (size_t k = 0; k < n; k++)
            if (!strcmp(str + sym[k].st_name, "stg_TSO_info")) { f->stg_tso_info = sym[k].st_value; break; }
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

static int perf_open_cpu(int cpu, unsigned freq)
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE, .size = sizeof attr, .config = PERF_COUNT_SW_CPU_CLOCK,
        .sample_freq = freq, .freq = 1,
    };
    return syscall(SYS_perf_event_open, &attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
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
    bpf_map__set_max_entries(s->skel->maps.rb, (size_t)(o->ring_mb ? o->ring_mb : 8) << 20);
    if (hsp_bpf__load(s->skel)) {
        seterr(err, errlen, "BPF load failed (verifier log above; root or CAP_BPF+CAP_PERFMON needed)%s%s", "", "");
        hsp_bpf__destroy(s->skel); free(s); return NULL;
    }
    int ncpu = sysconf(_SC_NPROCESSORS_CONF);
    s->links = calloc(ncpu, sizeof *s->links);
    s->nlinks = ncpu;
    for (int cpu = 0; cpu < ncpu; cpu++) {
        int fd = perf_open_cpu(cpu, s->info.freq_hz);
        if (fd < 0) {
            if (errno == ENODEV) continue;                    /* offline CPU */
            seterr(err, errlen, "perf_event_open: %s (CAP_PERFMON / perf_event_paranoid?)%s", strerror(errno), "");
            hs_sampler_close(s); return NULL;
        }
        s->links[cpu] = bpf_program__attach_perf_event(s->skel->progs.hsp_sample, fd);
        if (!s->links[cpu]) { seterr(err, errlen, "attach_perf_event: %s%s", strerror(errno), ""); hs_sampler_close(s); return NULL; }
        s->info.cpus++;
    }
    s->rb = ring_buffer__new(bpf_map__fd(s->skel->maps.rb), on_record, s, NULL);
    if (!s->rb) { seterr(err, errlen, "ring_buffer__new: %s%s", strerror(errno), ""); hs_sampler_close(s); return NULL; }
    return s;
}

const struct hs_sampler_info *hs_sampler_info(const struct hs_sampler *s) { return &s->info; }

int hs_sampler_poll(struct hs_sampler *s, int timeout_ms)
{
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
