// hsp symmap: the name map straight from the binary.  The rules are the
// ones the earlier Python prototype settled on (its docstrings explain
// each; the comments here say where a step comes from).
//
//   hsp symmap BIN OUT.hsm [--eventlog FILE] [--no-dwarf] [--user-packages a,b]
//
// Tiers, joined by address:
//   symtab  every defined ELF symbol (what `nm --defined-only -S` lists),
//           Z-decoded into package/module/name;
//   IPE     -finfo-table-map entries, read from the binary's static
//           IpeBufferListNodes (GHC 9.8 layout; `_ipe_buf' symbols) or, with
//           --eventlog, from an eventlog written by `+RTS -l' (any GHC);
//   DWARF   .debug_line rows (libdw), for resolve_leaf.
// The .mix tier (flow-trace builds) is not ported: it needs hpc sidecars.
#include <elf.h>
#include <elfutils/libdw.h>
#include <libelf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "hsm_write.h"
#include "zdecode.h"

namespace {

// ---------------------------------------------------------------- ELF

struct Section { std::string name; uint32_t type; uint64_t addr, off, size, flags; };

struct ElfFile {
  const unsigned char* m = nullptr; size_t len = 0;
  std::vector<Section> secs;
  std::vector<size_t> by_addr;   // indexes of file-backed sections with an address, sorted

  explicit ElfFile(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) throw std::runtime_error(path + ": " + strerror(errno));
    struct stat st; fstat(fd, &st); len = st.st_size;
    m = static_cast<const unsigned char*>(mmap(nullptr, len, PROT_READ, MAP_PRIVATE, fd, 0));
    close(fd);
    if (m == MAP_FAILED) throw std::runtime_error(path + ": mmap failed");
    const Elf64_Ehdr* eh = reinterpret_cast<const Elf64_Ehdr*>(m);
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_ident[EI_CLASS] != ELFCLASS64) throw std::runtime_error(path + ": not an ELF64 file");
    const Elf64_Shdr* sh = reinterpret_cast<const Elf64_Shdr*>(m + eh->e_shoff);
    const char* names = reinterpret_cast<const char*>(m + sh[eh->e_shstrndx].sh_offset);
    for (int i = 0; i < eh->e_shnum; i++)
      secs.push_back({names + sh[i].sh_name, sh[i].sh_type, sh[i].sh_addr, sh[i].sh_offset, sh[i].sh_size, sh[i].sh_flags});
    for (size_t i = 0; i < secs.size(); i++) if (secs[i].addr && secs[i].type != SHT_NOBITS) by_addr.push_back(i);
    std::sort(by_addr.begin(), by_addr.end(), [&](size_t a, size_t b) { return secs[a].addr < secs[b].addr; });
  }
  ~ElfFile() { if (m) munmap(const_cast<unsigned char*>(m), len); }

  const unsigned char* at_va(uint64_t va, size_t n) const {
    auto it = std::upper_bound(by_addr.begin(), by_addr.end(), va, [&](uint64_t v, size_t i) { return v < secs[i].addr; });
    if (it == by_addr.begin()) return nullptr;
    const Section& s = secs[*std::prev(it)];
    if (va + n > s.addr + s.size) return nullptr;
    return m + s.off + (va - s.addr);
  }
  const Section* section(std::string_view name) const {
    for (auto& s : secs) if (s.name == name) return &s;
    return nullptr;
  }
};

struct Sym { uint64_t addr, size; char type; std::string name; };

// nm --defined-only -S: defined symbols that are not FILE/SECTION, with
// nm's type letter; nm's default order is by name, and read_symbols then
// stable-sorts by (addr, -size), so ties stay in name order.
std::vector<Sym> read_symbols(const ElfFile& E) {
  std::vector<Sym> out;
  for (auto& s : E.secs) {
    if (s.type != SHT_SYMTAB) continue;
    const Elf64_Sym* sym = reinterpret_cast<const Elf64_Sym*>(E.m + s.off);
    const Section& strs = E.secs[/*sh_link*/ 0 + ([&] { for (size_t i = 0; i < E.secs.size(); i++) if (&E.secs[i] == &s) return i; return size_t(0); }())];
    (void)strs;
    // sh_link isn't kept in Section; find the string table as the section
    // named .strtab (the symtab's companion in every GHC binary)
    const Section* st = E.section(".strtab");
    if (!st) continue;
    const char* str = reinterpret_cast<const char*>(E.m + st->off);
    size_t n = s.size / sizeof(Elf64_Sym);
    for (size_t k = 0; k < n; k++) {
      const Elf64_Sym& y = sym[k];
      int typ = ELF64_ST_TYPE(y.st_info), bind = ELF64_ST_BIND(y.st_info);
      if (y.st_shndx == SHN_UNDEF || typ == STT_FILE || typ == STT_SECTION) continue;
      const char* nm = str + y.st_name;
      if (!*nm) continue;
      char c;
      if (y.st_shndx == SHN_ABS) c = 'A';
      else if (y.st_shndx == SHN_COMMON) c = 'C';
      else if (y.st_shndx >= E.secs.size()) c = '?';
      else {
        const Section& sec = E.secs[y.st_shndx];
        if (sec.flags & SHF_EXECINSTR) c = 'T';
        else if (sec.type == SHT_NOBITS) c = 'B';
        else if (sec.flags & SHF_WRITE) c = 'D';
        else c = 'R';
      }
      if (bind == STB_WEAK) c = typ == STT_OBJECT ? 'V' : 'W';
      else if (bind == STB_LOCAL) c = tolower(c);
      out.push_back({y.st_value, y.st_size, c, nm});
    }
  }
  std::sort(out.begin(), out.end(), [](const Sym& a, const Sym& b) {
    if (a.addr != b.addr) return a.addr < b.addr;
    if (a.size != b.size) return a.size > b.size;
    return a.name < b.name;
  });
  return out;
}

std::vector<std::pair<uint64_t, uint64_t>> exec_ranges(const ElfFile& E) {
  std::vector<std::pair<uint64_t, uint64_t>> out;
  for (auto& s : E.secs) if ((s.flags & SHF_EXECINSTR) && s.size) out.push_back({s.addr, s.addr + s.size});
  std::sort(out.begin(), out.end());
  return out;
}

// ---------------------------------------------------------------- classifier

bool starts_any(std::string_view s, std::initializer_list<const char*> ps) {
  for (const char* p : ps) if (s.starts_with(p)) return true;
  return false;
}

// Tier 4 (_RTS_PATTERNS / _GMP_PATTERNS / _LIBC_PATTERNS), as prefix tests
std::string classify_runtime(std::string_view n) {
  if (starts_any(n, {"__gmp", "__gmpn", "__mpn_", "_mpn_", "mpn_", "integer_cmm_"})) return "gmp";
  if (starts_any(n, {"memcpy", "memset", "memmove", "memcmp", "memchr", "str", "qsort", "sort", "malloc", "free", "calloc", "realloc",
                     "printf", "sprintf", "snprintf", "fprintf", "read", "write", "open", "close", "mmap", "munmap", "pthread_", "sem_",
                     "dl", "__libc_", "_IO_", "__pthread", "__errno", "abort", "exit", "_exit", "sig", "__cxa_"}))
    {
      // str[a-z]+, dl[a-z]+, sig[a-z]+ need a letter after the prefix
      if (n.starts_with("str") && !(n.size() > 3 && islower((unsigned char)n[3]))) {}
      else if (n.starts_with("dl") && !(n.size() > 2 && islower((unsigned char)n[2]))) {}
      else if (n.starts_with("sig") && !(n.size() > 3 && islower((unsigned char)n[3]))) {}
      else return "libc";
    }
  if (n == "_init" || n == "_fini" || n == "__abi_tag" || n.find("@GLIBC") != n.npos) return "libc";
  if (starts_any(n, {"stg_", "rts_", "__rts_", "ghczu", "hs_", "ffi_", "XXH",
                     "ALLOC_", "SLOW_CALL_", "ENT_", "RET_", "UPD_", "GC_", "HEAP_CHK", "STK_CHK", "TICK_",
                     "evacuate", "scavenge", "GarbageCollect", "gc_", "copyPart", "copy_tag", "todo_block", "push_scanned_block",
                     "steal_todo_block", "mark_stack", "upd_evacuee", "nonmoving", "mark_closure", "markCAFs", "markCapability",
                     "markScheduler", "markStable", "compact", "allocate", "allocGroup", "allocBlock", "freeGroup", "freeChain",
                     "initBlockAllocator", "resizeNursery", "updateRemembSet", "recordClosureMutated", "dirty_",
                     "schedule", "threadPaused", "threadStack", "updateThunk", "throwTo", "raiseAsync", "createThread", "newCAF",
                     "checkProddableBlock", "releaseCapability", "waitForCapability", "yieldCapability", "shutdownCapability", "stable",
                     "getOrSet", "lookupSymbol", "loadObj", "resolveObjs", "unloadObj", "ocInit", "ocGetNames", "ocResolve", "start_",
                     "stop_", "initStorage", "exitStorage", "initScheduler", "performGC", "performMajorGC", "getRTSStats", "stat_",
                     "post", "trace", "initEventLog", "endEventLog", "printAndClear", "moreCapEventBufs",
                     "__hs", "markQueue", "getMBlock", "freeMBlock", "setThreadName", "interruptible", "shutdown", "blockUserSignals",
                     "unblockUserSignals", "ioManager", "awaitEvent", "initMutex", "closeMutex", "createOSThread", "osThreadId", "setTicker",
                     "initTicker", "exitTicker", "barf", "debugBelch", "errorBelch", "sysErrorBelch", "vdebugBelch", "base_GHCziConcziSignal"}))
    return "rts";
  return "";
}

const std::unordered_set<std::string> BOOT_PACKAGES = {
    "array", "base", "binary", "bytestring", "Cabal", "Cabal-syntax", "containers", "deepseq", "directory", "exceptions", "filepath",
    "ghc", "ghc-bignum", "ghc-boot", "ghc-boot-th", "ghc-compact", "ghc-heap", "ghci", "ghc-prim", "haskeline", "hpc", "integer-gmp",
    "mtl", "parsec", "pretty", "process", "rts", "semaphore-compat", "stm", "system-cxx-std-lib", "template-haskell", "terminfo",
    "text", "time", "transformers", "unix", "xhtml", "ghc-internal", "ghc-experimental", "os-string"};

std::string bucket_for(const std::string& pname, std::string_view symbol, const std::unordered_set<std::string>& user) {
  if (!pname.empty()) {
    if (user.count(pname)) return "user";
    if (BOOT_PACKAGES.count(pname)) return "boot";
    return "dep";
  }
  if (!symbol.empty()) { std::string b = classify_runtime(symbol); if (!b.empty()) return b; }
  return "unknown";
}

// ---------------------------------------------------------------- spans

struct Span { long l1, c1, l2, c2; bool operator==(const Span& o) const { return l1 == o.l1 && c1 == o.c1 && l2 == o.l2 && c2 == o.c2; } };

bool all_digits(std::string_view s) { return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; }); }
long num(std::string_view s) { return std::strtol(std::string(s).c_str(), nullptr, 10); }

// pprUserRealSpan: "(l,c)-(l,c)" | "l:c-c" | "l:c-l:c" | "l:c"
std::optional<Span> parse_span(std::string_view s) {
  while (!s.empty() && isspace((unsigned char)s.front())) s.remove_prefix(1);
  while (!s.empty() && isspace((unsigned char)s.back())) s.remove_suffix(1);
  if (s.empty()) return std::nullopt;
  if (s.front() == '(') {   // (l,c)-(l,c)
    size_t p1 = s.find(')'); if (p1 == s.npos || p1 + 2 >= s.size() || s[p1 + 1] != '-' || s[p1 + 2] != '(') return std::nullopt;
    size_t p2 = s.find(')', p1 + 3); if (p2 != s.size() - 1) return std::nullopt;
    std::string_view a = s.substr(1, p1 - 1), b = s.substr(p1 + 3, p2 - p1 - 3);
    size_t ca = a.find(','), cb = b.find(',');
    if (ca == a.npos || cb == b.npos) return std::nullopt;
    std::string_view l1 = a.substr(0, ca), c1 = a.substr(ca + 1), l2 = b.substr(0, cb), c2 = b.substr(cb + 1);
    if (!(all_digits(l1) && all_digits(c1) && all_digits(l2) && all_digits(c2))) return std::nullopt;
    return Span{num(l1), num(c1), num(l2), num(c2)};
  }
  size_t colon = s.find(':');
  if (colon == s.npos) return std::nullopt;
  std::string_view l = s.substr(0, colon), rest = s.substr(colon + 1);
  if (!all_digits(l)) return std::nullopt;
  size_t dash = rest.find('-');
  if (dash == rest.npos) { if (!all_digits(rest)) return std::nullopt; return Span{num(l), num(rest), num(l), num(rest)}; }
  std::string_view c1 = rest.substr(0, dash), tail = rest.substr(dash + 1);
  if (!all_digits(c1)) return std::nullopt;
  size_t colon2 = tail.find(':');
  if (colon2 == tail.npos) { if (!all_digits(tail)) return std::nullopt; return Span{num(l), num(c1), num(l), num(tail)}; }
  std::string_view l2 = tail.substr(0, colon2), c2 = tail.substr(colon2 + 1);
  if (!(all_digits(l2) && all_digits(c2))) return std::nullopt;
  return Span{num(l), num(c1), num(l2), num(c2)};
}

// postIPE writes src_file ':' src_span in one field: split at the first
// colon whose tail is a well-formed span
std::pair<std::string, std::string> split_location(const std::string& loc) {
  size_t i = loc.find(':');
  while (i != std::string::npos) {
    if (parse_span(std::string_view(loc).substr(i + 1))) return {loc.substr(0, i), loc.substr(i + 1)};
    i = loc.find(':', i + 1);
  }
  std::string f = loc; while (!f.empty() && f.back() == ':') f.pop_back();
  return {f, ""};
}

bool span_contains(const Span& o, const Span& i) {
  return std::make_pair(o.l1, o.c1) <= std::make_pair(i.l1, i.c1) && std::make_pair(i.l2, i.c2) <= std::make_pair(o.l2, o.c2);
}
long span_size(const Span& s) { return (s.l2 - s.l1) * 10000 + (s.c2 - s.c1); }

// The top-level IPE spans of one file, innermost-containing lookup (SpanIndex)
struct SpanIndex {
  std::vector<Span> spans; std::vector<std::string> names;
  std::vector<std::pair<long, long>> starts, maxend;

  SpanIndex(std::vector<std::tuple<Span, std::string, int, bool>>& items) {
    // rank: a static closure with a label > labelled > unlabelled table name
    std::map<std::tuple<long, long, long, long>, std::pair<int, std::string>> best;
    for (auto& [sp, name, ctype, has_label] : items) {
      bool is_static = ctype == 7 || ctype == 14 || ctype == 21 || ctype == 28;
      int rank = (is_static && has_label) ? 2 : has_label ? 1 : 0;
      auto k = std::make_tuple(sp.l1, sp.c1, sp.l2, sp.c2);
      auto it = best.find(k);
      if (it == best.end() || rank > it->second.first) best[k] = {rank, name};
    }
    // sorted by start ascending, end descending: a span is top-level iff no
    // earlier-or-equal start already reaches its end
    std::vector<std::pair<Span, std::string>> v;
    for (auto& [k, rn] : best) v.push_back({Span{std::get<0>(k), std::get<1>(k), std::get<2>(k), std::get<3>(k)}, rn.second});
    std::sort(v.begin(), v.end(), [](auto& a, auto& b) {
      auto ka = std::make_tuple(a.first.l1, a.first.c1, -a.first.l2, -a.first.c2), kb = std::make_tuple(b.first.l1, b.first.c1, -b.first.l2, -b.first.c2);
      return ka < kb;
    });
    std::optional<std::pair<long, long>> reach;
    for (auto& [sp, nm] : v) {
      auto end = std::make_pair(sp.l2, sp.c2);
      if (!reach || end > *reach) { spans.push_back(sp); names.push_back(nm); reach = end; }
    }
    std::pair<long, long> run{0, 0};
    for (auto& s : spans) { starts.push_back({s.l1, s.c1}); auto e = std::make_pair(s.l2, s.c2); if (e > run) run = e; maxend.push_back(run); }
  }
  std::optional<std::pair<Span, std::string>> innermost(const Span& sp) const {
    auto it = std::upper_bound(starts.begin(), starts.end(), std::make_pair(sp.l1, sp.c1));
    long k = long(it - starts.begin()) - 1;
    auto end = std::make_pair(sp.l2, sp.c2);
    std::optional<std::pair<Span, std::string>> found;
    while (k >= 0 && maxend[k] >= end) {
      if (span_contains(spans[k], sp) && (!found || span_size(spans[k]) < span_size(found->first))) found = {spans[k], names[k]};
      k--;
    }
    return found;
  }
};

// ---------------------------------------------------------------- IPE

// The GHC version the binary was built with: the RTS info table keeps it in
// .rodata as a bare NUL-terminated "9.x.y" string (what `+RTS --info' prints).
std::pair<int, int> ghc_version(const ElfFile& E) {
  const Section* ro = E.section(".rodata");
  if (!ro) return {0, 0};
  const char* p = reinterpret_cast<const char*>(E.m + ro->off); const char* end = p + ro->size;
  for (const char* q = p; q + 8 < end; q++) {
    if (q[0] != '9' || q[1] != '.' || (q > p && q[-1] != 0)) continue;
    int a, b, c;
    if (sscanf(q, "%d.%d.%d", &a, &b, &c) == 3 && a == 9 && b < 20) {
      const char* z = q; while (z < end && *z) z++;
      if (z - q <= 8) return {a, b};
    }
  }
  return {0, 0};
}

struct Ipe { uint64_t info; std::string table_name; int closure_desc; std::string ty_desc, label, module, src_file, src_span; };

// GHC 9.8 IpeBufferListNode (rts/include/rts/IPE.h): next, compressed, count,
// tables*, entries*, entries_size, string_table*, string_table_size; entries
// are 8 x u32 (7 string offsets + pad); tables are info table pointers.
std::vector<Ipe> ipe_from_elf(const ElfFile& E, const std::vector<Sym>& syms, std::string& note) {
  std::vector<Ipe> out;
  std::vector<std::pair<std::string, uint64_t>> nodes;   // by name, as `nm` lists them
  for (auto& s : syms) if (s.name.ends_with("_ipe_buf")) nodes.push_back({s.name, s.addr});
  std::sort(nodes.begin(), nodes.end());
  size_t compressed = 0, bad = 0;
  for (auto& [nm, addr] : nodes) {
    const unsigned char* p = E.at_va(addr, 64);
    if (!p) { bad++; continue; }
    uint64_t f[8]; memcpy(f, p, 64);
    uint64_t comp = f[1], count = f[2], tables = f[3], entries = f[4], esize = f[5], strtab = f[6], ssize = f[7];
    if (comp) { compressed++; continue; }
    if (esize != count * 32) { bad++; continue; }
    if (!count) continue;
    const unsigned char* tabs = E.at_va(tables, 8 * count);
    const unsigned char* raw = E.at_va(entries, esize);
    const unsigned char* st = ssize ? E.at_va(strtab, ssize) : nullptr;
    if (!tabs || !raw || (ssize && !st)) { bad++; continue; }
    auto str = [&](uint32_t off) -> std::string {
      if (off >= ssize) return "";
      size_t n = strnlen(reinterpret_cast<const char*>(st) + off, ssize - off);
      return std::string(reinterpret_cast<const char*>(st) + off, n);
    };
    for (uint64_t k = 0; k < count; k++) {
      uint32_t idx[8]; memcpy(idx, raw + 32 * k, 32);
      uint64_t info; memcpy(&info, tabs + 8 * k, 8);
      std::string cd = str(idx[1]);
      out.push_back({info, str(idx[0]), all_digits(cd) ? (int)num(cd) : -1, str(idx[2]), str(idx[3]), str(idx[4]), str(idx[5]), str(idx[6])});
    }
  }
  note = std::to_string(nodes.size()) + " IPE nodes in the ELF, " + std::to_string(compressed) + " compressed (unsupported), " +
         std::to_string(bad) + " unreadable (a different GHC's layout?)";
  return out;
}

// GHC 9.2 / 9.4: one InfoProvEnt per info table, a data symbol named
// `<info label>_<Module>_ipe' (GHC.StgToCmm.Prof.emitInfoTableProv): info
// pointer, then char* table_name, closure_desc (decimal), ty_desc, label,
// module, srcloc ("file:span"), link.  Strings are absolute (non-PIE).
std::vector<Ipe> ipe_from_elf_92(const ElfFile& E, const std::vector<Sym>& syms, std::string& note) {
  std::vector<Ipe> out;
  size_t bad = 0;
  auto cstr = [&](uint64_t va) -> std::string {
    if (!va) return "";
    const unsigned char* p = E.at_va(va, 1);
    if (!p) return "";
    // bounded by the section the string lives in
    auto it = std::upper_bound(E.by_addr.begin(), E.by_addr.end(), va, [&](uint64_t v, size_t i) { return v < E.secs[i].addr; });
    const Section& sec = E.secs[*std::prev(it)];
    size_t room = sec.addr + sec.size - va;
    return std::string(reinterpret_cast<const char*>(p), strnlen(reinterpret_cast<const char*>(p), room));
  };
  for (auto& sy : syms) {
    if (!sy.name.ends_with("_ipe") || (sy.type != 'D' && sy.type != 'd')) continue;
    const unsigned char* p = E.at_va(sy.addr, 64);
    if (!p) { bad++; continue; }
    uint64_t f[8]; memcpy(f, p, 64);
    std::string cd = cstr(f[2]);
    auto [file, span] = split_location(cstr(f[6]));
    out.push_back({f[0], cstr(f[1]), all_digits(cd) ? (int)num(cd) : -1, cstr(f[3]), cstr(f[4]), cstr(f[5]), file, span});
  }
  note = std::to_string(out.size()) + " InfoProvEnt symbols (GHC 9.2 layout), " + std::to_string(bad) + " unreadable";
  return out;
}

// The eventlog: every EVENT_IPE (169), parsed structurally (its declared
// payload over-counts by one byte).  Big-endian.
uint16_t be16(const unsigned char* p) { return (p[0] << 8) | p[1]; }
uint32_t be32(const unsigned char* p) { return (uint32_t(p[0]) << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }
uint64_t be64(const unsigned char* p) { return (uint64_t(be32(p)) << 32) | be32(p + 4); }

std::vector<Ipe> ipe_from_eventlog(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error(path + ": cannot open");
  std::string data((std::istreambuf_iterator<char>(f)), {});
  const unsigned char* b = reinterpret_cast<const unsigned char*>(data.data());
  size_t o = 0, n = data.size();
  auto need = [&](size_t k) { if (o + k > n) throw std::runtime_error(path + ": truncated eventlog"); };
  need(8);
  if (be32(b) != 0x68647262) throw std::runtime_error(path + ": not an eventlog");
  o = 4;
  if (be32(b + o) != 0x68657462) throw std::runtime_error(path + ": no event-type block");
  o += 4;
  std::unordered_map<uint16_t, uint16_t> sizes;
  while (o + 4 <= n && be32(b + o) == 0x65746200) {
    o += 4; need(8);
    uint16_t num_ = be16(b + o); o += 2;
    uint16_t size = be16(b + o); o += 2;
    uint32_t dlen = be32(b + o); o += 4 + dlen; need(4);
    uint32_t elen = be32(b + o); o += 4 + elen; need(4);
    if (be32(b + o) != 0x65746500) throw std::runtime_error(path + ": malformed event type");
    o += 4;
    sizes[num_] = size;
  }
  need(12);
  if (be32(b + o) != 0x68657465) throw std::runtime_error(path + ": unterminated event-type block");
  o += 4;
  if (be32(b + o) != 0x68647265) throw std::runtime_error(path + ": unterminated header");
  o += 4;
  if (be32(b + o) != 0x64617462) throw std::runtime_error(path + ": no data block");
  o += 4;
  std::vector<Ipe> out;
  while (o + 2 <= n) {
    uint16_t et = be16(b + o);
    if (et == 0xFFFF) break;
    auto it = sizes.find(et);
    if (it == sizes.end()) { std::fprintf(stderr, "hsp symmap: %s: unknown event type %u; stopping\n", path.c_str(), et); break; }
    o += 2 + 8;
    size_t payload = it->second;
    if (payload == 0xFFFF) { need(2); payload = be16(b + o); o += 2; }
    if (et == 18) { o += payload; continue; }       // block marker: its own 14 bytes, then its contents inline
    if (et != 169) { o += payload; continue; }
    need(8);
    uint64_t info = be64(b + o); o += 8;
    std::string fields[6];
    for (auto& fld : fields) {
      size_t e = data.find('\0', o);
      if (e == std::string::npos) throw std::runtime_error(path + ": truncated IPE event");
      fld = data.substr(o, e - o); o = e + 1;
    }
    auto [file, span] = split_location(fields[5]);
    out.push_back({info, fields[0], all_digits(fields[1]) ? (int)num(fields[1]) : -1, fields[2], fields[3], fields[4], file, span});
  }
  return out;
}

const char* CLOSURE_TYPES[] = {
    "INVALID_OBJECT", "CONSTR", "CONSTR_1_0", "CONSTR_0_1", "CONSTR_2_0", "CONSTR_1_1", "CONSTR_0_2", "CONSTR_NOCAF", "FUN", "FUN_1_0",
    "FUN_0_1", "FUN_2_0", "FUN_1_1", "FUN_0_2", "FUN_STATIC", "THUNK", "THUNK_1_0", "THUNK_0_1", "THUNK_2_0", "THUNK_1_1", "THUNK_0_2",
    "THUNK_STATIC", "THUNK_SELECTOR", "BCO", "AP", "PAP", "AP_STACK", "IND", "IND_STATIC", "RET_BCO", "RET_SMALL", "RET_BIG", "RET_FUN",
    "UPDATE_FRAME", "CATCH_FRAME", "UNDERFLOW_FRAME", "STOP_FRAME", "BLOCKING_QUEUE", "BLACKHOLE", "MVAR_CLEAN", "MVAR_DIRTY", "TVAR",
    "ARR_WORDS", "MUT_ARR_PTRS_CLEAN", "MUT_ARR_PTRS_DIRTY", "MUT_ARR_PTRS_FROZEN_DIRTY", "MUT_ARR_PTRS_FROZEN_CLEAN", "MUT_VAR_CLEAN",
    "MUT_VAR_DIRTY", "WEAK", "PRIM", "MUT_PRIM", "TSO", "STACK", "TREC_CHUNK", "ATOMICALLY_FRAME", "CATCH_RETRY_FRAME", "CATCH_STM_FRAME",
    "WHITEHOLE", "SMALL_MUT_ARR_PTRS_CLEAN", "SMALL_MUT_ARR_PTRS_DIRTY", "SMALL_MUT_ARR_PTRS_FROZEN_DIRTY", "SMALL_MUT_ARR_PTRS_FROZEN_CLEAN",
    "COMPACT_NFDATA", "CONTINUATION"};
std::string closure_type_name(int t) { return t >= 0 && t < (int)(sizeof CLOSURE_TYPES / sizeof *CLOSURE_TYPES) ? CLOSURE_TYPES[t] : ""; }
bool is_return_frame(int t) { return t == 29 || t == 30 || t == 31 || t == 32 || t == 33 || t == 34 || t == 35 || t == 36 || t == 53 || t == 55 || t == 56 || t == 57 || t == 64; }

// ---------------------------------------------------------------- roll-ups

// $wfoo is foo's worker, $sfoo a specialisation: the parent is the name
// with the prefixes gone and, for an exposed local, its unique tail dropped
std::string worker_parent(const std::string& name) {
  if (name.empty()) return "";
  size_t i = 0;
  while (i + 1 < name.size() && name[i] == '$' && (name[i + 1] == 'w' || name[i + 1] == 's')) i += 2;
  if (i == 0 || i >= name.size()) return "";
  std::string s = name.substr(i);
  // _UNIQ_TAIL: _[A-Za-z]{0,4}[0-9][A-Za-z0-9]*$  (leftmost match, as re.sub finds it)
  for (size_t p = 0; p < s.size(); p++) {
    if (s[p] != '_') continue;
    if (zdec::uniq_tail(std::string_view(s).substr(p + 1))) { std::string r = s.substr(0, p); return r.empty() ? s : r; }
  }
  return s;
}

// ---------------------------------------------------------------- DWARF

hsmw::Lines dwarf_lines(const std::string& path) {
  hsmw::Lines L;
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) return L;
  elf_version(EV_CURRENT);                       // libelf refuses everything until told the API version
  Dwarf* dw = dwarf_begin(fd, DWARF_C_READ);
  if (!dw) std::fprintf(stderr, "hsp symmap: no DWARF in %s (%s)\n", path.c_str(), dwarf_errmsg(-1));
  if (!dw) { close(fd); return L; }
  struct Row { uint64_t addr; uint32_t fid, line; };
  std::vector<Row> rows;
  std::vector<std::string> files;
  std::unordered_map<std::string, uint32_t> fid;
  Dwarf_Off off = 0, next; size_t hsize;
  while (dwarf_nextcu(dw, off, &next, &hsize, nullptr, nullptr, nullptr) == 0) {
    Dwarf_Die cu;
    if (!dwarf_offdie(dw, off + hsize, &cu)) { off = next; continue; }   // returns the DIE, null on failure
    Dwarf_Lines* lines; size_t n;
    if (dwarf_getsrclines(&cu, &lines, &n) == 0) {
      for (size_t i = 0; i < n; i++) {
        Dwarf_Line* l = dwarf_onesrcline(lines, i);
        bool end; Dwarf_Addr a; int ln;
        if (dwarf_lineendsequence(l, &end)) continue;
        if (dwarf_lineaddr(l, &a) || dwarf_lineno(l, &ln)) continue;
        // a sequence's end is a row too (line 0): the addresses after it have
        // no line until the next sequence starts, however close that is
        if (end) ln = 0;
        const char* src = dwarf_linesrc(l, nullptr, nullptr);
        std::string f = src ? src : "";
        auto slash = f.rfind('/');
        if (slash != std::string::npos) f = f.substr(slash + 1);
        auto [it, fresh] = fid.try_emplace(f, files.size());
        if (fresh) files.push_back(f);
        rows.push_back({a, it->second, (uint32_t)ln});
      }
    }
    off = next;
  }
  dwarf_end(dw);
  close(fd);
  // at one address an end row sorts first, so a sequence starting there wins
  std::sort(rows.begin(), rows.end(), [](auto& a, auto& b) {
    return std::make_tuple(a.addr, a.line != 0, a.fid, a.line) < std::make_tuple(b.addr, b.line != 0, b.fid, b.line);
  });
  for (auto& r : rows) { L.addr.push_back(r.addr); L.file.push_back(files[r.fid]); L.line.push_back(r.line); }
  return L;
}

}  // namespace

int cmd_symmap(int argc, char** argv) {
  if (argc < 2) { std::fprintf(stderr, "usage: hsp symmap BIN OUT.hsm [--eventlog FILE] [--no-dwarf] [--user-packages a,b]\n"); return 2; }
  std::string bin = argv[0], outp = argv[1], eventlog;
  bool dwarf = true;
  std::unordered_set<std::string> user;
  for (int i = 2; i < argc; i++) {
    if (!strcmp(argv[i], "--eventlog") && i + 1 < argc) eventlog = argv[++i];
    else if (!strcmp(argv[i], "--no-dwarf")) dwarf = false;
    else if (!strcmp(argv[i], "--user-packages") && i + 1 < argc) {
      std::string_view v = argv[++i];
      for (size_t b = 0; b <= v.size();) { size_t e = v.find(',', b); if (e == v.npos) e = v.size(); if (e > b) user.insert(std::string(v.substr(b, e - b))); b = e + 1; }
    }
  }
  ElfFile E(bin);
  std::vector<Sym> syms = read_symbols(E);
  hsmw::Input in;
  in.exec_ranges = exec_ranges(E);
  std::fprintf(stderr, "symbols %zu, executable ranges %zu\n", syms.size(), in.exec_ranges.size());

  std::string note;
  auto [gmaj, gmin] = ghc_version(E);
  std::fprintf(stderr, "GHC %d.%d\n", gmaj, gmin);
  std::vector<Ipe> ipes;
  if (!eventlog.empty()) ipes = ipe_from_eventlog(eventlog);
  else if (gmaj == 9 && gmin <= 4) ipes = ipe_from_elf_92(E, syms, note);
  else ipes = ipe_from_elf(E, syms, note);
  if (ipes.empty() && eventlog.empty())
    std::fprintf(stderr, "hsp symmap: no IPE found in the ELF (built without -finfo-table-map, or a layout this reader lacks: GHC 9.10 needs --eventlog)\n");
  size_t ret_frames = 0; for (auto& p : ipes) if (is_return_frame(p.closure_desc)) ret_frames++;
  std::fprintf(stderr, "IPE %zu entries (%zu return/stack frames)%s%s\n", ipes.size(), ret_frames, note.empty() ? "" : "; ", note.c_str());

  // the info-pointer delta, measured against the _info symbols
  std::unordered_set<uint64_t> sym_addrs;
  for (auto& s : syms) if (s.name.ends_with("_info")) sym_addrs.insert(s.addr);
  int64_t delta = 0;
  if (!ipes.empty() && !sym_addrs.empty()) {
    long best = -1;
    for (int cand : {0, 8, 16, 24, 32}) {
      long h = 0; for (auto& p : ipes) if (sym_addrs.count(p.info + cand)) h++;
      if (h > best) { best = h; delta = cand; }
    }
    std::fprintf(stderr, "info delta %ld (%ld IPE entries land on an _info symbol)\n", (long)delta, best);
  }
  in.info_delta = delta;

  auto& entries = in.entries;
  std::unordered_map<uint64_t, uint32_t> by_info;
  std::unordered_map<std::string, std::vector<std::pair<uint64_t, std::string>>> globals_by_module;
  // -- tier 3: every defined symbol
  for (auto& s : syms) {
    auto d = zdec::split_symbol(s.name);
    hsmw::Entry e;
    e.addr = s.addr; e.size = s.size; e.info_ptr = s.name.ends_with("_info") ? s.addr : 0;
    e.symbol = s.name;
    if (d) { e.package_name = d->package_name; e.module = d->module; e.name = d->name; } else e.name = s.name;
    e.bucket = bucket_for(e.package_name, s.name, user);
    e.source_tier = "symtab"; e.rollup = "self";
    uint32_t i = entries.size();
    entries.push_back(std::move(e));
    const hsmw::Entry& ee = entries.back();
    if (s.name.ends_with("_info")) by_info.try_emplace(s.addr, i);
    if (s.size > 0) in.intervals.emplace_back(s.addr, s.addr + s.size, i);
    if (s.type == 'T' && !ee.module.empty() && s.name.ends_with("_info") && d) {
      std::string wp = worker_parent(ee.name);
      globals_by_module[ee.module].push_back({s.addr, wp.empty() ? ee.name : wp});
    }
  }
  for (auto& [m, v] : globals_by_module) std::sort(v.begin(), v.end());

  // -- tier 1: IPE.  First pass: the exact rules; second: address adjacency
  std::unordered_map<std::string, std::vector<std::tuple<Span, std::string, int, bool>>> per_file;
  for (auto& p : ipes) {
    auto sp = parse_span(p.src_span);
    if (!sp || p.src_file.empty()) continue;
    per_file[p.src_file].push_back({*sp, p.label.empty() ? p.table_name : p.label, p.closure_desc, !p.label.empty()});
  }
  std::unordered_map<std::string, SpanIndex> span_index;
  size_t toplevels = 0;
  for (auto& [f, items] : per_file) { auto [it, _] = span_index.emplace(f, items); toplevels += it->second.spans.size(); }
  std::fprintf(stderr, "IPE spans: %zu files, %zu top-level bindings\n", span_index.size(), toplevels);

  struct Pending { const Ipe* p; uint64_t info_ptr; std::optional<Span> span; int sym; std::string name, toplevel, how; };
  std::vector<Pending> pending; pending.reserve(ipes.size());
  for (auto& p : ipes) {
    Pending q; q.p = &p; q.info_ptr = p.info + delta; q.span = parse_span(p.src_span);
    auto it = by_info.find(q.info_ptr); q.sym = it == by_info.end() ? -1 : (int)it->second;
    q.name = p.label.empty() ? p.table_name : p.label;
    if (q.span) {
      auto ix = span_index.find(p.src_file);
      if (ix != span_index.end()) {
        auto found = ix->second.innermost(*q.span);
        if (found) { q.toplevel = found->second; q.how = found->first == *q.span ? "self" : "ipe-span"; }
      }
    }
    if (q.toplevel.empty()) {
      std::string cand = worker_parent(q.sym >= 0 ? entries[q.sym].name : q.name);
      if (!cand.empty()) { q.toplevel = cand; q.how = "worker-name"; }
    }
    pending.push_back(std::move(q));
  }
  // anchors: exactly-resolved IPE entries plus the ELF globals, per module
  std::unordered_map<std::string, std::vector<std::pair<uint64_t, std::string>>> anchors = globals_by_module;
  for (auto& q : pending) if (!q.toplevel.empty()) anchors[q.p->module].push_back({q.info_ptr, q.toplevel});
  std::unordered_map<std::string, std::vector<uint64_t>> anchor_addrs;
  for (auto& [m, v] : anchors) { std::sort(v.begin(), v.end()); auto& a = anchor_addrs[m]; for (auto& [x, _] : v) a.push_back(x); }
  auto anchor_before = [&](const std::string& mod, uint64_t a) -> const std::string* {
    auto it = anchor_addrs.find(mod);
    if (it == anchor_addrs.end() || it->second.empty()) return nullptr;
    auto k = std::upper_bound(it->second.begin(), it->second.end(), a);
    if (k == it->second.begin()) return nullptr;
    return &anchors[mod][k - it->second.begin() - 1].second;
  };
  std::map<std::string, long> rollup_counts;
  for (auto& q : pending) {
    const Ipe& p = *q.p;
    if (q.toplevel.empty()) { if (const std::string* t = anchor_before(p.module, q.info_ptr)) { q.toplevel = *t; q.how = "addr-adjacency"; } }
    if (q.toplevel.empty() && q.how.empty()) { q.toplevel = p.label; q.how = "self"; }
    else if (q.toplevel.empty()) { q.how = "self"; }
    rollup_counts[q.how]++;
    hsmw::Entry e;
    const hsmw::Entry* sym = q.sym >= 0 ? &entries[q.sym] : nullptr;
    e.addr = q.info_ptr; e.size = sym ? sym->size : 0; e.info_ptr = q.info_ptr;
    e.symbol = sym ? sym->symbol : "";
    e.package_name = sym ? sym->package_name : "";
    e.module = p.module; e.name = q.name; e.toplevel = q.toplevel;
    e.src_file = p.src_file; e.src_span = p.src_span;
    e.source_tier = "ipe";
    e.bucket = bucket_for(e.package_name, e.symbol, user);
    e.rollup = q.how;
    e.closure_type_name = closure_type_name(p.closure_desc);
    uint32_t i = entries.size();
    entries.push_back(std::move(e));
    by_info[q.info_ptr] = i;                          // IPE wins over the symbol table
    if (entries.back().size) in.intervals.emplace_back(q.info_ptr, q.info_ptr + entries.back().size, i);
  }
  pending.clear(); pending.shrink_to_fit();

  // -- roll-up for symtab-only entries
  std::map<std::string, long> sym_rollup;
  for (auto& e : entries) {
    if (e.source_tier != "symtab" || !e.toplevel.empty() || e.module.empty()) continue;
    std::string parent = worker_parent(e.name);
    if (!parent.empty()) { e.toplevel = parent; e.rollup = "worker-name"; sym_rollup["worker-name"]++; continue; }
    const std::string* t = anchor_before(e.module, e.addr);
    if (t && *t != e.name) { e.toplevel = *t; e.rollup = "addr-adjacency"; sym_rollup["addr-adjacency"]++; }
    else { e.toplevel = e.name; sym_rollup["self"]++; }
  }

  // -- refine(): inlined origins, clean anchors, packages
  auto exact = [](const std::string& r) { return r == "mix-span" || r == "ipe-span" || r == "worker-name" || r == "self"; };
  {
    std::unordered_map<std::string, std::map<std::string, long>> static_files;
    for (auto& e : entries)
      if (e.source_tier == "ipe" && !e.src_file.empty() && !e.module.empty() && e.closure_type_name.ends_with("_STATIC")) static_files[e.module][e.src_file]++;
    std::unordered_map<std::string, std::string> own;
    for (auto& [m, c] : static_files) {
      // Counter.most_common(1): highest count, first inserted on ties -- a
      // std::map iterates by key, so track insertion order separately
      std::string bestf; long bestc = -1;
      for (auto& [f, n] : c) if (n > bestc) { bestc = n; bestf = f; }
      own[m] = bestf;
    }
    std::unordered_map<std::string, std::vector<std::string>> owners;
    for (auto& [m, f] : own) owners[f].push_back(m);
    std::unordered_map<std::string, std::string> file_owner;
    for (auto& [f, ms] : owners) if (ms.size() == 1) file_owner[f] = ms[0];
    long n_inl = 0;
    for (auto& e : entries) {
      if (e.source_tier != "ipe") continue;
      if (!e.inlined.empty()) { n_inl++; continue; }
      if (e.src_file.empty() || e.module.empty()) continue;
      auto o = own.find(e.module);
      if (o != own.end() && o->second == e.src_file) continue;
      auto fo = file_owner.find(e.src_file);
      if (fo != file_owner.end() && fo->second != e.module) {
        std::string origin = exact(e.rollup) ? e.toplevel : "";
        e.inlined = fo->second + "." + (!origin.empty() ? origin : !e.name.empty() ? e.name : e.name);
        e.toplevel.clear(); e.rollup = "inlined-site";
        n_inl++;
      }
    }
    std::unordered_map<std::string, std::vector<std::pair<uint64_t, std::string>>> anc;
    for (auto& e : entries)
      if (e.source_tier == "ipe" && e.inlined.empty() && exact(e.rollup) && !e.toplevel.empty() && e.info_ptr && !e.module.empty())
        anc[e.module].push_back({e.info_ptr, e.toplevel});
    std::unordered_map<std::string, std::vector<uint64_t>> addrs;
    for (auto& [m, v] : anc) { std::sort(v.begin(), v.end()); for (auto& [a, _] : v) addrs[m].push_back(a); }
    std::map<std::string, long> re_rolled;
    for (auto& e : entries) {
      const std::string& how = e.rollup;
      if ((how != "inlined-site" && how != "addr-adjacency") || e.module.empty()) continue;
      uint64_t a = e.info_ptr ? e.info_ptr : e.addr;
      auto ci = anc.find(e.module);
      bool has = ci != anc.end() && !ci->second.empty();
      if (!has && how == "addr-adjacency") continue;
      long k = -1;
      if (has) { auto& ad = addrs[e.module]; k = long(std::upper_bound(ad.begin(), ad.end(), a) - ad.begin()) - 1; }
      if (k >= 0) { e.toplevel = ci->second[k].second; re_rolled[how]++; }
      else if (how == "inlined-site") { e.toplevel = "<inlined " + e.inlined + ">"; re_rolled["inlined-no-site"]++; }
      else if (e.source_tier == "symtab") { e.toplevel = e.name; e.rollup = "self"; re_rolled["adjacency->self"]++; }
      else { e.toplevel = e.name; e.rollup = "self"; re_rolled["adjacency->self"]++; }
    }
    std::unordered_map<std::string, std::map<std::string, long>> mod_pkgs;
    for (auto& e : entries) if (e.source_tier == "symtab" && !e.module.empty() && !e.package_name.empty()) mod_pkgs[e.module][e.package_name]++;
    long filled = 0, ambiguous = 0;
    for (auto& [m, c] : mod_pkgs) if (c.size() > 1) ambiguous++;
    for (auto& e : entries) {
      if (e.source_tier != "ipe" || !e.package_name.empty()) continue;
      auto it = mod_pkgs.find(e.module);
      if (it == mod_pkgs.end() || it->second.size() != 1) continue;
      e.package_name = it->second.begin()->first;
      e.bucket = bucket_for(e.package_name, e.symbol, user);
      filled++;
    }
    std::fprintf(stderr, "roll-up: ");
    for (auto& [k, v] : rollup_counts) std::fprintf(stderr, "%s %ld  ", k.c_str(), v);
    std::fprintf(stderr, "| symtab: ");
    for (auto& [k, v] : sym_rollup) std::fprintf(stderr, "%s %ld  ", k.c_str(), v);
    std::fprintf(stderr, "\nrefine: inlined %ld, own files %zu, re-rolled ", n_inl, own.size());
    for (auto& [k, v] : re_rolled) std::fprintf(stderr, "%s %ld  ", k.c_str(), v);
    std::fprintf(stderr, ", package filled %ld, ambiguous modules %ld\n", filled, ambiguous);
  }

  for (auto& [p, i] : by_info) in.by_info.push_back({p, i});
  std::sort(in.intervals.begin(), in.intervals.end());
  if (dwarf) {
    in.lines = dwarf_lines(bin);
    std::fprintf(stderr, "DWARF rows %zu\n", in.lines.addr.size());
  }
  hsmw::write_hsm(in, outp);
  return 0;
}
