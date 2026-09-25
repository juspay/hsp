#include "hsm.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "pyfmt.h"

namespace hsm {

Map Map::open(const char* path) {
  int fd = ::open(path, O_RDONLY);
  if (fd < 0) throw std::runtime_error(std::string(path) + ": " + std::strerror(errno));
  struct stat st;
  fstat(fd, &st);
  void* p = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (p == MAP_FAILED) throw std::runtime_error(std::string(path) + ": mmap failed");
  Map m;
  m.base_ = static_cast<const char*>(p);
  m.len_ = st.st_size;
  m.h_ = m.at<Header>(0);
  if (m.len_ < sizeof(Header) || std::memcmp(m.h_->magic, MAGIC, 8) != 0)
    throw std::runtime_error(std::string(path) + ": not an hsp map (" + std::string(m.h_->magic, 8) + ")");
  const Header& h = *m.h_;
  m.e_ = m.at<Entry>(h.entries);
  m.bi_ = m.at<ByInfo>(h.byinfo);
  m.ex_ = m.at<Range>(h.exec);
  m.strs_ = m.at<char>(h.strings);
  m.iv_start_ = m.at<uint64_t>(h.iv_start);
  m.iv_end_ = m.at<uint64_t>(h.iv_end);
  m.iv_maxend_ = m.at<uint64_t>(h.iv_maxend);
  m.iv_idx_ = m.at<uint32_t>(h.iv_idx);
  m.cs_addr_ = m.at<uint64_t>(h.cs_addr);
  m.cs_idx_ = m.at<uint32_t>(h.cs_idx);
  m.ow_addr_ = m.at<uint64_t>(h.ow_addr);
  m.ow_idx_ = m.at<uint32_t>(h.ow_idx);
  m.ln_addr_ = m.at<uint64_t>(h.ln_addr);
  m.ln_file_ = m.at<uint32_t>(h.ln_file);
  m.ln_line_ = m.at<uint32_t>(h.ln_line);
  m.bs_ = m.at<BSpan>(h.bspans);
  return m;
}

Map::Map(Map&& o) noexcept { *this = o; o.base_ = nullptr; }

Map::~Map() {
  if (base_) munmap(const_cast<char*>(base_), len_);
}

// bisect.bisect_right(a, x) - 1 over a sorted array: the last index with
// a[k] <= x, or -1.
static long last_le(const uint64_t* a, uint64_t n, uint64_t x) {
  return long(std::upper_bound(a, a + n, x) - a) - 1;
}

const Entry* Map::resolve_info(uint64_t ptr) const {
  auto find = [&](uint64_t p) -> const Entry* {
    const ByInfo* end = bi_ + h_->n_byinfo;
    const ByInfo* it = std::lower_bound(bi_, end, p, [](const ByInfo& b, uint64_t v) { return b.ptr < v; });
    return it != end && it->ptr == p ? e_ + it->idx : nullptr;
  };
  // a collector may hand back the raw IPE word instead
  const Entry* e = find(ptr);
  return e ? e : find(ptr + h_->info_delta);
}

std::optional<Range> Map::exec_range(uint64_t addr) const {
  const Range* end = ex_ + h_->n_exec;
  const Range* it = std::upper_bound(ex_, end, addr, [](uint64_t v, const Range& r) { return v < r.lo; });
  if (it == ex_) return std::nullopt;
  --it;
  return addr < it->hi ? std::optional<Range>(*it) : std::nullopt;
}

Hit Map::resolve_addr(uint64_t addr) const {
  // exact at an info table: by_info.get(addr), no info_delta here
  const ByInfo* bend = bi_ + h_->n_byinfo;
  const ByInfo* b = std::lower_bound(bi_, bend, addr, [](const ByInfo& x, uint64_t v) { return x.ptr < v; });
  if (b != bend && b->ptr == addr) return Hit{e_ + b->idx};
  // Symbols nest and overlap, so walk back from the last interval starting at
  // or below addr until no earlier one can still reach it (prefix max of ends).
  for (long k = last_le(iv_start_, h_->n_iv, addr); k >= 0 && iv_maxend_[k] > addr; k--)
    if (iv_start_[k] <= addr && addr < iv_end_[k]) return Hit{e_ + iv_idx_[k]};
  return resolve_extent(addr);
}

bool atomic(const Map& m, const Entry& e) {
  std::string_view sym = m.str(e.symbol);
  if (m.str(e.closure_type_name).starts_with("CONSTR") || sym.ends_with("_con_info") ||
      sym.ends_with("_con_entry") || sym.ends_with("_static_info"))
    return true;
  return !sym.empty() && !e.module && !sym.starts_with("stg_");
}

Hit Map::resolve_extent(uint64_t addr) const {
  auto rng = exec_range(addr);
  if (!rng) return {};
  long k = last_le(cs_addr_, h_->n_cstarts, addr);
  if (k < 0 || cs_addr_[k] < rng->lo) return {};
  const Entry* e = e_ + cs_idx_[k];
  // extent is only sound after a Haskell procedure: past a constructor's entry
  // or a C function's st_size is code with no name of its own
  if (e->size && cs_addr_[k] + e->size <= addr && atomic(*this, *e)) return {};
  Hit h{e};
  h.match = Hit::EXTENT;
  return h;
}

std::optional<std::pair<uint32_t, uint32_t>> Map::line_at(uint64_t pc) const {
  long k = last_le(ln_addr_, h_->n_lines, pc);
  if (k < 0 || !ln_line_[k] || pc - ln_addr_[k] > 4096) return std::nullopt;   // line 0: past a sequence's end
  return std::make_pair(ln_file_[k], ln_line_[k]);
}

uint32_t Map::binding_at_line(uint32_t module, uint32_t file, int64_t line) const {
  const BSpan* end = bs_ + h_->n_bspans;
  auto key = [](const BSpan& s) { return std::make_pair(s.module, s.file); };
  auto [lo, hi] = std::equal_range(bs_, end, BSpan{module, file, 0, 0, 0, 0},
                                   [&](const BSpan& a, const BSpan& b) { return key(a) < key(b); });
  // innermost wins; on a tie the earlier span (list order) stays
  const BSpan* best = nullptr;
  for (const BSpan* s = lo; s != hi; ++s)
    if (s->lo <= line && line <= s->hi && (!best || s->hi - s->lo < best->hi - best->lo)) best = s;
  return best ? best->toplevel : 0;
}

Hit Map::resolve_leaf(uint64_t pc) const {
  Hit e = resolve_addr(pc);
  if (!e || !lines_ || !h_->n_lines || !e.e->module) return e;
  std::string_view sym = str(e.e->symbol);
  if (str(e.e->closure_type_name).starts_with("CONSTR") || sym.ends_with("_con_info") ||
      sym.ends_with("_con_entry") || sym.ends_with("_static_info"))
    return e;
  auto fl = line_at(pc);
  if (!fl) return e;
  uint32_t t = binding_at_line(e.e->module, fl->first, fl->second);
  if (!t) return e;
  bool guessed = e.match != Hit::NONE || str(e.e->rollup) == "addr-adjacency" || !e.e->src_span;
  // compare by text: the entry's toplevel and a span's toplevel are both
  // interned, so equal text means equal offset
  if (t == e.e->toplevel) { e.dwarf = true; return e; }
  if (guessed) { e.toplevel = t; e.match = Hit::DWARF_LINE; return e; }
  e.site = t;   // inlined / specialised
  return e;
}

const Entry* Map::owner(uint64_t addr) const {
  long k = last_le(ow_addr_, h_->n_owner, addr);
  return k < 0 ? nullptr : e_ + ow_idx_[k];
}

std::string Map::near(uint64_t pc) const {
  long k = last_le(ow_addr_, h_->n_owner, pc);
  if (k < 0) return "-";
  // audit() sorts by (addr, symbol), Owner by (addr, index): among entries at
  // the same address take the greatest symbol, as the Python bisect lands there
  long best = k;
  for (long j = k - 1; j >= 0 && ow_addr_[j] == ow_addr_[k]; j--)
    if (str(e_[ow_idx_[j]].symbol) > str(e_[ow_idx_[best]].symbol)) best = j;
  return std::string(str(e_[ow_idx_[best]].symbol)) + "+" + pyfmt::hex(pc - ow_addr_[k]);
}

}  // namespace hsm
