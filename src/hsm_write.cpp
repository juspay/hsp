#include "hsm_write.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <stdexcept>
#include <tuple>
#include <unordered_map>

#include "hsm.h"

using namespace hsm;

namespace hsmw {
namespace {

// One copy of every distinct string; offset 0 is "".
struct Strings {
  std::string blob{'\0'};
  std::unordered_map<std::string, uint32_t> at;
  uint32_t put(const std::string& s) {
    if (s.empty()) return 0;
    auto [it, fresh] = at.try_emplace(s, uint32_t(blob.size()));
    if (fresh) { blob += s; blob += '\0'; }
    return it->second;
  }
};

struct Out {
  std::string buf = std::string(sizeof(Header), '\0');
  uint64_t put(const void* p, size_t bytes) {
    buf.resize((buf.size() + 7) & ~size_t(7), '\0');
    uint64_t off = buf.size();
    buf.append(static_cast<const char*>(p), bytes);
    return off;
  }
  template <class T> uint64_t put(const std::vector<T>& v) { return put(v.data(), v.size() * sizeof(T)); }
};

}  // namespace

void write_hsm(const Input& in, const std::string& outp) {
  Strings S;
  Header h{};
  std::memcpy(h.magic, MAGIC, 8);
  h.info_delta = in.info_delta;

  std::vector<hsm::Entry> E;
  E.reserve(in.entries.size());
  for (const Entry& x : in.entries) {
    hsm::Entry e{};
    e.addr = x.addr; e.size = x.size; e.info_ptr = x.info_ptr;
    e.symbol = S.put(x.symbol); e.package_name = S.put(x.package_name); e.module = S.put(x.module);
    e.name = S.put(x.name); e.toplevel = S.put(x.toplevel); e.src_file = S.put(x.src_file);
    e.src_span = S.put(x.src_span); e.closure_type_name = S.put(x.closure_type_name); e.inlined = S.put(x.inlined);
    e.bucket = S.put(x.bucket); e.rollup = S.put(x.rollup); e.source_tier = S.put(x.source_tier);
    E.push_back(e);
  }

  std::vector<ByInfo> BI;
  for (auto& [p, i] : in.by_info) BI.push_back({p, i, 0});
  std::sort(BI.begin(), BI.end(), [](auto& a, auto& b) { return a.ptr < b.ptr; });
  auto by_info = [&](uint64_t p) -> const ByInfo* {
    auto it = std::lower_bound(BI.begin(), BI.end(), p, [](auto& b, uint64_t v) { return b.ptr < v; });
    return it != BI.end() && it->ptr == p ? &*it : nullptr;
  };

  std::vector<uint64_t> ivs, ive, ivm;
  std::vector<uint32_t> ivi;
  { uint64_t run = 0;
    for (auto& [s, e, i] : in.intervals) { ivs.push_back(s); ive.push_back(e); ivi.push_back(i); run = std::max(run, e); ivm.push_back(run); } }

  std::vector<Range> EX;
  for (auto& [lo, hi] : in.exec_ranges) EX.push_back({lo, hi});
  std::sort(EX.begin(), EX.end(), [](auto& a, auto& b) { return a.lo < b.lo; });
  auto in_exec = [&](uint64_t a) {
    auto it = std::upper_bound(EX.begin(), EX.end(), a, [](uint64_t v, const Range& r) { return v < r.lo; });
    return it != EX.begin() && a < std::prev(it)->hi;
  };

  // extent starts: per distinct code address, its by_info entry if it has
  // one, else the first entry there
  std::vector<uint64_t> csa; std::vector<uint32_t> csi;
  { std::unordered_map<uint64_t, uint32_t> starts;
    for (uint32_t i = 0; i < E.size(); i++) {
      uint64_t a = E[i].info_ptr ? E[i].info_ptr : E[i].addr;
      if (!a || !in_exec(a)) continue;
      if (const ByInfo* b = by_info(a)) starts[a] = b->idx; else starts.try_emplace(a, i);
    }
    std::vector<std::pair<uint64_t, uint32_t>> v(starts.begin(), starts.end());
    std::sort(v.begin(), v.end());
    for (auto& [a, i] : v) { csa.push_back(a); csi.push_back(i); } }

  // Owner: symtab entries with an address in .text, sorted by (addr, index)
  std::vector<uint64_t> owa; std::vector<uint32_t> owi;
  { uint32_t symtab = S.put("symtab");
    std::vector<std::pair<uint64_t, uint32_t>> v;
    for (uint32_t i = 0; i < E.size(); i++)
      if (E[i].source_tier == symtab && E[i].addr && in_exec(E[i].addr)) v.push_back({E[i].addr, i});
    std::sort(v.begin(), v.end());
    for (auto& [a, i] : v) { owa.push_back(a); owi.push_back(i); } }

  // attach_lines: each top-level binding's line extent in its file, from the
  // spans of entries whose roll-up is exact; the binding's own entry wins
  std::vector<BSpan> BS;
  { std::vector<uint32_t> exact;
    for (const char* r : {"mix-span", "ipe-span", "worker-name", "self"}) exact.push_back(S.put(r));
    struct Acc { int64_t lo, hi; bool own; int64_t olo, ohi; };
    std::map<std::tuple<uint32_t, uint32_t, uint32_t>, size_t> key;
    std::vector<std::tuple<uint32_t, uint32_t, uint32_t>> order;
    std::vector<Acc> acc;
    for (size_t idx = 0; idx < E.size(); idx++) {
      const hsm::Entry& e = E[idx];
      if (!(e.toplevel && e.src_file && e.module && e.src_span)) continue;
      if (std::find(exact.begin(), exact.end(), e.rollup) == exact.end()) continue;
      std::string_view sp(S.blob.data() + e.src_span);
      std::vector<int64_t> nums;
      for (size_t j = 0; j < sp.size();) {
        if (!isdigit((unsigned char)sp[j])) { j++; continue; }
        int64_t x = 0;
        while (j < sp.size() && isdigit((unsigned char)sp[j])) x = x * 10 + (sp[j++] - '0');
        nums.push_back(x);
      }
      if (nums.empty()) continue;
      int64_t lo = nums[0], hi = (sp[0] == '(' && nums.size() >= 3) ? nums[2] : nums[0];
      std::string_view f(S.blob.data() + e.src_file);
      auto slash = f.rfind('/');
      uint32_t fb = S.put(std::string(slash == f.npos ? f : f.substr(slash + 1)));
      auto k = std::make_tuple(e.module, fb, e.toplevel);
      auto [it, fresh] = key.try_emplace(k, acc.size());
      if (fresh) { acc.push_back({lo, hi, false, 0, 0}); order.push_back(k); }
      Acc& a = acc[it->second];
      a.lo = std::min(a.lo, lo); a.hi = std::max(a.hi, hi);
      if (e.name == e.toplevel) {
        if (!a.own) { a.own = true; a.olo = lo; a.ohi = hi; }
        a.olo = std::min(a.olo, lo); a.ohi = std::max(a.ohi, hi);
      }
    }
    for (size_t i = 0; i < order.size(); i++) {
      auto [m, f, t] = order[i]; const Acc& a = acc[i];
      BS.push_back({m, f, t, 0, a.own ? a.olo : a.lo, a.own ? a.ohi : a.hi});
    }
    std::stable_sort(BS.begin(), BS.end(), [](auto& a, auto& b) { return std::make_pair(a.module, a.file) < std::make_pair(b.module, b.file); }); }

  std::vector<uint32_t> lfile; lfile.reserve(in.lines.addr.size());
  for (auto& f : in.lines.file) lfile.push_back(S.put(f));

  Out o;
  h.n_entries = E.size(); h.entries = o.put(E);
  h.n_byinfo = BI.size(); h.byinfo = o.put(BI);
  h.n_iv = ivs.size(); h.iv_start = o.put(ivs); h.iv_end = o.put(ive); h.iv_maxend = o.put(ivm); h.iv_idx = o.put(ivi);
  h.n_exec = EX.size(); h.exec = o.put(EX);
  h.n_cstarts = csa.size(); h.cs_addr = o.put(csa); h.cs_idx = o.put(csi);
  h.n_owner = owa.size(); h.ow_addr = o.put(owa); h.ow_idx = o.put(owi);
  h.n_lines = in.lines.addr.size(); h.ln_addr = o.put(in.lines.addr); h.ln_file = o.put(lfile); h.ln_line = o.put(in.lines.line);
  h.n_bspans = BS.size(); h.bspans = o.put(BS);
  h.n_strings = S.blob.size(); h.strings = o.put(S.blob.data(), S.blob.size());
  std::memcpy(o.buf.data(), &h, sizeof h);

  std::string tmp = outp + ".tmp";
  FILE* f = std::fopen(tmp.c_str(), "wb");
  if (!f || std::fwrite(o.buf.data(), 1, o.buf.size(), f) != o.buf.size() || std::fclose(f) != 0)
    throw std::runtime_error(tmp + ": write failed");
  std::rename(tmp.c_str(), outp.c_str());
  std::fprintf(stderr, "wrote %s: %zu MB (entries %zu, by_info %zu, intervals %zu, extent starts %zu, owner %zu, DWARF rows %zu, binding spans %zu)\n",
               outp.c_str(), o.buf.size() >> 20, E.size(), BI.size(), ivs.size(), csa.size(), owa.size(), in.lines.addr.size(), BS.size());
}

}  // namespace hsmw
