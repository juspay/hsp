// Turning resolved entries into the names a profile shows.  Shared by fold
// (offline reports) and collect (the collector): the same rules, so a
// Pyroscope profile and a fold report name things identically.
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "hsm.h"

namespace naming {

// name(e, fallback): Module.binding; stg_ names stand alone
inline std::string name(const hsm::Map& m, const hsm::Hit& h, const std::string& fallback) {
  if (!h) return fallback;
  const hsm::Entry& e = *h.e;
  uint32_t t = h.toplevel ? h.toplevel : e.toplevel;
  std::string_view n = t ? m.str(t) : e.name ? m.str(e.name) : m.str(e.symbol);
  std::string_view mod = m.str(e.module);
  if (!mod.empty() && !n.empty() && !n.starts_with("stg_")) return std::string(mod) + "." + std::string(n);
  return std::string(n);
}
inline hsm::Hit hit(const hsm::Entry* e) { return hsm::Hit{e}; }

// GHC and Cmm code keep Sp in %rbp; C code does not
inline bool haskell_mode(std::string_view sym) {
  for (const char* s : {"_info", "_entry", "_ret", "_fast", "_slow"})
    if (sym.ends_with(s)) return true;
  return sym.starts_with("stg_");
}

inline bool exact_rollup(std::string_view r) {
  return r == "mix-span" || r == "ipe-span" || r == "worker-name" || r == "self";
}

// Owner.of(addr, frame): for an address with no name of its own, the module
// (return frames) or package (leaf PCs) of the nearest preceding ELF symbol
inline std::optional<std::string> owner_of(const hsm::Map& m, uint64_t addr, bool frame) {
  const hsm::Entry* e = m.owner(addr);
  if (!e) return std::nullopt;
  if (frame && e->module) return std::string(m.str(e->module)) + ".<local>";
  if (e->package_name) return std::string(m.str(e->package_name)) + ":<unnamed>";
  return std::nullopt;
}
inline std::string owner_or(const hsm::Map& m, uint64_t addr, bool frame) {
  auto o = owner_of(m, addr, frame);
  return o ? *o : "?0x" + [](uint64_t a) { char b[32]; snprintf(b, sizeof b, "%lx", (unsigned long)a); return std::string(b); }(addr);
}

// names are interned: a stack is a vector of small ints
struct Names {
  std::vector<std::string> s;
  std::unordered_map<std::string, uint32_t> at;
  uint32_t id(const std::string& n) {
    auto [it, fresh] = at.try_emplace(n, s.size());
    if (fresh) s.push_back(n);
    return it->second;
  }
};

// Names frames, with an update frame named by its thunk's creator when the
// thunk's info table is known (`X [thunk]'); memoised per address.
class FrameNamer {
 public:
  FrameNamer(const hsm::Map& m, Names& N) : m_(m), N_(N) {}

  // thunk_name(ui): "" none, "\x01" blackholed (creator lost), else the name
  const std::string& thunk_name(uint64_t ui) {
    auto [it, fresh] = tcache_.try_emplace(ui);
    if (!fresh) return it->second;
    const hsm::Entry* e = m_.resolve_info(ui);
    if (e && m_.str(e->closure_type_name).starts_with("THUNK") && !name(m_, hit(e), "").empty())
      return it->second = name(m_, hit(e), "") + " [thunk]";
    hsm::Hit b = e ? hit(e) : m_.resolve_addr(ui);
    std::string bn;
    if (b) {
      uint32_t t = b.e->toplevel ? b.e->toplevel : b.e->name;
      bn = std::string(m_.str(b.e->symbol)) + " " + std::string(m_.str(t));
    }
    return it->second = bn.find("BLACKHOLE_info") != bn.npos ? "\x01" : "";
  }

  // frame_name(f, ui) as a Names id; counts the thunk outcome in stat
  uint32_t frame_id(uint64_t fr, uint64_t ui) {
    const std::string& t = ui ? thunk_name(ui) : empty_;
    bool named = !t.empty() && t != "\x01";
    if (ui) (named ? named_ : t == "\x01" ? blackholed_ : other_)++;
    if (named) return N_.id(t);
    auto key = fr;
    auto it = fcache_.find(key);
    if (it != fcache_.end()) return it->second;
    const hsm::Entry* ie = m_.resolve_info(fr);
    uint32_t id = N_.id(name(m_, ie ? hit(ie) : m_.resolve_addr(fr), owner_or(m_, fr, true)));
    fcache_.emplace(key, id);
    return id;
  }

  // the leaf: resolve_leaf (DWARF applies) + owner fallback
  uint32_t leaf_id(uint64_t pc, hsm::Hit* out = nullptr) {
    hsm::Hit e = m_.resolve_leaf(pc);
    if (out) *out = e;
    auto it = lcache_.find(pc);
    if (it != lcache_.end()) return it->second;
    uint32_t id = N_.id(name(m_, e, owner_or(m_, pc, false)));
    lcache_.emplace(pc, id);
    return id;
  }

  long long named_ = 0, blackholed_ = 0, other_ = 0;

 private:
  const hsm::Map& m_;
  Names& N_;
  std::string empty_;
  std::unordered_map<uint64_t, std::string> tcache_;
  std::unordered_map<uint64_t, uint32_t> fcache_, lcache_;
};

}  // namespace naming
