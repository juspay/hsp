// hsp fold: hswalk_agg.py in C++. Resolves the sampler's output (bpftrace
// hswalk*.bt lines) through an .hsm, prints the same report and writes the
// same collapsed-stack files, byte for byte.
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "capture.h"
#include "hsm.h"
#include "naming.h"
#include "pyfmt.h"

using namespace hsm;
using pyfmt::Counter;
using pyfmt::f;

namespace {

// hash for the audit's (what, address) and (leaf, site) keys
struct PairHash {
  size_t operator()(const std::pair<int, uint64_t>& p) const { return std::hash<uint64_t>()(p.second * 2 + p.first); }
};
struct PairHash32 {
  size_t operator()(const std::pair<uint32_t, uint32_t>& p) const { return std::hash<uint64_t>()((uint64_t(p.first) << 32) | p.second); }
};

const char* STATUS[] = {nullptr, "stop", "badframe", "bco", "depth-cap", "noframe"};

using naming::name; using naming::hit; using naming::haskell_mode; using naming::exact_rollup;
using naming::owner_of; using naming::owner_or; using naming::Names;

struct Sample {
  uint64_t pc;
  std::vector<uint64_t> frames_raw;
  bool has_hid = false;
  std::string hid, label;          // label "" = None
  bool has_ts = false, has_acnt = false;
  long long ts = 0, acnt = 0, alloc = 0;
  uint32_t leaf;
  std::string sym;
  bool haskell;
  std::string status;
  long long depth, hops, scanned, cost;
  std::vector<uint32_t> stack;
  std::vector<uint32_t> guessed;   // a set; small, so a sorted vector
  bool leaf_guessed;
  const char* leaf_dwarf;          // nullptr = None
  uint32_t leaf_site;              // 0 = None; else a Names id + 1
};

// "{k} {n} ({pct:.1f}%)" for exact / extent / unresolved
std::string row(const Counter<std::string>& c) {
  long long t = c.total();
  if (!t) t = 1;
  std::string o;
  for (const char* k : {"exact", "extent", "unresolved"}) {
    if (!o.empty()) o += "  ";
    o += f("%s %lld (%.1f%%)", k, c.get(k), 100.0 * c.get(k) / t);
  }
  return o;
}

int audit(const Map& m, const std::vector<Sample>& samples, const Names& N, double max_unresolved) {
  auto klass = [](const Hit& h) -> const char* { return !h ? "unresolved" : h.match ? "extent" : "exact"; };
  Counter<std::string> leaf, frame, roll, heur, inl;
  std::vector<std::pair<std::string, Counter<std::string>>> by_bucket;   // insertion order
  std::unordered_map<std::string, size_t> by_bucket_at;
  Counter<std::pair<int, uint64_t>, PairHash> unres;
  auto count_roll = [&](const Hit& h) {
    std::string_view r = m.str(h.e->rollup);
    roll.add(exact_rollup(r) ? "exact" : "heuristic");
    if (!exact_rollup(r)) heur.add(name(m, h, "?"));
  };
  for (const Sample& s : samples) {
    Hit e = m.resolve_addr(s.pc);
    leaf.add(klass(e));
    if (!e) unres.add({0, s.pc});
    else count_roll(e);
    for (uint64_t fr : s.frames_raw) {
      const Entry* ie = m.resolve_info(fr);
      Hit a = ie ? Hit{} : m.resolve_addr(fr);
      const char* k = ie ? "exact" : klass(a);
      Hit h = ie ? hit(ie) : a;
      if (h && h.e->inlined) inl.add(std::string(m.str(h.e->inlined)));
      frame.add(k);
      std::string b = h && h.e->bucket ? std::string(m.str(h.e->bucket)) : "none";
      auto [it, fresh] = by_bucket_at.try_emplace(b, by_bucket.size());
      if (fresh) by_bucket.push_back({b, {}});
      by_bucket[it->second].second.add(k);
      if (!h) unres.add({1, fr});
      else count_roll(h);
    }
  }
  std::printf("\nresolution audit\n");
  std::printf("  leaf PCs      %s\n", row(leaf).c_str());
  std::printf("  caller frames %s\n", row(frame).c_str());
  std::stable_sort(by_bucket.begin(), by_bucket.end(),
                   [](auto& a, auto& b) { return a.second.total() > b.second.total(); });
  for (auto& [b, c] : by_bucket) std::printf("      %-8s %s\n", b.c_str(), row(c).c_str());
  long long rt = roll.total() ? roll.total() : 1;
  std::printf("  roll-up to top level  exact %lld (%.1f%%)  heuristic (addr-adjacency) %lld (%.1f%%)\n",
              roll.get("exact"), 100.0 * roll.get("exact") / rt, roll.get("heuristic"), 100.0 * roll.get("heuristic") / rt);
  if (!heur.empty()) std::printf("      heuristic roll-ups, most frequent: %s\n", pyfmt::dict_str(heur.most_common(5)).c_str());
  if (!inl.empty())
    std::printf("  frames in inlined code: %lld (named by the enclosing binding of their module, by address -- "
                "counted in heuristic above); top origins: %s\n", inl.total(), pyfmt::dict_str(inl.most_common(5)).c_str());
  if (!unres.empty()) {
    std::printf("  unresolved, most frequent (what, address, nearest ELF symbol):\n");
    for (auto& [k, c] : unres.most_common(10))
      std::printf("      %5lld  %-5s %s  %s\n", c, k.first ? "frame" : "leaf", pyfmt::hex(k.second).c_str(), m.near(k.second).c_str());
  }
  Counter<std::string> dw;
  for (const Sample& s : samples) dw.add(s.leaf_dwarf ? s.leaf_dwarf : "no DWARF line / not applied");
  bool any_dw = false;
  for (auto& kv : dw.items) if (kv.first != "no DWARF line / not applied") any_dw = true;
  if (any_dw) {
    std::printf("  leaf DWARF    confirmed %lld  rescued-a-guess %lld  inlined (origin kept, site noted) %lld  none %lld\n",
                dw.get("confirmed"), dw.get("rescued"), dw.get("site"), dw.get("no DWARF line / not applied"));
    Counter<std::pair<uint32_t, uint32_t>, PairHash32> sites;
    for (const Sample& s : samples) if (s.leaf_site) sites.add({s.leaf, s.leaf_site - 1});
    if (!sites.empty()) {
      std::string o;
      for (auto& [k, c] : sites.most_common(4)) {
        if (!o.empty()) o += ", ";
        o += f("%s inlined into %s (%lld)", N.s[k.first].c_str(), N.s[k.second].c_str(), c);
      }
      std::printf("      most common inlining sites: %s\n", o.c_str());
    }
  }
  std::vector<std::pair<std::string, long long>> attributed;   // insertion order, like the dict
  auto attr = [&](const std::string& k, long long c) {
    for (auto& kv : attributed) if (kv.first == k) { kv.second += c; return; }
    attributed.push_back({k, c});
  };
  long long nothing = 0;
  // dict iteration: unres.items() in insertion order
  for (auto& [k, c] : unres.items) {
    if (owner_of(m, k.second, k.first == 1)) attr(k.first ? "module (frame)" : "package (leaf)", c);
    else nothing += c;
  }
  if (!unres.empty())
    std::printf("  unresolved by name, attributed instead to: %s   no owner at all: %lld\n", pyfmt::dict_str(attributed).c_str(), nothing);
  long long total = leaf.total() + frame.total();
  double pct = 100.0 * nothing / std::max(1LL, total);
  bool pass = pct <= max_unresolved;
  std::printf("  GATE unattributed %lld/%lld = %.2f%%  (limit %s%%)  -> %s\n", nothing, total, pct,
              pyfmt::float_repr(max_unresolved).c_str(), pass ? "PASS" : "FAIL");
  return pass ? 0 : 3;
}

}  // namespace

int cmd_fold(int argc, char** argv) {
  if (argc < 3) {
    std::fprintf(stderr, "usage: hsp fold CAPTURE MAP.hsm OUTDIR [--max-unresolved PCT] [--no-lines]\n");
    return 2;
  }
  const char* path = argv[0];
  std::string outdir = argv[2];
  auto join_path = [&](const char* fn) { return outdir.ends_with("/") ? outdir + fn : outdir + "/" + fn; };
  double max_unresolved = 1.0;
  bool lines = true;
  for (int i = 3; i < argc; i++) {
    if (!std::strcmp(argv[i], "--max-unresolved") && i + 1 < argc) max_unresolved = std::atof(argv[++i]);
    else if (!std::strcmp(argv[i], "--no-lines")) lines = false;
  }
  Map m = Map::open(argv[1]);
  m.use_lines(lines);
  if (lines && m.n_lines()) std::printf("DWARF lines attached: %s rows\n", pyfmt::commas(m.n_lines()).c_str());
  Names N;

  // thunk_name(ui): the creator of an update frame's thunk; "" none, "\x01" blackholed
  std::unordered_map<uint64_t, std::string> tcache;
  auto thunk_name = [&](uint64_t ui) -> const std::string& {
    auto [it, fresh] = tcache.try_emplace(ui);
    if (!fresh) return it->second;
    const Entry* e = m.resolve_info(ui);
    if (e && m.str(e->closure_type_name).starts_with("THUNK") && !name(m, hit(e), "").empty())
      return it->second = name(m, hit(e), "") + " [thunk]";
    Hit b = e ? hit(e) : m.resolve_addr(ui);
    std::string bn;
    if (b) {
      uint32_t t = b.e->toplevel ? b.e->toplevel : b.e->name;
      bn = std::string(m.str(b.e->symbol)) + " " + std::string(m.str(t));
    }
    return it->second = bn.find("BLACKHOLE_info") != bn.npos ? "\x01" : "";
  };
  Counter<std::string> thunk_stat;
  auto frame_name = [&](uint64_t fr, uint64_t ui) -> std::string {
    const std::string& t = ui ? thunk_name(ui) : std::string();
    bool named = !t.empty() && t != "\x01";
    if (ui) thunk_stat.add(named ? "creator named" : t == "\x01" ? "blackholed (creator lost)" : "other");
    if (named) return t;
    const Entry* ie = m.resolve_info(fr);
    return name(m, ie ? hit(ie) : m.resolve_addr(fr), owner_or(m, fr, true));
  };

  std::vector<Sample> samples;
  read_capture(path, [&](RawSample& rs) {
      Sample s;
      s.pc = rs.pc;
      s.depth = rs.depth; s.hops = rs.hops; s.scanned = rs.scanned; s.cost = rs.cost;
      s.frames_raw = std::move(rs.frames);
      s.has_hid = rs.has_hid; s.hid = rs.hid; s.label = rs.label;
      s.has_ts = rs.has_ts; s.ts = rs.ts; s.has_acnt = rs.has_acnt; s.acnt = rs.acnt;
      const std::vector<uint64_t>& uis = rs.updatees;
      Hit e = m.resolve_leaf(s.pc);
      s.sym = e ? std::string(e.e->symbol ? m.str(e.e->symbol) : m.str(e.e->name)) : "";
      s.leaf = N.id(name(m, e, owner_or(m, s.pc, false)));
      s.haskell = haskell_mode(s.sym);
      s.status = rs.status >= 1 && rs.status <= 5 ? STATUS[rs.status] : std::to_string(rs.status);
      // zip(frames, uis): the shorter one decides
      size_t nz = std::min(s.frames_raw.size(), uis.size());
      for (size_t i = 0; i < nz; i++) s.stack.push_back(N.id(frame_name(s.frames_raw[i], uis[i])));
      for (uint64_t fr : s.frames_raw) {
        if (m.resolve_info(fr)) continue;
        Hit a = m.resolve_addr(fr);
        if (a && !a.match) continue;
        s.guessed.push_back(N.id(name(m, a, owner_or(m, fr, true))));
      }
      std::sort(s.guessed.begin(), s.guessed.end());
      s.guessed.erase(std::unique(s.guessed.begin(), s.guessed.end()), s.guessed.end());
      s.leaf_guessed = e && e.match != Hit::NONE && e.match != Hit::DWARF_LINE;
      s.leaf_dwarf = !e ? nullptr : e.match == Hit::DWARF_LINE ? "rescued" : e.site ? "site" : e.dwarf ? "confirmed" : nullptr;
      s.leaf_site = e && e.site ? N.id(std::string(m.str(e.site))) + 1 : 0;
      samples.push_back(std::move(s));
  });
  if (samples.empty()) { std::printf("no samples\n"); return 1; }

  if (!thunk_stat.empty()) {
    long long tt = thunk_stat.total();
    std::string o;
    for (auto& [k, v] : thunk_stat.most_common()) {
      if (!o.empty()) o += ", ";
      o += f("%s %lld (%.1f%%)", k.c_str(), v, 100.0 * v / tt);
    }
    std::printf("thunk creators (hswalk_thunk.bt): update frames %s\n", o.c_str());
  }
  std::vector<const Sample*> h, c;
  for (auto& s : samples) (s.haskell ? h : c).push_back(&s);
  std::printf("samples in .text: %zu   haskell-mode %zu   c-mode %zu\n", samples.size(), h.size(), c.size());
  for (auto [label, group] : {std::pair{"haskell-mode", &h}, std::pair{"c-mode", &c}}) {
    if (group->empty()) continue;
    Counter<std::string> st;
    for (auto* s : *group) st.add(s->status);
    std::printf("  %-13s status: %s\n", label, pyfmt::dict_str(st.items).c_str());
  }
  auto leaves = [&](const std::vector<const Sample*>& g) {
    Counter<std::string> lc;
    for (auto* s : g) lc.add(N.s[s->leaf]);
    return pyfmt::dict_str(lc.most_common(8));
  };
  if (!h.empty()) {
    std::map<long long, long long> scan;
    for (auto* s : h) scan[s->scanned]++;
    std::string o = "{";
    for (auto& [k, v] : scan) o += (o.size() > 1 ? ", " : "") + std::to_string(k) + ": " + std::to_string(v);
    std::printf("  scan (words skipped above Sp): %s}\n", o.c_str());
    std::vector<long long> d, hp, costs;
    std::vector<double> per;
    for (auto* s : h) {
      d.push_back(s->depth); hp.push_back(s->hops); costs.push_back(s->cost);
      per.push_back(double(s->cost) / std::max(1LL, s->depth));
    }
    std::sort(d.begin(), d.end()); std::sort(hp.begin(), hp.end()); std::sort(costs.begin(), costs.end());
    std::printf("  depth min/median/max %lld/%lld/%lld   chunk hops max %lld\n", d[0], d[d.size() / 2], d.back(), hp.back());
    auto q = [&](double x) { return costs[std::min(costs.size() - 1, size_t(x * costs.size()))]; };
    std::sort(per.begin(), per.end());
    size_t n = per.size();
    double med = n % 2 ? per[n / 2] : (per[n / 2 - 1] + per[n / 2]) / 2;
    std::printf("  walk cost ns  p50 %lld  p90 %lld  p99 %lld  max %lld   (per frame ~%.0f ns)\n",
                q(.5), q(.9), q(.99), costs.back(), med);
    std::printf("  haskell leaves: %s\n", leaves(h).c_str());
  }
  if (!c.empty()) std::printf("  c-mode leaves:  %s\n", leaves(c).c_str());

  // walked samples keep their stack; the rest are bucketed under [c]
  auto body = [&](const Sample& s) {
    std::string o;
    if (s.status == "stop") {
      for (auto it = s.stack.rbegin(); it != s.stack.rend(); ++it) { o += N.s[*it]; o += ';'; }
    } else {
      o = "[c];";
    }
    return o + N.s[s.leaf];
  };
  Counter<std::string> folded;
  for (auto& s : samples) if (s.status == "stop") folded.add(body(s));
  for (auto& s : samples) if (s.status != "stop") folded.add(body(s));

  // self / inclusive per function over walked samples; stg_ frames are the
  // machinery of evaluation, left out of inclusive counts
  auto generic = [&](uint32_t n) { return N.s[n].starts_with("stg_"); };
  Counter<uint32_t> selfc, incl, guess;
  size_t nw = 0;
  for (auto& s : samples) {
    if (s.status != "stop") continue;
    nw++;
    selfc.add(s.leaf);
    std::set<uint32_t> fn(s.stack.begin(), s.stack.end());
    fn.insert(s.leaf);
    // Python iterates a set() here, whose order follows CPython's randomised
    // string hashes, so its ties in incl.most_common() vary run to run. Here
    // ties go by first appearance of the name: deterministic.
    for (uint32_t n : fn) {
      if (generic(n)) continue;
      incl.add(n);
      bool g = std::binary_search(s.guessed.begin(), s.guessed.end(), n) || (n == s.leaf && s.leaf_guessed);
      if (g) guess.add(n);
    }
  }
  std::printf("\nwalked samples %zu of %zu (%.1f%%) -- statistical: +/-%.1f%% per bucket\n", nw, samples.size(),
              100.0 * nw / samples.size(), 100.0 / std::pow(double(std::max<size_t>(1, nw)), 0.5));
  std::printf("  %5s %6s %5s %7s  function\n", "incl", "incl%", "self", "guess%");
  std::printf("  (guess%% = share of this function's evidence named by nearest preceding symbol,\n");
  std::printf("   not an exact hit: right module, probable function -- see the audit)\n");
  for (auto& [n, v] : incl.most_common(25))
    std::printf("  %5lld %6.1f %5lld %6.0f%%  %s\n", v, 100.0 * v / nw, selfc.get(n), 100.0 * guess.get(n) / v, N.s[n].c_str());

  // allocation: per green thread in time order, the drop of its allocation
  // counter between two samples is the bytes it allocated in between
  bool any_acnt = std::any_of(samples.begin(), samples.end(), [](auto& s) { return s.has_acnt; });
  auto root_of = [&](const Sample& s) -> std::string {
    return !s.label.empty() && s.label != "-" ? s.label : s.has_hid ? "(unlabelled thread)" : "(no Haskell thread: C code)";
  };
  if (any_acnt) {
    std::vector<std::pair<std::string, std::vector<Sample*>>> byhid;
    std::unordered_map<std::string, size_t> byhid_at;
    for (auto& s : samples) {
      if (!s.has_acnt) continue;
      auto [it, fresh] = byhid_at.try_emplace(s.hid, byhid.size());
      if (fresh) byhid.push_back({s.hid, {}});
      byhid[it->second].second.push_back(&s);
    }
    long long resets = 0, gaps = 0;
    for (auto& [hid, ss] : byhid) {
      std::stable_sort(ss.begin(), ss.end(), [](auto* a, auto* b) { return a->ts < b->ts; });
      for (size_t i = 1; i < ss.size(); i++) {
        long long d = ss[i - 1]->acnt - ss[i]->acnt;
        if (d < 0) resets++;
        else { ss[i]->alloc = d; gaps++; }
      }
    }
    long long tot = 0;
    for (auto& s : samples) tot += s.alloc;
    std::printf("allocation (hswalk_rid.bt counters): %s bytes attributed over %s intervals in %s green threads; %lld counter resets skipped\n",
                pyfmt::commas(tot).c_str(), pyfmt::commas(gaps).c_str(), pyfmt::commas(byhid.size()).c_str(), resets);
    Counter<std::string> fa, fal;
    for (auto& s : samples) {
      if (!s.alloc) continue;
      std::string b = body(s);
      fa.add(b, s.alloc);
      std::string root = !s.label.empty() && s.label != "-" ? s.label : "(unlabelled thread)";
      fal.add(root + ";" + b, s.alloc);
    }
    for (auto [fn, cc] : {std::pair{"collapsed-alloc.txt", &fa}, std::pair{"collapsed-alloc-labelled.txt", &fal}}) {
      FILE* o = std::fopen(join_path(fn).c_str(), "w");
      for (auto& [k, v] : cc->most_common()) std::fprintf(o, "%s %lld\n", k.c_str(), v);
      std::fclose(o);
    }
    Counter<uint32_t> self_a;
    for (auto& s : samples) if (s.alloc) self_a.add(s.leaf, s.alloc);
    std::printf("  top allocating leaves (approximate: bytes of the interval ending there):\n");
    for (auto& [k, v] : self_a.most_common(8))
      std::printf("    %5.1f%%  %10.1f MB  %s\n", 100.0 * v / std::max(1LL, tot), v / 1e6, N.s[k].c_str());
  }

  // the same stacks with the green thread's label as the root frame
  if (std::any_of(samples.begin(), samples.end(), [](auto& s) { return s.has_hid; })) {
    Counter<std::string> lab, kinds;
    for (auto& s : samples) lab.add(root_of(s) + ";" + body(s));
    for (auto& s : samples)
      kinds.add(s.label.starts_with("rid:") ? "rid" : !s.label.empty() && s.label != "-" ? "other label"
                : s.has_hid ? "unlabelled" : "no thread (C)");
    std::string o;
    for (auto& [k, v] : kinds.most_common()) {
      if (!o.empty()) o += ", ";
      o += f("%s %lld (%.1f%%)", k.c_str(), v, 100.0 * v / samples.size());
    }
    std::printf("green-thread labels: %s\n", o.c_str());
    FILE* fo = std::fopen(join_path("collapsed-labelled.txt").c_str(), "w");
    for (auto& [k, v] : lab.most_common()) std::fprintf(fo, "%s %lld\n", k.c_str(), v);
    std::fclose(fo);
  }
  std::string out = join_path("collapsed.txt");
  FILE* fo = std::fopen(out.c_str(), "w");
  for (auto& [k, v] : folded.most_common()) std::fprintf(fo, "%s %lld\n", k.c_str(), v);
  std::fclose(fo);
  std::printf("collapsed stacks -> %s (%zu distinct)\n", out.c_str(), folded.items.size());
  std::fflush(stdout);
  return audit(m, samples, N, max_unresolved);
}
