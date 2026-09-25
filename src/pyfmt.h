// Output helpers that reproduce Python's formatting byte for byte, so hsp's
// reports can be diffed against the Python tools they replace.
#pragma once
#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace pyfmt {

// printf into a std::string.
inline std::string f(const char* fmt, ...) {
  va_list ap, ap2;
  va_start(ap, fmt);
  va_copy(ap2, ap);
  int n = std::vsnprintf(nullptr, 0, fmt, ap);
  va_end(ap);
  std::string s(n, '\0');
  std::vsnprintf(s.data(), n + 1, fmt, ap2);
  va_end(ap2);
  return s;
}

// Python repr() of a str: single quotes unless the text has a ' and no ".
inline std::string repr(std::string_view s) {
  bool sq = s.find('\'') != s.npos, dq = s.find('"') != s.npos;
  char q = (sq && !dq) ? '"' : '\'';
  std::string o(1, q);
  for (unsigned char c : s) {
    if (c == q || c == '\\') { o += '\\'; o += char(c); }
    else if (c == '\t') o += "\\t";
    else if (c == '\n') o += "\\n";
    else if (c == '\r') o += "\\r";
    else if (c < 0x20 || c == 0x7f) o += f("\\x%02x", c);
    else o += char(c);
  }
  return o + q;
}

// f"{n:,}"
inline std::string commas(long long n) {
  std::string d = std::to_string(n < 0 ? -n : n), o;
  for (size_t i = 0; i < d.size(); i++) {
    if (i && (d.size() - i) % 3 == 0) o += ',';
    o += d[i];
  }
  return n < 0 ? "-" + o : o;
}

// f"{a:#x}" -- Python prints 0 as 0x0, printf's %#x prints it as 0.
inline std::string hex(uint64_t a) { return f("0x%lx", (unsigned long)a); }

// repr() of a float: the shortest text that reads back as the same double,
// with ".0" when it looks like an integer (1.0, 0.25, 1e-05)
inline std::string float_repr(double x) {
  std::string s;
  for (int prec = 1; prec <= 17; prec++) {
    s = f("%.*g", prec, x);
    if (std::strtod(s.c_str(), nullptr) == x) break;
  }
  if (s.find_first_of(".en") == s.npos) s += ".0";
  return s;
}

// collections.Counter: counts plus first-insertion order, which is how
// most_common() breaks ties.
template <class K, class H = std::hash<K>>
struct Counter {
  std::unordered_map<K, size_t, H> at;
  std::vector<std::pair<K, long long>> items;

  void add(const K& k, long long v = 1) {
    auto [it, fresh] = at.try_emplace(k, items.size());
    if (fresh) items.emplace_back(k, 0);
    items[it->second].second += v;
  }
  long long get(const K& k) const {
    auto it = at.find(k);
    return it == at.end() ? 0 : items[it->second].second;
  }
  long long total() const {
    long long t = 0;
    for (auto& kv : items) t += kv.second;
    return t;
  }
  bool empty() const { return items.empty(); }
  // highest count first; equal counts keep insertion order (stable sort)
  std::vector<std::pair<K, long long>> most_common(size_t n = SIZE_MAX) const {
    auto v = items;
    std::stable_sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second > b.second; });
    if (v.size() > n) v.resize(n);
    return v;
  }
};

// Python repr() of a dict whose keys are str: {'a': 1, 'b': 2}
template <class It>
std::string dict_str(It b, It e) {
  std::string o = "{";
  for (auto it = b; it != e; ++it) {
    if (it != b) o += ", ";
    o += repr(it->first) + ": " + std::to_string(it->second);
  }
  return o + "}";
}
template <class V> std::string dict_str(const V& v) { return dict_str(v.begin(), v.end()); }

}  // namespace pyfmt
