// GHC Z-encoding decoder and the splitter for the symbol names it produces:
// a port of the earlier Python decoder (whose docstring explains the heuristics).
// `zdecode' is exact (GHC.Utils.Encoding.zDecodeString); `parse_symbol' is
// the <package>_<Module>_<name>_<suffix> split with the local-tail, worker
// and main-unit rules.
#pragma once
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace zdec {

inline bool isdig(char c) { return c >= '0' && c <= '9'; }
inline bool ishex(char c) { return isdig(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

// s[i] is the digit after 'Z': consume <digits>(T|H); on no terminator emit
// the 'Z' literally (GHC uniques are base-62: sat_s2dZ0)
inline size_t decode_tuple(std::string_view s, size_t i, std::string& out) {
  size_t start = i; unsigned long num = 0;
  while (i < s.size() && isdig(s[i])) { num = num * 10 + (s[i] - '0'); i++; }
  if (i < s.size() && s[i] == 'T') {
    if (num == 0) out += "()"; else { out += '('; out.append(num - 1, ','); out += ')'; }
    return i + 1;
  }
  if (i < s.size() && s[i] == 'H') {
    if (num == 1) out += "(# #)"; else { out += "(#"; out.append(num - 1, ','); out += "#)"; }
    return i + 1;
  }
  out += s[start - 1];
  return start;
}

inline void put_utf8(std::string& o, unsigned long cp) {
  if (cp < 0x80) o += char(cp);
  else if (cp < 0x800) { o += char(0xC0 | (cp >> 6)); o += char(0x80 | (cp & 0x3F)); }
  else if (cp < 0x10000) { o += char(0xE0 | (cp >> 12)); o += char(0x80 | ((cp >> 6) & 0x3F)); o += char(0x80 | (cp & 0x3F)); }
  else { o += char(0xF0 | (cp >> 18)); o += char(0x80 | ((cp >> 12) & 0x3F)); o += char(0x80 | ((cp >> 6) & 0x3F)); o += char(0x80 | (cp & 0x3F)); }
}

// s[i] is the digit after 'z': consume <hex>U, else emit 'z' literally
inline size_t decode_num_esc(std::string_view s, size_t i, std::string& out) {
  size_t start = i; unsigned long num = 0;
  while (i < s.size() && ishex(s[i])) { num = num * 16 + (isdig(s[i]) ? s[i] - '0' : (tolower(s[i]) - 'a' + 10)); i++; }
  if (i < s.size() && s[i] == 'U') { put_utf8(out, num); return i + 1; }
  out += s[start - 1];
  return start;
}

inline std::string zdecode(std::string_view s) {
  std::string out; out.reserve(s.size());
  size_t i = 0, n = s.size();
  while (i < n) {
    char c = s[i];
    if (c == 'Z' && i + 1 < n) {
      char d = s[i + 1];
      if (isdig(d)) { i = decode_tuple(s, i + 1, out); continue; }
      switch (d) { case 'L': out += '('; break; case 'R': out += ')'; break; case 'M': out += '['; break;
                   case 'N': out += ']'; break; case 'C': out += ':'; break; case 'Z': out += 'Z'; break; default: out += d; }
      i += 2; continue;
    }
    if (c == 'z' && i + 1 < n) {
      char d = s[i + 1];
      if (isdig(d)) { i = decode_num_esc(s, i + 1, out); continue; }
      switch (d) { case 'z': out += 'z'; break; case 'a': out += '&'; break; case 'b': out += '|'; break; case 'c': out += '^'; break;
                   case 'd': out += '$'; break; case 'e': out += '='; break; case 'g': out += '>'; break; case 'h': out += '#'; break;
                   case 'i': out += '.'; break; case 'l': out += '<'; break; case 'm': out += '-'; break; case 'n': out += '!'; break;
                   case 'p': out += '+'; break; case 'q': out += '\''; break; case 'r': out += '\\'; break; case 's': out += '/'; break;
                   case 't': out += '*'; break; case 'u': out += '_'; break; case 'v': out += '%'; break; default: out += d; }
      i += 2; continue;
    }
    out += c; i++;
  }
  return out;
}

struct Parsed {
  std::string package, package_name, package_version, module, name, suffix;
  bool is_local = false;
};

inline std::vector<std::string_view> split_us(std::string_view s) {
  std::vector<std::string_view> t; size_t b = 0;
  for (size_t i = 0; i <= s.size(); i++) if (i == s.size() || s[i] == '_') { t.push_back(s.substr(b, i - b)); b = i + 1; }
  return t;
}

// ^[A-Za-z]{0,4}[0-9][A-Za-z0-9]*$
inline bool uniq_tail(std::string_view t) {
  size_t i = 0;
  while (i < t.size() && i < 4 && isalpha((unsigned char)t[i])) i++;
  if (i >= t.size() || !isdig(t[i])) return false;
  for (; i < t.size(); i++) if (!isalnum((unsigned char)t[i])) return false;
  return true;
}

inline bool looks_like_module(std::string_view enc) {
  std::string d = zdecode(enc);
  std::string_view s = d;
  if (s.starts_with(":")) s = s.substr(1);
  return !s.empty() && isupper((unsigned char)s[0]);
}

// package_module_name (3 tokens) or module_name (2, main unit)
inline bool try_shape(const std::vector<std::string_view>& head, std::string_view& pkg, std::string_view& mod, std::string_view& name, bool& has_pkg) {
  if (head.size() == 3 && looks_like_module(head[1])) { pkg = head[0]; mod = head[1]; name = head[2]; has_pkg = true; return true; }
  if (head.size() == 2 && looks_like_module(head[0])) { mod = head[0]; name = head[1]; has_pkg = false; return true; }
  return false;
}

inline bool version_like(std::string_view p) {   // ^\d+(\.\d+)*$
  if (p.empty() || !isdig(p[0])) return false;
  bool prev_dot = false;
  for (size_t i = 0; i < p.size(); i++) {
    if (p[i] == '.') { if (prev_dot || i + 1 == p.size()) return false; prev_dot = true; }
    else if (isdig(p[i])) prev_dot = false;
    else return false;
  }
  return true;
}

inline std::optional<Parsed> parse_symbol(std::string_view sym) {
  if (sym.empty() || sym.find('_') == sym.npos) return std::nullopt;
  auto tokens = split_us(sym);
  std::string suffix;
  size_t n = tokens.size();
  if (n >= 2) {
    std::string_view a = tokens[n - 2], b = tokens[n - 1];
    if ((a == "con" && b == "info") || (a == "con" && b == "entry") || (a == "static" && b == "info") || (a == "closure" && b == "tbl")) {
      suffix = std::string(a) + "_" + std::string(b); tokens.resize(n - 2);
    }
  }
  if (suffix.empty()) {
    std::string_view b = tokens[n - 1];
    if (b == "info" || b == "closure" || b == "entry" || b == "slow" || b == "fast" || b == "ret" || b == "bytes" || b == "srt") {
      suffix = std::string(b); tokens.resize(n - 1);
    } else return std::nullopt;
  }
  n = tokens.size();
  std::string_view pkg, mod, name; bool has_pkg = false, is_local = false;
  std::string name_buf;
  if (!try_shape(tokens, pkg, mod, name, has_pkg)) {
    bool ok = false;
    for (size_t cut = 1; cut + 1 < n; cut++) {
      bool all = true;
      for (size_t k = n - cut; k < n; k++) if (!uniq_tail(tokens[k])) { all = false; break; }
      if (!all) break;
      std::vector<std::string_view> head(tokens.begin(), tokens.begin() + (n - cut));
      if (try_shape(head, pkg, mod, name, has_pkg)) {
        name_buf = std::string(name);
        for (size_t k = n - cut; k < n; k++) { name_buf += '_'; name_buf += tokens[k]; }
        name = name_buf; is_local = true; ok = true; break;
      }
    }
    if (!ok) return std::nullopt;
  }
  Parsed p;
  p.module = zdecode(mod);
  p.name = zdecode(name);
  p.suffix = suffix;
  if (!is_local && (p.name.starts_with("$w") || p.name.starts_with("$s") || p.name.starts_with("$j"))) is_local = true;
  p.is_local = is_local;
  p.package = has_pkg ? zdecode(pkg) : "main";
  // split_package_id: the first '-' field that is digits and dots is the version
  auto parts = split_us(p.package);   // reuse: split on '-' instead
  parts.clear();
  { size_t b = 0; std::string_view s = p.package;
    for (size_t i = 0; i <= s.size(); i++) if (i == s.size() || s[i] == '-') { parts.push_back(s.substr(b, i - b)); b = i + 1; } }
  p.package_name = p.package;
  for (size_t i = 0; i < parts.size(); i++)
    if (version_like(parts[i])) {
      std::string nm; for (size_t k = 0; k < i; k++) { if (k) nm += '-'; nm += parts[k]; }
      p.package_name = nm.empty() ? p.package : nm;
      p.package_version = std::string(parts[i]);
      break;
    }
  return p;
}

// split_symbol: parse_symbol, with -fdistinct-constructor-tables' extra
// "<UsingModule>_<N>" pair peeled and folded into the name, and the home
// unit shape (module read as package) normalised to package "main".
inline std::optional<Parsed> split_symbol(std::string_view sym) {
  auto d = parse_symbol(sym);
  if (!d) {
    // ^(?P<head>.+?)_(?P<usage>[A-Za-z][A-Za-z0-9]*)_(?P<n>\d+)_(con_info|con_entry)$
    std::string_view suf;
    if (sym.ends_with("_con_info")) suf = "con_info"; else if (sym.ends_with("_con_entry")) suf = "con_entry";
    if (!suf.empty()) {
      std::string_view rest = sym.substr(0, sym.size() - suf.size() - 1);
      auto toks = split_us(rest);
      // the non-greedy head takes the fewest tokens: find the first split where
      // usage and n match; head must be non-empty
      for (size_t i = 1; i + 2 <= toks.size(); i++) {
        std::string_view usage = toks[i], num = toks[i + 1];
        if (i + 2 != toks.size()) continue;
        bool u = !usage.empty() && isalpha((unsigned char)usage[0]);
        for (char c : usage) if (!isalnum((unsigned char)c)) u = false;
        bool nn = !num.empty(); for (char c : num) if (!isdig(c)) nn = false;
        if (!u || !nn) continue;
        std::string head; for (size_t k = 0; k < i; k++) { if (k) head += '_'; head += toks[k]; }
        auto d2 = parse_symbol(head + "_" + std::string(suf));
        if (d2) { d2->name += "_" + std::string(usage) + "_" + std::string(num); d = d2; }
        break;
      }
    }
    if (!d) return std::nullopt;
  }
  if (!d->package.empty() && (isupper((unsigned char)d->package[0]) || d->package[0] == '(')) {
    d->module = d->package; d->package = "main"; d->package_name = "main"; d->package_version.clear();
  }
  return d;
}

}  // namespace zdec
