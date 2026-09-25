#include "capture.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <unordered_map>

#include "hsp_abi.h"

namespace {

// Python str.split(): runs of whitespace, no empty fields
std::vector<std::string_view> split(std::string_view l) {
  std::vector<std::string_view> p;
  auto ws = [](unsigned char c) { return c == ' ' || (c >= 9 && c <= 13) || (c >= 0x1c && c <= 0x1f); };
  for (size_t i = 0; i < l.size();) {
    while (i < l.size() && ws(l[i])) i++;
    size_t b = i;
    while (i < l.size() && !ws(l[i])) i++;
    if (i > b) p.push_back(l.substr(b, i - b));
  }
  return p;
}
uint64_t hexnum(std::string_view s) { return std::strtoull(std::string(s).c_str(), nullptr, 16); }
long long decnum(std::string_view s) { return std::strtoll(std::string(s).c_str(), nullptr, 10); }
bool isdigits(std::string_view s) {
  return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
}
std::string join(const std::vector<std::string_view>& p, size_t from) {
  std::string o;
  for (size_t i = from; i < p.size(); i++) { if (i > from) o += ' '; o += p[i]; }
  return o;
}

// bpftrace text, exactly as hswalk_agg.py reads it: per tid, F lines
// accumulate until the E line; an L line before the E line is the running
// green thread.
void read_text(std::ifstream& in, const std::function<void(RawSample&)>& cb) {
  std::unordered_map<std::string, std::vector<uint64_t>> pending, thunks;
  struct Label { std::string hid, label; bool has_ts, has_cnt; long long ts, cnt; };
  std::unordered_map<std::string, Label> labels;
  std::string line;
  while (std::getline(in, line)) {
    auto p = split(line);
    if (p.empty()) continue;
    if (p[0] == "L" && p.size() >= 4) {
      if (p.size() >= 6 && isdigits(p[3])) {       // L tid hid nsecs alloc|? label
        bool c = p[4] != "?";
        labels[std::string(p[1])] = {std::string(p[2]), join(p, 5), true, c, decnum(p[3]), c ? decnum(p[4]) : 0};
      } else {                                      // older: L tid hid label
        labels[std::string(p[1])] = {std::string(p[2]), join(p, 3), false, false, 0, 0};
      }
      continue;
    }
    if (p[0] == "F" && p.size() >= 4 && p.size() <= 6) {
      pending[std::string(p[1])].push_back(hexnum(p[3]));
      thunks[std::string(p[1])].push_back(p.size() >= 5 ? hexnum(p[4]) : 0);
    } else if (p[0] == "E" && p.size() == 8) {
      RawSample s;
      s.tid = std::string(p[1]);
      s.pc = hexnum(p[2]);
      s.status = decnum(p[3]);
      s.depth = decnum(p[4]); s.hops = decnum(p[5]); s.scanned = decnum(p[6]); s.cost = decnum(p[7]);
      auto pit = pending.find(s.tid);
      if (pit != pending.end()) { s.frames = std::move(pit->second); pending.erase(pit); }
      auto lit = labels.find(s.tid);
      if (lit != labels.end()) {
        s.has_hid = true; s.hid = lit->second.hid; s.label = lit->second.label;
        s.has_ts = lit->second.has_ts; s.ts = lit->second.ts;
        s.has_acnt = lit->second.has_cnt; s.acnt = lit->second.cnt;
        labels.erase(lit);
      }
      s.updatees.assign(s.frames.size(), 0);
      auto tit = thunks.find(s.tid);
      if (tit != thunks.end()) { s.updatees = std::move(tit->second); thunks.erase(tit); }
      cb(s);
    }
  }
}

// hsp record: the file header, then hs_rec records with 2*depth trailing words
void read_binary(std::ifstream& in, const char* path, const std::function<void(RawSample&)>& cb) {
  hs_file_hdr fh;
  in.read(reinterpret_cast<char*>(&fh), sizeof fh);
  if (!in || fh.version != 1 || fh.hdr_size < sizeof fh)
    throw std::runtime_error(std::string(path) + ": unsupported HSPREC header");
  in.seekg(fh.hdr_size);
  std::vector<char> buf(sizeof(hs_rec));
  for (size_t n = 0;; n++) {
    in.read(buf.data(), HS_REC_FIXED);
    if (in.gcount() == 0) break;
    if (in.gcount() != std::streamsize(HS_REC_FIXED))
      throw std::runtime_error(std::string(path) + ": truncated record " + std::to_string(n));
    const hs_rec* r = reinterpret_cast<const hs_rec*>(buf.data());
    if (r->depth > HS_MAX_DEPTH) throw std::runtime_error(std::string(path) + ": bad depth in record " + std::to_string(n));
    size_t words = 2 * r->depth;
    in.read(buf.data() + HS_REC_FIXED, words * 8);
    if (in.gcount() != std::streamsize(words * 8))
      throw std::runtime_error(std::string(path) + ": truncated frames in record " + std::to_string(n));
    r = reinterpret_cast<const hs_rec*>(buf.data());
    RawSample s;
    s.tid = std::to_string(r->tid);
    s.pc = r->pc;
    s.status = r->status; s.depth = r->depth; s.hops = r->hops; s.scanned = r->scanned; s.cost = r->cost_ns;
    s.frames.resize(r->depth); s.updatees.resize(r->depth);
    for (unsigned i = 0; i < r->depth; i++) { s.frames[i] = r->frames[2 * i]; s.updatees[i] = r->frames[2 * i + 1]; }
    if (r->flags & HS_F_TSO) {
      s.has_hid = true;
      s.hid = std::to_string(r->tso_id);
      s.label = (r->flags & HS_F_LABEL) ? std::string(r->label, std::min<size_t>(r->label_len, HS_LABEL_MAX)) : "-";
      s.has_ts = true; s.ts = (long long)r->ts_ns;
      s.has_acnt = r->flags & HS_F_ALLOC; s.acnt = r->alloc;
    }
    cb(s);
  }
}

}  // namespace

void read_capture(const char* path, const std::function<void(RawSample&)>& cb) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error(std::string(path) + ": cannot open");
  char magic[8] = {};
  in.read(magic, 8);
  in.clear();
  in.seekg(0);
  if (std::memcmp(magic, HS_FILE_MAGIC, 8) == 0) read_binary(in, path, cb);
  else read_text(in, cb);
}
