// hsp agent: continuous profiling of one GHC process on the host it runs on.
//
//   hsp agent (-p PID | --name COMM) --collector URL [--service NAME]
//             [--interval SECS] [--spool DIR] [--label-mode none|full|tag]
//             [-F hz] [-d depth] [--no-label] [--no-alloc] [--no-thunk]
//   hsp agent --from-capture FILE --exe PATH --collector URL ...   (no root: replays a capture)
//
// Every interval the samples since the last one are folded into distinct
// stacks (info pointers, unresolved) with a sample count and the bytes the
// green threads allocated, and POSTed to the collector as HSPAGG01
// (wire.h).  The host keeps no name map and does no resolution.  If the
// collector is unreachable the batch goes to the spool dir and is retried
// on later intervals; without a spool it is dropped and counted.
//
// The allocation counter is per green thread: the drop between two samples
// of the same thread is the bytes it allocated in between, attributed to
// the later sample's stack (as fold does).  The last counter of every
// thread is remembered across intervals.
#include <curl/curl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "capture.h"
#include "hsp_abi.h"
#include "sampler.h"
#include "wire.h"

namespace {

volatile sig_atomic_t stop_requested;
void on_signal(int) { stop_requested = 1; }

// one aggregation window
struct Batch {
  struct Key {
    uint8_t status; uint32_t label; uint64_t pc; std::vector<uint64_t> frames;   // (info, updatee) pairs
    bool operator==(const Key& o) const { return status == o.status && label == o.label && pc == o.pc && frames == o.frames; }
  };
  struct KeyHash {
    size_t operator()(const Key& k) const {
      uint64_t h = 1469598103934665603ull;
      auto mix = [&](uint64_t v) { h ^= v; h *= 1099511628211ull; };
      mix(k.status); mix(k.label); mix(k.pc);
      for (uint64_t f : k.frames) mix(f);
      return h;
    }
  };
  struct Val { uint64_t count = 0, alloc = 0; };
  std::unordered_map<Key, Val, KeyHash> stacks;
  std::vector<std::string> labels{""};
  std::unordered_map<std::string, uint32_t> label_at{{"", 0}};
  uint64_t from_ns = 0, until_ns = 0, samples = 0;

  uint32_t label_id(const std::string& l) {
    auto [it, fresh] = label_at.try_emplace(l, labels.size());
    if (fresh) labels.push_back(l);
    return it->second;
  }
  void clear() {
    stacks.clear(); labels.assign(1, ""); label_at = {{"", 0}}; from_ns = until_ns = samples = 0;
  }
};

struct Agent {
  std::string service, collector, spool, label_mode = "full";
  std::string host;          // reported host name; empty = gethostname()
  unsigned freq = 99;
  int64_t mono_to_real = 0;      // CLOCK_REALTIME - CLOCK_MONOTONIC, ns
  Batch batch;
  // per green thread: last (ts, counter), for allocation deltas across intervals
  struct Last { uint64_t ts; int64_t acnt; };
  std::unordered_map<uint64_t, Last> last;
  uint64_t sent = 0, failed = 0, spooled = 0, dropped = 0;
  // self-metrics: per interval (reset at flush) and cumulative
  std::string metrics_file;
  uint64_t max_batch_bytes = 64ull << 20, spool_max_bytes = 256ull << 20, batch_bytes = 0;
  struct Walk { uint64_t samples = 0, stop = 0, broken = 0, truncated = 0, noframe = 0, labelled = 0, cost_ns = 0; } iv;
  uint64_t ring_dropped_seen = 0, early_flushes = 0;
  hs_sampler* sampler = nullptr;
  const struct hs_sampler_info* info = nullptr;
  std::string exe; uint64_t exe_size = 0; uint32_t pid = 0;

  void flush(bool early = false);

  std::string label_of(const RawSample& s) {
    if (label_mode == "none" || s.label.empty() || s.label == "-") return "";
    if (label_mode == "tag") {                        // "rid:<id> TAG" -> "TAG"
      auto sp = s.label.find(' ');
      return sp == s.label.npos ? "" : s.label.substr(sp + 1);
    }
    return s.label;
  }

  void add(const RawSample& s) {
    uint64_t alloc = 0;
    if (s.has_acnt) {
      uint64_t hid = std::strtoull(s.hid.c_str(), nullptr, 10);
      auto it = last.find(hid);
      if (it != last.end() && (uint64_t)s.ts >= it->second.ts) {
        int64_t d = it->second.acnt - s.acnt;
        if (d > 0) alloc = d;                          // a rise = the app reset the counter
      }
      last[hid] = {(uint64_t)s.ts, s.acnt};
    }
    Batch::Key k;
    k.status = (uint8_t)s.status; k.label = batch.label_id(label_of(s)); k.pc = s.pc;
    if (s.status == HS_STATUS_STOP) {
      k.frames.resize(2 * s.frames.size());
      for (size_t i = 0; i < s.frames.size(); i++) { k.frames[2 * i] = s.frames[i]; k.frames[2 * i + 1] = i < s.updatees.size() ? s.updatees[i] : 0; }
    }
    size_t kb = 16 * k.frames.size();
    auto [it2, fresh2] = batch.stacks.try_emplace(std::move(k));
    if (fresh2) batch_bytes += sizeof(wire_stack) + kb;
    Batch::Val& v = it2->second;
    v.count++; v.alloc += alloc;
    batch.samples++;
    iv.samples++;
    if (s.status == HS_STATUS_STOP) iv.stop++;
    else if (s.status == HS_STATUS_DEPTHCAP) iv.truncated++;
    else if (s.status == HS_STATUS_NOFRAME) iv.noframe++;
    else iv.broken++;
    if (!s.label.empty() && s.label != "-") iv.labelled++;
    iv.cost_ns += s.cost;
    uint64_t real = s.has_ts ? (uint64_t)((int64_t)s.ts + mono_to_real) : now_real();
    if (!batch.from_ns || real < batch.from_ns) batch.from_ns = real;
    if (real > batch.until_ns) batch.until_ns = real;
    if (batch_bytes >= max_batch_bytes) flush(true);     // the memory cap: ship now
  }

  static uint64_t now_real() {
    timespec t; clock_gettime(CLOCK_REALTIME, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
  }

  std::string serialize() {
    std::string o;
    wire_hdr h{};
    std::memcpy(h.magic, WIRE_MAGIC, 8);
    h.version = 1; h.hdr_size = sizeof h;
    h.from_ns = batch.from_ns; h.until_ns = batch.until_ns ? batch.until_ns : batch.from_ns;
    h.freq_hz = freq; h.pid = pid; h.exe_size = exe_size;
    h.n_labels = batch.labels.size(); h.n_stacks = batch.stacks.size(); h.n_samples = batch.samples;
    if (host.empty()) gethostname(h.host, sizeof h.host - 1);
    else std::snprintf(h.host, sizeof h.host, "%s", host.c_str());
    std::snprintf(h.service, sizeof h.service, "%s", service.c_str());
    std::snprintf(h.exe, sizeof h.exe, "%s", exe.c_str());
    o.append(reinterpret_cast<const char*>(&h), sizeof h);
    for (const std::string& l : batch.labels) {
      uint16_t n = std::min<size_t>(l.size(), 65535);
      o.append(reinterpret_cast<const char*>(&n), 2); o.append(l.data(), n);
    }
    for (auto& [k, v] : batch.stacks) {
      wire_stack s{v.count, v.alloc, k.pc, k.label, (uint16_t)(k.frames.size() / 2), k.status, 0};
      o.append(reinterpret_cast<const char*>(&s), sizeof s);
      o.append(reinterpret_cast<const char*>(k.frames.data()), k.frames.size() * 8);
    }
    return o;
  }

  bool post(const std::string& body) {
    CURL* c = curl_easy_init();
    if (!c) return false;
    std::string url = collector + "/v1/profile";
    curl_slist* hdrs = curl_slist_append(nullptr, "Content-Type: application/octet-stream");
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)body.size());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, +[](char*, size_t s, size_t n, void*) -> size_t { return s * n; });
    CURLcode rc = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if (rc != CURLE_OK) std::fprintf(stderr, "hsp agent: POST %s: %s\n", url.c_str(), curl_easy_strerror(rc));
    else if (code != 200) std::fprintf(stderr, "hsp agent: POST %s: HTTP %ld\n", url.c_str(), code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    return rc == CURLE_OK && code == 200;
  }

  // keep the spool under spool_max_bytes: oldest batches go first
  void spool_prune(size_t incoming) {
    DIR* d = opendir(spool.c_str());
    if (!d) return;
    std::vector<std::pair<std::string, uint64_t>> files; uint64_t total = incoming;
    while (dirent* e = readdir(d)) {
      if (!std::string_view(e->d_name).ends_with(".hspagg")) continue;
      struct stat st{}; std::string p = spool + "/" + e->d_name;
      if (stat(p.c_str(), &st) == 0) { files.push_back({p, (uint64_t)st.st_size}); total += st.st_size; }
    }
    closedir(d);
    std::sort(files.begin(), files.end());
    for (auto& [p, sz] : files) {
      if (total <= spool_max_bytes) break;
      unlink(p.c_str()); total -= sz; dropped++;
    }
  }

  void spool_write(const std::string& body) {
    if (spool.empty()) { dropped++; return; }
    spool_prune(body.size());
    std::string p = spool + "/" + std::to_string(now_real()) + ".hspagg";
    std::ofstream f(p, std::ios::binary); f.write(body.data(), body.size());
    if (f) spooled++; else dropped++;
  }

  void spool_retry() {
    if (spool.empty()) return;
    DIR* d = opendir(spool.c_str());
    if (!d) return;
    std::vector<std::string> files;
    while (dirent* e = readdir(d)) if (std::string_view(e->d_name).ends_with(".hspagg")) files.push_back(e->d_name);
    closedir(d);
    std::sort(files.begin(), files.end());
    for (auto& f : files) {
      std::string p = spool + "/" + f;
      std::ifstream in(p, std::ios::binary);
      std::string body((std::istreambuf_iterator<char>(in)), {});
      if (!post(body)) return;                         // still down; keep the rest for later
      unlink(p.c_str()); sent++;
    }
  }

  void flush_impl(bool early) {
    if (early) early_flushes++;
    size_t body_size = 0;
    if (!batch.stacks.empty()) {
      std::string body = serialize();
      body_size = body.size();
      if (post(body)) sent++; else { failed++; spool_write(body); }
      std::fprintf(stderr, "hsp agent: %s: %lu samples, %u stacks, %zu KB -> sent %lu failed %lu spooled %lu dropped %lu%s\n",
                   ctime_short().c_str(), (unsigned long)batch.samples, (unsigned)batch.stacks.size(), body.size() >> 10, sent, failed, spooled, dropped,
                   early ? " (early: batch cap)" : "");
      batch.clear(); batch_bytes = 0;
    }
    spool_retry();
    write_metrics(body_size);
    iv = Walk{};
  }

  static uint64_t rss_bytes() {
    std::ifstream f("/proc/self/statm"); uint64_t size = 0, rss = 0; f >> size >> rss; return rss * 4096;
  }

  // Prometheus text, written atomically, for node_exporter's textfile collector
  void write_metrics(size_t last_body) {
    uint64_t st[HS_ST_COUNT] = {};
    if (sampler) hs_sampler_stats(sampler, st);
    if (st[HS_ST_DROPPED] > ring_dropped_seen) {
      std::fprintf(stderr, "hsp agent: WARNING ring buffer dropped %lu records this interval (raise -r, or lower -F)\n",
                   (unsigned long)(st[HS_ST_DROPPED] - ring_dropped_seen));
      ring_dropped_seen = st[HS_ST_DROPPED];
    }
    if (metrics_file.empty()) return;
    std::string o;
    auto m = [&](const char* name, const char* help, const char* type, uint64_t v) {
      o += "# HELP "; o += name; o += ' '; o += help; o += "\n# TYPE "; o += name; o += ' '; o += type; o += '\n';
      o += name; o += "{service=\""; o += service; o += "\",pid=\""; o += std::to_string(pid); o += "\"} "; o += std::to_string(v); o += '\n';
    };
    m("hsp_agent_ticks_total", "perf ticks for the target", "counter", st[HS_ST_TICKS]);
    m("hsp_agent_walked_total", "ticks with a stack walk", "counter", st[HS_ST_WALKED]);
    m("hsp_agent_walk_stop_total", "walks that reached STOP_FRAME", "counter", st[HS_ST_STOP]);
    m("hsp_agent_walk_broken_total", "walks ended on an invalid frame", "counter", st[HS_ST_BROKEN]);
    m("hsp_agent_walk_truncated_total", "walks that hit the depth cap", "counter", st[HS_ST_TRUNCATED]);
    m("hsp_agent_ring_dropped_total", "records lost to a full ring buffer", "counter", st[HS_ST_DROPPED]);
    m("hsp_agent_interval_samples", "samples in the last interval", "gauge", iv.samples);
    m("hsp_agent_interval_stop", "of which walked to STOP_FRAME", "gauge", iv.stop);
    m("hsp_agent_interval_labelled", "of which on a labelled green thread", "gauge", iv.labelled);
    m("hsp_agent_interval_walk_cost_ns_avg", "mean in-kernel cost per sample, last interval", "gauge", iv.samples ? iv.cost_ns / iv.samples : 0);
    m("hsp_agent_batches_sent_total", "batches accepted by the collector", "counter", sent);
    m("hsp_agent_batches_failed_total", "POSTs that failed (spooled or dropped)", "counter", failed);
    m("hsp_agent_batches_spooled_total", "batches written to the spool", "counter", spooled);
    m("hsp_agent_batches_dropped_total", "batches lost (no spool, or spool full)", "counter", dropped);
    m("hsp_agent_early_flushes_total", "flushes forced by the batch memory cap", "counter", early_flushes);
    m("hsp_agent_last_batch_bytes", "size of the last batch on the wire", "gauge", last_body);
    m("hsp_agent_rss_bytes", "the agent's resident memory", "gauge", rss_bytes());
    std::string tmp = metrics_file + ".tmp";
    std::ofstream f(tmp); f << o; f.close();
    if (f) rename(tmp.c_str(), metrics_file.c_str());
  }

  static std::string ctime_short() {
    time_t t = time(nullptr); char b[32]; std::strftime(b, sizeof b, "%H:%M:%S", localtime(&t)); return b;
  }
};

void Agent::flush(bool early) { flush_impl(early); }

// hs_rec -> RawSample, as capture.cpp does for a file
void rec_to_raw(const hs_rec* r, RawSample& s) {
  s.tid = std::to_string(r->tid);
  s.pc = r->pc;
  s.status = r->status; s.depth = r->depth; s.hops = r->hops; s.scanned = r->scanned; s.cost = r->cost_ns;
  s.frames.resize(r->depth); s.updatees.resize(r->depth);
  for (unsigned i = 0; i < r->depth; i++) { s.frames[i] = r->frames[2 * i]; s.updatees[i] = r->frames[2 * i + 1]; }
  s.has_hid = r->flags & HS_F_TSO;
  if (s.has_hid) {
    s.hid = std::to_string(r->tso_id);
    s.label = (r->flags & HS_F_LABEL) ? std::string(r->label, std::min<size_t>(r->label_len, HS_LABEL_MAX)) : "-";
    s.has_ts = true; s.ts = (long long)r->ts_ns;
    s.has_acnt = r->flags & HS_F_ALLOC; s.acnt = r->alloc;
  } else { s.has_ts = true; s.ts = (long long)r->ts_ns; }
}

pid_t find_by_comm(const std::string& comm) {
  DIR* d = opendir("/proc");
  pid_t found = 0;
  while (dirent* e = readdir(d)) {
    if (!isdigit((unsigned char)e->d_name[0])) continue;
    std::ifstream f(std::string("/proc/") + e->d_name + "/comm");
    std::string c; std::getline(f, c);
    if (c == comm) { found = atoi(e->d_name); break; }
  }
  closedir(d);
  return found;
}

void usage() {
  std::fputs("usage: hsp agent (-p PID | --name COMM | --from-capture FILE --exe PATH) --collector URL\n"
             "                 [--service NAME] [--host NAME] [--interval SECS] [--spool DIR] [--label-mode none|full|tag]\n"
             "                 [--metrics-file PATH] [--max-batch-mb MB] [--spool-max-mb MB]\n"
             "                 [-F hz] [-d depth] [-r ring_mb] [--no-label] [--no-alloc] [--no-thunk]\n", stderr);
}

}  // namespace

int cmd_agent(int argc, char** argv) {
  Agent a;
  hs_sampler_opts o{}; o.freq_hz = 99; o.max_depth = 512; o.ring_mb = 8;
  std::string name, capture;
  pid_t pid = 0;
  double interval = 10;
  for (int i = 0; i < argc; i++) {
    std::string f = argv[i];
    auto val = [&]() -> const char* { return i + 1 < argc ? argv[++i] : (usage(), exit(2), nullptr); };
    if (f == "-p") pid = atoi(val());
    else if (f == "--name") name = val();
    else if (f == "--from-capture") capture = val();
    else if (f == "--exe") a.exe = val();
    else if (f == "--collector") a.collector = val();
    else if (f == "--service") a.service = val();
    else if (f == "--host") a.host = val();
    else if (f == "--interval") interval = atof(val());
    else if (f == "--spool") a.spool = val();
    else if (f == "--label-mode") a.label_mode = val();
    else if (f == "--metrics-file") a.metrics_file = val();
    else if (f == "--max-batch-mb") a.max_batch_bytes = (uint64_t)atof(val()) * (1 << 20);
    else if (f == "--spool-max-mb") a.spool_max_bytes = (uint64_t)atof(val()) * (1 << 20);
    else if (f == "-r") o.ring_mb = atoi(val());
    else if (f == "-F") o.freq_hz = atoi(val());
    else if (f == "-d") o.max_depth = atoi(val());
    else if (f == "--no-label") o.no_label = 1;
    else if (f == "--no-alloc") o.no_alloc = 1;
    else if (f == "--no-thunk") o.no_thunk = 1;
    else { usage(); return 2; }
  }
  if (a.collector.empty() || (pid == 0 && name.empty() && capture.empty()) || interval <= 0) { usage(); return 2; }
  if (!capture.empty() && a.exe.empty()) { std::fprintf(stderr, "hsp agent: --from-capture needs --exe PATH (the sampled binary, for the map)\n"); return 2; }
  curl_global_init(CURL_GLOBAL_DEFAULT);
  a.freq = o.freq_hz;
  {
    timespec m, r; clock_gettime(CLOCK_MONOTONIC, &m); clock_gettime(CLOCK_REALTIME, &r);
    a.mono_to_real = ((int64_t)r.tv_sec * 1000000000 + r.tv_nsec) - ((int64_t)m.tv_sec * 1000000000 + m.tv_nsec);
  }
  struct sigaction sa{}; sa.sa_handler = on_signal; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
  sigaction(SIGINT, &sa, nullptr); sigaction(SIGTERM, &sa, nullptr);

  if (!capture.empty()) {
    // replay: every sample in one batch, timestamps kept relative to now;
    // the capture header says what rate it was taken at
    {
      std::ifstream f(capture, std::ios::binary); hs_file_hdr fh{};
      if (f.read(reinterpret_cast<char*>(&fh), sizeof fh) && !std::memcmp(fh.magic, HS_FILE_MAGIC, 8) && fh.freq_hz) a.freq = fh.freq_hz;
    }
    struct stat st{};
    if (stat(a.exe.c_str(), &st) == 0) a.exe_size = st.st_size;
    if (a.service.empty()) a.service = a.exe.substr(a.exe.rfind('/') + 1);
    uint64_t first = 0;
    read_capture(capture.c_str(), [&](RawSample& s) {
      if (s.has_ts) { if (!first) first = s.ts; s.ts = (long long)(a.now_real() - a.mono_to_real) - (long long)(1000000000ull * 60) + (s.ts - (long long)first); }
      a.add(s);
    });
    a.flush();
    curl_global_cleanup();
    return a.sent ? 0 : 1;
  }

  if (pid == 0) {
    pid = find_by_comm(name);
    if (!pid) { std::fprintf(stderr, "hsp agent: no process named %s\n", name.c_str()); return 1; }
  }
  char err[512];
  hs_sampler* s = hs_sampler_attach(pid, nullptr, &o, +[](void* ctx, const hs_rec* r, size_t) -> int {
    RawSample raw; rec_to_raw(r, raw); static_cast<Agent*>(ctx)->add(raw); return 0; }, &a, err, sizeof err);
  if (!s) { std::fprintf(stderr, "hsp agent: %s\n", err); return 2; }
  a.sampler = s;
  a.info = hs_sampler_info(s);
  a.exe = a.info->exe; a.exe_size = a.info->exe_size; a.pid = pid;
  if (a.service.empty()) a.service = a.exe.substr(a.exe.rfind('/') + 1);
  std::fprintf(stderr, "hsp agent: pid %d, %s, GHC %d.%d, %u Hz x %d CPUs, every %.0f s -> %s (service %s)\n",
               pid, a.info->exe, a.info->ghc_major, a.info->ghc_minor, a.info->freq_hz, a.info->cpus, interval,
               a.collector.c_str(), a.service.c_str());
  auto next = std::chrono::steady_clock::now() + std::chrono::duration<double>(interval);
  while (!stop_requested) {
    if (hs_sampler_poll(s, 200) < 0) break;
    if (!hs_sampler_alive(s)) { std::fprintf(stderr, "hsp agent: target exited\n"); break; }
    if (std::chrono::steady_clock::now() >= next) { a.flush(); next += std::chrono::duration<double>(interval); }
  }
  hs_sampler_poll(s, 0);
  a.flush();
  uint64_t st[HS_ST_COUNT]; hs_sampler_stats(s, st);
  std::fprintf(stderr, "hsp agent: ticks=%lu walked=%lu stop=%lu broken=%lu truncated=%lu dropped=%lu | batches sent %lu failed %lu spooled %lu dropped %lu\n",
               (unsigned long)st[HS_ST_TICKS], (unsigned long)st[HS_ST_WALKED], (unsigned long)st[HS_ST_STOP], (unsigned long)st[HS_ST_BROKEN],
               (unsigned long)st[HS_ST_TRUNCATED], (unsigned long)st[HS_ST_DROPPED], a.sent, a.failed, a.spooled, a.dropped);
  hs_sampler_close(s);
  curl_global_cleanup();
  return 0;
}
