// hsp collect: receives HSPAGG01 batches from agents, resolves them with
// the .hsm map of the binary they came from, and pushes folded profiles to
// Pyroscope.  One process for the whole fleet; the only one holding maps.
//
//   hsp collect --listen [ADDR:]PORT --maps DIR [--pyroscope URL] [--dump DIR]
//               [--threads N] [--queue-mb MB]
//
// Map lookup, in order: DIR/<exe_id>.hsm (the id is the SHA-256 of the
// binary, sent by the agent and stored in the map: `hsp symmap --install DIR'
// writes that name); then DIR/maps.tsv lines `exe-path<TAB>exe-size<TAB>map.hsm';
// then DIR/<basename of exe>.hsm.  A map found by path is refused when it
// carries an id and the batch carries a different one: wrong build.  Maps
// stay open (mmap'd) once used and are reloaded when the file changes; a
// missing map is looked for again on every batch, so one that arrives later
// (CI finishing after the deploy) is picked up without a restart, and the
// agent spools the batches until then.
//
// Threads: --threads request handlers (default 4) accept and resolve
// concurrently, one batch at a time per map; one pusher thread hands the
// folded profiles to Pyroscope from a bounded queue (--queue-mb, default
// 256), so a slow or down Pyroscope never blocks an agent's POST.  When the
// queue is full the oldest profile is dropped and counted.
//
// Endpoints:  POST /v1/profile   an HSPAGG01 body -> 200 "ok"
//             GET  /healthz      200
//             GET  /stats        one line per map + counters
//             GET  /metrics      Prometheus text
//
// Pyroscope gets, per batch, `<service>.cpu{host=..,pid=..}' with sample
// counts and `<service>.alloc_space{...}' with bytes, both as folded text
// through the legacy /ingest API, over the batch's time window.
#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "exeid.h"
#include "hsm.h"
#include "hsp_abi.h"
#include "naming.h"
#include "wire.h"

namespace {

volatile sig_atomic_t stop_requested;
void on_signal(int) { stop_requested = 1; }

struct Loaded {
  std::mutex mu;                       // the namer's caches are not thread-safe
  std::unique_ptr<hsm::Map> map;
  naming::Names names;
  std::unique_ptr<naming::FrameNamer> namer;
  std::string path;
  ino_t ino = 0; time_t mtime = 0;     // the file as loaded: a changed file is reloaded
  uint64_t batches = 0, samples = 0;
};

struct PushJob {
  std::string name, body;
  uint64_t from, until; unsigned hz; const char* units;
};

// The Pyroscope side: a bounded queue drained by one thread.
struct Pusher {
  std::string pyroscope;
  size_t max_bytes = 256u << 20;
  std::mutex mu; std::condition_variable cv;
  std::deque<PushJob> q; size_t bytes = 0; bool stopping = false;
  std::atomic<uint64_t> pushed{0}, failed{0}, dropped{0};
  std::thread th;

  void start() { th = std::thread([this] { run(); }); }
  void stop() { { std::lock_guard<std::mutex> l(mu); stopping = true; } cv.notify_all(); if (th.joinable()) th.join(); }
  size_t depth() { std::lock_guard<std::mutex> l(mu); return q.size(); }

  void enqueue(PushJob j) {
    if (pyroscope.empty()) return;
    std::lock_guard<std::mutex> l(mu);
    while (!q.empty() && bytes + j.body.size() > max_bytes) { bytes -= q.front().body.size(); q.pop_front(); dropped++; }
    bytes += j.body.size(); q.push_back(std::move(j));
    cv.notify_one();
  }

  void run() {
    for (;;) {
      PushJob j;
      {
        std::unique_lock<std::mutex> l(mu);
        cv.wait(l, [&] { return stopping || !q.empty(); });
        if (q.empty()) return;             // stopping and drained
        j = std::move(q.front()); q.pop_front(); bytes -= j.body.size();
      }
      // three tries with a pause: a Pyroscope restart is seconds, not minutes
      bool ok = false;
      for (int t = 0; t < 3 && !ok; t++) {
        if (t) { std::unique_lock<std::mutex> l(mu); if (cv.wait_for(l, std::chrono::seconds(2), [&] { return stopping; })) break; }
        ok = push_one(j);
      }
      if (ok) pushed++; else failed++;
    }
  }

  static std::string urlenc(const std::string& s) {
    std::string o; char b[4];
    for (unsigned char c : s) {
      if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') o += c;
      else { std::snprintf(b, sizeof b, "%%%02X", c); o += b; }
    }
    return o;
  }

  bool push_one(const PushJob& j) {
    std::string url = pyroscope + "/ingest?name=" + urlenc(j.name) + "&from=" + std::to_string(j.from) + "&until=" + std::to_string(j.until) +
                      "&format=folded&sampleRate=" + std::to_string(j.hz) + "&spyName=hsp&units=" + j.units + "&aggregationType=sum";
    CURL* c = curl_easy_init();
    curl_slist* hdrs = curl_slist_append(nullptr, "Content-Type: text/plain");
    hdrs = curl_slist_append(hdrs, "Expect:");     // no 100-continue wait on large bodies
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, j.body.data());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)j.body.size());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, +[](char*, size_t s, size_t n, void*) -> size_t { return s * n; });
    CURLcode rc = curl_easy_perform(c);
    long code = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs); curl_easy_cleanup(c);
    if (rc != CURLE_OK || code != 200) {
      std::fprintf(stderr, "hsp collect: pyroscope ingest %s: %s HTTP %ld\n", j.name.c_str(), rc == CURLE_OK ? "" : curl_easy_strerror(rc), code);
      return false;
    }
    return true;
  }
};

struct Collector {
  std::string maps_dir, dump;
  Pusher pusher;
  std::mutex mu;                                                  // index, loaded, counters, log throttle
  std::map<std::string, std::shared_ptr<Loaded>> loaded;           // by map path; handlers hold their own reference
  std::map<std::pair<std::string, uint64_t>, std::string> index;   // (exe, size) -> map path
  uint64_t received = 0, rejected = 0, no_map = 0, wrong_map = 0;
  std::map<std::string, std::chrono::steady_clock::time_point> last_log;

  void load_index() {
    std::ifstream f(maps_dir + "/maps.tsv");
    std::string line;
    while (std::getline(f, line)) {
      if (line.empty() || line[0] == '#') continue;
      std::istringstream is(line);
      std::string exe, size, map;
      if (std::getline(is, exe, '\t') && std::getline(is, size, '\t') && std::getline(is, map, '\t'))
        index[{exe, std::strtoull(size.c_str(), nullptr, 10)}] = map[0] == '/' ? map : maps_dir + "/" + map;
    }
  }

  // once a minute per message: a missing map repeats every interval from every agent
  void log_throttled(const std::string& msg) {
    auto now = std::chrono::steady_clock::now();
    auto& t = last_log[msg];
    if (t.time_since_epoch().count() && now - t < std::chrono::seconds(60)) return;
    t = now;
    std::fprintf(stderr, "hsp collect: %s\n", msg.c_str());
  }

  // Which map for this batch, loading it on first use.  Caller holds mu.
  std::shared_ptr<Loaded> map_for(const std::string& exe, uint64_t size, const exeid::Id& id, std::string& why) {
    std::vector<std::string> candidates;
    bool have_id = !exeid::is_zero(id);
    if (have_id) candidates.push_back(maps_dir + "/" + exeid::hex(id) + ".hsm");
    auto it = index.find({exe, size});
    if (it != index.end()) candidates.push_back(it->second);
    auto w = index.find({exe, 0});                                    // wildcard size
    if (w != index.end()) candidates.push_back(w->second);
    candidates.push_back(maps_dir + "/" + exe.substr(exe.rfind('/') + 1) + ".hsm");
    for (const std::string& path : candidates) {
      struct stat st{};
      if (stat(path.c_str(), &st)) continue;
      std::shared_ptr<Loaded> L;
      auto l = loaded.find(path);
      if (l != loaded.end() && l->second->ino == st.st_ino && l->second->mtime == st.st_mtime) L = l->second;
      else {
        try {
          auto N = std::make_shared<Loaded>();
          N->map = std::make_unique<hsm::Map>(hsm::Map::open(path.c_str()));
          N->namer = std::make_unique<naming::FrameNamer>(*N->map, N->names);
          N->path = path; N->ino = st.st_ino; N->mtime = st.st_mtime;
          std::fprintf(stderr, "hsp collect: %s %s for %s\n", l == loaded.end() ? "loaded" : "reloaded (file changed)", path.c_str(), exe.c_str());
          L = loaded[path] = N;      // a handler still resolving with the old one keeps it alive until it is done
        } catch (const std::exception& e) { why = e.what(); return nullptr; }
      }
      // a map found by path must be for this build, if both sides know the build
      if (have_id && L->map->has_exe_id() && std::memcmp(L->map->header().exe_id, id.data(), 32)) {
        why = "wrong build: " + path + " is for " + exeid::hex(*reinterpret_cast<const exeid::Id*>(L->map->header().exe_id)).substr(0, 12) +
              "…, batch from " + exeid::hex(id).substr(0, 12) + "…";
        wrong_map++;
        continue;
      }
      return L;
    }
    if (why.empty()) {
      why = "no map for " + exe + " (" + std::to_string(size) + " bytes" + (have_id ? ", id " + exeid::hex(id) : std::string(", no id")) + ")";
      no_map++;
    }
    return nullptr;
  }

  // one batch -> two folded profiles (samples, bytes) queued for Pyroscope; false with why
  bool handle(const std::string& body, std::string& why) {
    if (body.size() < offsetof(wire_hdr, exe_id)) { why = "short body"; return false; }
    wire_hdr h{};
    uint32_t hdr_size; std::memcpy(&hdr_size, body.data() + offsetof(wire_hdr, hdr_size), 4);
    if (hdr_size > body.size()) { why = "short body"; return false; }
    std::memcpy(&h, body.data(), std::min<size_t>(hdr_size, sizeof h));   // version 1 has no exe_id: stays zero
    if (std::memcmp(h.magic, WIRE_MAGIC, 8) || (h.version != 1 && h.version != 2)) { why = "not HSPAGG01"; return false; }
    std::string exe(h.exe, strnlen(h.exe, sizeof h.exe)), service(h.service, strnlen(h.service, sizeof h.service)),
        host(h.host, strnlen(h.host, sizeof h.host));
    exeid::Id id; std::memcpy(id.data(), h.exe_id, 32);
    std::shared_ptr<Loaded> L;
    {
      std::lock_guard<std::mutex> l(mu);
      L = map_for(exe, h.exe_size, id, why);
      if (!L) return false;
    }
    const char* p = body.data() + h.hdr_size; const char* end = body.data() + body.size();
    std::vector<std::string> labels;
    for (uint32_t i = 0; i < h.n_labels; i++) {
      uint16_t n; if (p + 2 > end) { why = "truncated labels"; return false; }
      std::memcpy(&n, p, 2); p += 2;
      if (p + n > end) { why = "truncated labels"; return false; }
      labels.emplace_back(p, n); p += n;
    }
    std::unordered_map<std::string, uint64_t> cpu, alloc;
    uint64_t samples = 0;
    {
      std::lock_guard<std::mutex> l(L->mu);
      for (uint32_t i = 0; i < h.n_stacks; i++) {
        wire_stack s; if (p + sizeof s > end) { why = "truncated stacks"; return false; }
        std::memcpy(&s, p, sizeof s); p += sizeof s;
        size_t words = 2 * (size_t)s.depth;
        if (p + words * 8 > end) { why = "truncated frames"; return false; }
        const uint64_t* fr = reinterpret_cast<const uint64_t*>(p); p += words * 8;
        std::string line;
        if (s.label < labels.size() && !labels[s.label].empty()) { line += labels[s.label]; line += ';'; }
        if (s.status == HS_STATUS_STOP) {
          // frames are youngest first; folded text wants the root first
          for (size_t k = s.depth; k-- > 0;) { line += L->names.s[L->namer->frame_id(fr[2 * k], fr[2 * k + 1])]; line += ';'; }
        } else {
          line += "[c];";
        }
        line += L->names.s[L->namer->leaf_id(s.pc)];
        cpu[line] += s.count;
        if (s.alloc) alloc[line] += s.alloc;
        samples += s.count;
      }
      L->batches++; L->samples += samples;
    }
    uint64_t from = h.from_ns / 1000000000ull, until = h.until_ns / 1000000000ull;
    if (until <= from) until = from + 1;
    std::string labelset = "host=" + host + ",pid=" + std::to_string(h.pid);
    pusher.enqueue({service + ".cpu{" + labelset + "}", folded(cpu), from, until, h.freq_hz, "samples"});
    if (!alloc.empty()) pusher.enqueue({service + ".alloc_space{" + labelset + "}", folded(alloc), from, until, h.freq_hz, "bytes"});
    if (!dump.empty()) {
      std::ofstream f(dump + "/" + std::to_string(h.until_ns) + "-" + service + ".txt");
      for (auto& [k, v] : cpu) f << k << ' ' << v << '\n';
    }
    std::fprintf(stderr, "hsp collect: %s@%s pid %u: %u samples, %u stacks, %zu resolved lines, window %lus\n",
                 service.c_str(), host.c_str(), h.pid, h.n_samples, h.n_stacks, cpu.size(), (unsigned long)(until - from));
    return true;
  }

  static std::string folded(const std::unordered_map<std::string, uint64_t>& m) {
    std::string body;
    for (auto& [k, v] : m) { body += k; body += ' '; body += std::to_string(v); body += '\n'; }
    return body;
  }

  std::string metrics() {
    std::lock_guard<std::mutex> l(mu);
    std::string o;
    auto m = [&](const char* n, const char* t, uint64_t v, const std::string& lbl = "") {
      o += "# TYPE "; o += n; o += ' '; o += t; o += '\n'; o += n; o += lbl; o += ' '; o += std::to_string(v); o += '\n';
    };
    m("hsp_collect_batches_received_total", "counter", received);
    m("hsp_collect_batches_rejected_total", "counter", rejected);
    m("hsp_collect_batches_no_map_total", "counter", no_map);
    m("hsp_collect_batches_wrong_map_total", "counter", wrong_map);
    m("hsp_collect_pushes_total", "counter", pusher.pushed);
    m("hsp_collect_pushes_failed_total", "counter", pusher.failed);
    m("hsp_collect_pushes_dropped_total", "counter", pusher.dropped);
    m("hsp_collect_push_queue_depth", "gauge", pusher.depth());
    m("hsp_collect_maps_loaded", "gauge", loaded.size());
    for (auto& [p, L] : loaded) m("hsp_collect_map_samples_total", "counter", L->samples, "{map=\"" + p + "\"}");
    return o;
  }

  std::string stats() {
    std::lock_guard<std::mutex> l(mu);
    std::string o = "received " + std::to_string(received) + " rejected " + std::to_string(rejected) + " (no map " + std::to_string(no_map) +
                    ", wrong build " + std::to_string(wrong_map) + ") pushed " + std::to_string(pusher.pushed) + " push_failed " +
                    std::to_string(pusher.failed) + " push_dropped " + std::to_string(pusher.dropped) + " queue " + std::to_string(pusher.depth()) + "\n";
    for (auto& [p, L] : loaded) o += p + ": " + std::to_string(L->batches) + " batches, " + std::to_string(L->samples) + " samples\n";
    return o;
  }
};

// A minimal HTTP/1.1 server: Content-Length bodies, one request per
// connection, accept()ed by several threads.
struct Http {
  int fd = -1;
  bool listen_on(const std::string& spec) {
    std::string addr = "0.0.0.0"; int port;
    auto c = spec.rfind(':');
    if (c == spec.npos) port = atoi(spec.c_str()); else { addr = spec.substr(0, c); port = atoi(spec.c_str() + c + 1); }
    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (inet_pton(AF_INET, addr.c_str(), &sa.sin_addr) != 1) return false;
    return bind(fd, (sockaddr*)&sa, sizeof sa) == 0 && listen(fd, 128) == 0;
  }
  static bool read_exact(int c, std::string& buf, size_t want) {
    while (buf.size() < want) {
      char tmp[65536]; ssize_t n = read(c, tmp, sizeof tmp);
      if (n <= 0) return false;
      buf.append(tmp, n);
    }
    return true;
  }
  // returns method, path, body; false when the listener is closed or the request is bad
  bool next(std::string& method, std::string& path, std::string& body, int& client) {
    client = accept(fd, nullptr, nullptr);
    if (client < 0) return false;
    timeval tv{30, 0}; setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);   // a stalled agent must not hold a thread
    std::string buf;
    size_t hdr_end;
    for (;;) {
      hdr_end = buf.find("\r\n\r\n");
      if (hdr_end != buf.npos) break;
      char tmp[8192]; ssize_t n = read(client, tmp, sizeof tmp);
      if (n <= 0) { close(client); client = -1; return false; }
      buf.append(tmp, n);
      if (buf.size() > 1 << 20) { close(client); client = -1; return false; }
    }
    std::istringstream is(buf.substr(0, hdr_end));
    std::string ver; is >> method >> path >> ver;
    size_t len = 0;
    std::string line;
    while (std::getline(is, line)) {
      if (line.size() > 15 && strncasecmp(line.c_str(), "content-length:", 15) == 0) len = std::strtoull(line.c_str() + 15, nullptr, 10);
    }
    if (len > 512u << 20) { close(client); client = -1; return false; }
    body = buf.substr(hdr_end + 4);
    if (!read_exact(client, body, len)) { close(client); client = -1; return false; }
    body.resize(len);
    return true;
  }
  static void reply(int client, int code, const std::string& text) {
    std::string r = "HTTP/1.1 " + std::to_string(code) + (code == 200 ? " OK" : code == 404 ? " Not Found" : " Bad Request") +
                    "\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(text.size()) + "\r\nConnection: close\r\n\r\n" + text;
    size_t off = 0;
    while (off < r.size()) { ssize_t n = write(client, r.data() + off, r.size() - off); if (n <= 0) break; off += n; }
    close(client);
  }
};

void serve(Collector& C, Http& h) {
  while (!stop_requested) {
    std::string method, path, body; int client;
    if (!h.next(method, path, body, client)) { if (stop_requested || client < 0 && h.fd < 0) break; continue; }
    if (method == "GET" && path == "/healthz") Http::reply(client, 200, "ok\n");
    else if (method == "GET" && path == "/stats") Http::reply(client, 200, C.stats());
    else if (method == "GET" && path == "/metrics") Http::reply(client, 200, C.metrics());
    else if (method == "POST" && path == "/v1/profile") {
      std::string why;
      { std::lock_guard<std::mutex> l(C.mu); C.received++; }
      if (C.handle(body, why)) Http::reply(client, 200, "ok\n");
      else {
        { std::lock_guard<std::mutex> l(C.mu); C.rejected++; C.log_throttled("rejected: " + why); }
        Http::reply(client, 400, why + "\n");
      }
    } else Http::reply(client, 404, "no such endpoint\n");
  }
}

void usage() {
  std::fputs("usage: hsp collect --listen [ADDR:]PORT --maps DIR [--pyroscope URL] [--dump DIR] [--threads N] [--queue-mb MB]\n", stderr);
}

}  // namespace

int cmd_collect(int argc, char** argv) {
  Collector C;
  std::string listen; int threads = 4;
  for (int i = 0; i < argc; i++) {
    std::string f = argv[i];
    auto val = [&]() -> const char* { return i + 1 < argc ? argv[++i] : (usage(), exit(2), nullptr); };
    if (f == "--listen") listen = val();
    else if (f == "--maps") C.maps_dir = val();
    else if (f == "--pyroscope") C.pusher.pyroscope = val();
    else if (f == "--dump") C.dump = val();
    else if (f == "--threads") threads = std::max(1, atoi(val()));
    else if (f == "--queue-mb") C.pusher.max_bytes = (size_t)std::max(1, atoi(val())) << 20;
    else { usage(); return 2; }
  }
  if (listen.empty() || C.maps_dir.empty()) { usage(); return 2; }
  curl_global_init(CURL_GLOBAL_DEFAULT);
  C.load_index();
  Http h;
  if (!h.listen_on(listen)) { std::fprintf(stderr, "hsp collect: cannot listen on %s: %s\n", listen.c_str(), strerror(errno)); return 2; }
  // signals go to this thread only; it then closes the listener, which ends the
  // handlers' accept()s
  sigset_t set; sigemptyset(&set); sigaddset(&set, SIGINT); sigaddset(&set, SIGTERM);
  pthread_sigmask(SIG_BLOCK, &set, nullptr);
  signal(SIGPIPE, SIG_IGN);
  std::fprintf(stderr, "hsp collect: listening on %s, maps in %s (%zu indexed), pyroscope %s, %d threads\n", listen.c_str(), C.maps_dir.c_str(),
               C.index.size(), C.pusher.pyroscope.empty() ? "(none: dump only)" : C.pusher.pyroscope.c_str(), threads);
  C.pusher.start();
  std::vector<std::thread> workers;
  for (int i = 0; i < threads; i++) workers.emplace_back([&] { serve(C, h); });
  int sig = 0; sigwait(&set, &sig);
  stop_requested = 1;
  shutdown(h.fd, SHUT_RDWR); close(h.fd); h.fd = -1;
  for (auto& w : workers) w.join();
  C.pusher.stop();                       // drains what is queued
  std::fprintf(stderr, "hsp collect: stopped (signal %d)\n", sig);
  curl_global_cleanup();
  return 0;
}
