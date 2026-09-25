// hsp collect: receives HSPAGG01 batches from agents, resolves them with
// the .hsm map of the binary they came from, and pushes folded profiles to
// Pyroscope.  One process for the whole fleet; the only one holding maps.
//
//   hsp collect --listen [ADDR:]PORT --maps DIR --pyroscope URL [--dump DIR]
//
// Map lookup: DIR/maps.tsv lines `exe-path<TAB>exe-size<TAB>map.hsm', or
// failing that DIR/<basename of exe>.hsm.  Maps stay open (mmap'd) once used.
//
// Endpoints:  POST /v1/profile   an HSPAGG01 body -> 200 "ok"
//             GET  /healthz      200
//             GET  /stats        one line per map + counters
//
// Pyroscope gets, per batch, `<service>.cpu{host=..,pid=..}' with sample
// counts and `<service>.alloc_space{...}' with bytes, both as folded text
// through the legacy /ingest API, over the batch's time window.
#include <arpa/inet.h>
#include <curl/curl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "hsm.h"
#include "hsp_abi.h"
#include "naming.h"
#include "wire.h"

namespace {

volatile sig_atomic_t stop_requested;
void on_signal(int) { stop_requested = 1; }

struct Loaded {
  std::unique_ptr<hsm::Map> map;
  naming::Names names;
  std::unique_ptr<naming::FrameNamer> namer;
  std::string path;
  uint64_t batches = 0, samples = 0;
};

struct Collector {
  std::string maps_dir, pyroscope, dump;
  std::map<std::string, std::unique_ptr<Loaded>> loaded;   // by map path
  std::map<std::pair<std::string, uint64_t>, std::string> index;   // (exe, size) -> map path
  uint64_t received = 0, rejected = 0, pushed = 0, push_failed = 0;

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

  Loaded* map_for(const std::string& exe, uint64_t size, std::string& why) {
    std::string path;
    auto it = index.find({exe, size});
    if (it != index.end()) path = it->second;
    else {
      // wildcard size in maps.tsv (0) or the basename convention
      auto w = index.find({exe, 0});
      if (w != index.end()) path = w->second;
      else path = maps_dir + "/" + exe.substr(exe.rfind('/') + 1) + ".hsm";
    }
    auto l = loaded.find(path);
    if (l != loaded.end()) return l->second.get();
    struct stat st{};
    if (stat(path.c_str(), &st)) { why = "no map for " + exe + " (" + std::to_string(size) + " bytes): " + path; return nullptr; }
    try {
      auto L = std::make_unique<Loaded>();
      L->map = std::make_unique<hsm::Map>(hsm::Map::open(path.c_str()));
      L->namer = std::make_unique<naming::FrameNamer>(*L->map, L->names);
      L->path = path;
      std::fprintf(stderr, "hsp collect: loaded %s for %s\n", path.c_str(), exe.c_str());
      return (loaded[path] = std::move(L)).get();
    } catch (const std::exception& e) { why = e.what(); return nullptr; }
  }

  // one batch -> two folded profiles (samples, bytes); returns false with why
  bool handle(const std::string& body, std::string& why) {
    if (body.size() < sizeof(wire_hdr)) { why = "short body"; return false; }
    wire_hdr h; std::memcpy(&h, body.data(), sizeof h);
    if (std::memcmp(h.magic, WIRE_MAGIC, 8) || h.version != 1) { why = "not HSPAGG01"; return false; }
    std::string exe(h.exe, strnlen(h.exe, sizeof h.exe)), service(h.service, strnlen(h.service, sizeof h.service)),
        host(h.host, strnlen(h.host, sizeof h.host));
    Loaded* L = map_for(exe, h.exe_size, why);
    if (!L) return false;
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
    uint64_t from = h.from_ns / 1000000000ull, until = h.until_ns / 1000000000ull;
    if (until <= from) until = from + 1;
    std::string labelset = "host=" + host + ",pid=" + std::to_string(h.pid);
    bool ok = push(service + ".cpu{" + labelset + "}", cpu, from, until, h.freq_hz, "samples");
    if (!alloc.empty()) ok = push(service + ".alloc_space{" + labelset + "}", alloc, from, until, h.freq_hz, "bytes") && ok;
    if (!dump.empty()) {
      std::ofstream f(dump + "/" + std::to_string(h.until_ns) + "-" + service + ".txt");
      for (auto& [k, v] : cpu) f << k << ' ' << v << '\n';
    }
    std::fprintf(stderr, "hsp collect: %s@%s pid %u: %u samples, %u stacks, %zu resolved lines, window %lus%s\n",
                 service.c_str(), host.c_str(), h.pid, h.n_samples, h.n_stacks, cpu.size(), (unsigned long)(until - from),
                 ok ? "" : " (push FAILED)");
    return true;
  }

  static std::string urlenc(const std::string& s) {
    std::string o; char b[4];
    for (unsigned char c : s) {
      if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') o += c;
      else { std::snprintf(b, sizeof b, "%%%02X", c); o += b; }
    }
    return o;
  }

  bool push(const std::string& name, const std::unordered_map<std::string, uint64_t>& folded,
            uint64_t from, uint64_t until, unsigned hz, const char* units) {
    if (pyroscope.empty()) return true;
    std::string body;
    for (auto& [k, v] : folded) { body += k; body += ' '; body += std::to_string(v); body += '\n'; }
    std::string url = pyroscope + "/ingest?name=" + urlenc(name) + "&from=" + std::to_string(from) + "&until=" + std::to_string(until) +
                      "&format=folded&sampleRate=" + std::to_string(hz) + "&spyName=hsp&units=" + units + "&aggregationType=sum";
    CURL* c = curl_easy_init();
    curl_slist* hdrs = curl_slist_append(nullptr, "Content-Type: text/plain");
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)body.size());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, +[](char*, size_t s, size_t n, void*) -> size_t { return s * n; });
    CURLcode rc = curl_easy_perform(c);
    long code = 0; curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(hdrs); curl_easy_cleanup(c);
    if (rc != CURLE_OK || code != 200) {
      std::fprintf(stderr, "hsp collect: pyroscope ingest %s: %s HTTP %ld\n", name.c_str(), rc == CURLE_OK ? "" : curl_easy_strerror(rc), code);
      push_failed++; return false;
    }
    pushed++;
    return true;
  }

  std::string metrics() {
    std::string o;
    auto m = [&](const char* n, const char* t, uint64_t v, const std::string& lbl = "") {
      o += "# TYPE "; o += n; o += ' '; o += t; o += '\n'; o += n; o += lbl; o += ' '; o += std::to_string(v); o += '\n';
    };
    m("hsp_collect_batches_received_total", "counter", received);
    m("hsp_collect_batches_rejected_total", "counter", rejected);
    m("hsp_collect_pushes_total", "counter", pushed);
    m("hsp_collect_pushes_failed_total", "counter", push_failed);
    m("hsp_collect_maps_loaded", "gauge", loaded.size());
    for (auto& [p, L] : loaded) m("hsp_collect_map_samples_total", "counter", L->samples, "{map=\"" + p + "\"}");
    return o;
  }

  std::string stats() {
    std::string o = "received " + std::to_string(received) + " rejected " + std::to_string(rejected) + " pushed " +
                    std::to_string(pushed) + " push_failed " + std::to_string(push_failed) + "\n";
    for (auto& [p, L] : loaded) o += p + ": " + std::to_string(L->batches) + " batches, " + std::to_string(L->samples) + " samples\n";
    return o;
  }
};

// A minimal HTTP/1.1 server: one request at a time, Content-Length bodies.
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
    return bind(fd, (sockaddr*)&sa, sizeof sa) == 0 && listen(fd, 64) == 0;
  }
  static bool read_exact(int c, std::string& buf, size_t want) {
    while (buf.size() < want) {
      char tmp[65536]; ssize_t n = read(c, tmp, sizeof tmp);
      if (n <= 0) return false;
      buf.append(tmp, n);
    }
    return true;
  }
  // returns method, path, body
  bool next(std::string& method, std::string& path, std::string& body, int& client) {
    client = accept(fd, nullptr, nullptr);
    if (client < 0) return false;
    std::string buf;
    size_t hdr_end;
    for (;;) {
      hdr_end = buf.find("\r\n\r\n");
      if (hdr_end != buf.npos) break;
      char tmp[8192]; ssize_t n = read(client, tmp, sizeof tmp);
      if (n <= 0) { close(client); return false; }
      buf.append(tmp, n);
      if (buf.size() > 1 << 20) { close(client); return false; }
    }
    std::istringstream is(buf.substr(0, hdr_end));
    std::string ver; is >> method >> path >> ver;
    size_t len = 0;
    std::string line;
    while (std::getline(is, line)) {
      if (line.size() > 15 && strncasecmp(line.c_str(), "content-length:", 15) == 0) len = std::strtoull(line.c_str() + 15, nullptr, 10);
    }
    body = buf.substr(hdr_end + 4);
    if (!read_exact(client, body, len)) { close(client); return false; }
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

void usage() {
  std::fputs("usage: hsp collect --listen [ADDR:]PORT --maps DIR [--pyroscope URL] [--dump DIR]\n", stderr);
}

}  // namespace

int cmd_collect(int argc, char** argv) {
  Collector C;
  std::string listen;
  for (int i = 0; i < argc; i++) {
    std::string f = argv[i];
    auto val = [&]() -> const char* { return i + 1 < argc ? argv[++i] : (usage(), exit(2), nullptr); };
    if (f == "--listen") listen = val();
    else if (f == "--maps") C.maps_dir = val();
    else if (f == "--pyroscope") C.pyroscope = val();
    else if (f == "--dump") C.dump = val();
    else { usage(); return 2; }
  }
  if (listen.empty() || C.maps_dir.empty()) { usage(); return 2; }
  curl_global_init(CURL_GLOBAL_DEFAULT);
  C.load_index();
  Http h;
  if (!h.listen_on(listen)) { std::fprintf(stderr, "hsp collect: cannot listen on %s: %s\n", listen.c_str(), strerror(errno)); return 2; }
  // no SA_RESTART: a signal must interrupt accept(), or the loop only notices
  // it at the next request
  struct sigaction sa{}; sa.sa_handler = on_signal; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
  sigaction(SIGINT, &sa, nullptr); sigaction(SIGTERM, &sa, nullptr);
  signal(SIGPIPE, SIG_IGN);
  std::fprintf(stderr, "hsp collect: listening on %s, maps in %s (%zu indexed), pyroscope %s\n", listen.c_str(), C.maps_dir.c_str(),
               C.index.size(), C.pyroscope.empty() ? "(none: dump only)" : C.pyroscope.c_str());
  while (!stop_requested) {
    std::string method, path, body; int client;
    if (!h.next(method, path, body, client)) { if (stop_requested) break; usleep(1000); continue; }
    if (method == "GET" && path == "/healthz") Http::reply(client, 200, "ok\n");
    else if (method == "GET" && path == "/stats") Http::reply(client, 200, C.stats());
    else if (method == "GET" && path == "/metrics") Http::reply(client, 200, C.metrics());
    else if (method == "POST" && path == "/v1/profile") {
      std::string why;
      C.received++;
      if (C.handle(body, why)) Http::reply(client, 200, "ok\n");
      else { C.rejected++; std::fprintf(stderr, "hsp collect: rejected: %s\n", why.c_str()); Http::reply(client, 400, why + "\n"); }
    } else Http::reply(client, 404, "no such endpoint\n");
  }
  curl_global_cleanup();
  return 0;
}
