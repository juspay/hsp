// A capture, whichever sampler wrote it: `hsp record' (HSPREC01, binary) or
// bpftrace hswalk*.bt (text: L/F/E lines).  Both become the same RawSample.
#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct RawSample {
  std::string tid;
  uint64_t pc = 0;
  long long status = 0, depth = 0, hops = 0, scanned = 0, cost = 0;
  std::vector<uint64_t> frames;     // return-frame info pointers, youngest first
  std::vector<uint64_t> updatees;   // per frame: the updatee's info pointer, or 0
  bool has_hid = false;             // a green thread was running (text: an L line)
  std::string hid, label;           // label "" or "-": none
  bool has_ts = false, has_acnt = false;
  long long ts = 0, acnt = 0;
  uint8_t flags = 0;                // HS_F_* (hsp record); 0 from a text capture
};

// What a capture says about the process it sampled (HSPREC01 only).
struct CaptureInfo {
  bool binary = false;
  uint32_t pid = 0, freq_hz = 0;
  uint64_t text_lo = 0, text_hi = 0;          // the executable's text; 0, 0 unknown
  struct Mapping { uint64_t start, end, offset; std::string path; };
  std::vector<Mapping> maps;                  // its executable mappings; empty in older captures
  bool outside_text(uint64_t pc) const { return text_hi && (pc < text_lo || pc >= text_hi); }
};

// Calls `cb' once per sample, in file order; `info', when given, is filled
// before the first call.  Throws std::runtime_error.
void read_capture(const char* path, const std::function<void(RawSample&)>& cb, CaptureInfo* info = nullptr);
