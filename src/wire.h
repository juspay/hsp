// HSPAGG01: what `hsp agent' sends to `hsp collect' for one interval.
// Unresolved: stacks are info pointers, so the production host needs no map.
//
//   struct wire_hdr
//   labels:  n_labels x { u16 len; char bytes[len] }        (label 0 = none)
//   stacks:  n_stacks x { struct wire_stack; u64 frames[2*depth] }
//
// Everything little-endian, no alignment padding between items (the reader
// memcpy's).  A stack's frames are (info pointer, updatee info pointer) pairs,
// youngest first, exactly as hs_rec carries them.
#pragma once
#include <cstdint>

#define WIRE_MAGIC "HSPAGG01"

struct wire_hdr {
  char magic[8];
  uint32_t version;        // 1
  uint32_t hdr_size;       // sizeof(wire_hdr)
  uint64_t from_ns, until_ns;   // CLOCK_REALTIME window of the samples
  uint32_t freq_hz;
  uint32_t pid;
  uint64_t exe_size;       // the target executable's byte size: map identity with exe path
  uint32_t n_labels, n_stacks;
  uint32_t n_samples;      // ticks aggregated (for the resolution audit)
  uint32_t flags;
  char host[64];
  char service[64];        // Pyroscope application name
  char exe[256];           // the target executable's path
};

struct wire_stack {
  uint64_t count;          // samples
  uint64_t alloc;          // bytes attributed (counter deltas ending here)
  uint64_t pc;             // leaf
  uint32_t label;          // index into labels
  uint16_t depth;
  uint8_t status;          // HS_STATUS_*
  uint8_t pad;
};
