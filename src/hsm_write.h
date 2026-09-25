// Building an .hsm from an entry list: everything SymMap.__init__ and
// attach_lines computed at load time in the Python prototype, as sorted
// arrays; `symmap' fills an Input from the ELF and this writes it.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace hsmw {

// One entry, as strings ("" = None); the Python's dict.
struct Entry {
  uint64_t addr = 0, size = 0, info_ptr = 0;   // 0 = None
  std::string symbol, package_name, module, name, toplevel, src_file, src_span,
      closure_type_name, inlined, bucket, rollup, source_tier;
};

struct Lines {   // DWARF rows sorted by (addr, file, line)
  std::vector<uint64_t> addr;
  std::vector<std::string> file;    // basenames; interned by the writer
  std::vector<uint32_t> line;
};

struct Input {
  std::vector<Entry> entries;                               // in build order
  std::vector<std::pair<uint64_t, uint32_t>> by_info;       // (ptr, idx), any order
  std::vector<std::tuple<uint64_t, uint64_t, uint32_t>> intervals;   // (start, end, idx), sorted by start
  std::vector<std::pair<uint64_t, uint64_t>> exec_ranges;   // sorted
  int64_t info_delta = 0;
  Lines lines;
};

// Writes OUT.hsm atomically; throws std::runtime_error.  Prints a summary to stderr.
void write_hsm(const Input& in, const std::string& out);

}  // namespace hsmw
