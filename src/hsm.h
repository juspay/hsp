// .hsm: hsp's name map. One file, mmap'd, no parsing at load time.
//
// It holds what the earlier Python resolver built in memory when it loaded a
// symmap.json.gz, already laid out as sorted arrays: the entries, the lookup
// indexes over them, the DWARF line table and the binding spans. Every
// resolver below is a line-for-line port of the SymMap method it names.
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace hsm {

constexpr char MAGIC[8] = {'H', 'S', 'P', 'M', 'A', 'P', '0', '1'};

// A string is a u32 offset into the string table; offset 0 is "" and stands
// for Python's None (the Python code only ever tests these for truthiness).
struct Entry {
  uint64_t addr, size, info_ptr;       // 0 = None
  uint32_t symbol, package_name, module, name, toplevel, src_file, src_span,
      closure_type_name, inlined, bucket, rollup, source_tier;
};

struct ByInfo { uint64_t ptr; uint32_t idx, pad; };           // sorted by ptr
struct Range { uint64_t lo, hi; };                            // [lo, hi)
struct BSpan { uint32_t module, file, toplevel, pad; int64_t lo, hi; };

// Offsets are from the start of the file; every array is 8-byte aligned.
struct Header {
  char magic[8];
  int64_t info_delta;
  uint64_t n_entries, n_byinfo, n_iv, n_exec, n_cstarts, n_owner, n_lines, n_bspans, n_strings;
  uint64_t entries, byinfo, exec, strings;
  uint64_t iv_start, iv_end, iv_maxend, iv_idx;   // intervals, column by column
  uint64_t cs_addr, cs_idx;                       // extent starts
  uint64_t ow_addr, ow_idx;                       // symtab entries in .text
  uint64_t ln_addr, ln_file, ln_line;             // DWARF rows
  uint64_t bspans;                                // sorted by (module, file)
};

// What a resolver returns: an entry plus what resolve_extent / resolve_leaf
// added to their copy of the Python dict.
struct Hit {
  const Entry* e = nullptr;
  enum Match : uint8_t { NONE, EXTENT, DWARF_LINE } match = NONE;   // "match" key
  uint32_t toplevel = 0;       // resolve_leaf's replacement toplevel, 0 = entry's own
  uint32_t site = 0;           // "site": the binding it was inlined into
  bool dwarf = false;          // "dwarf": "confirmed"
  explicit operator bool() const { return e != nullptr; }
};

class Map {
 public:
  static Map open(const char* path);        // throws std::runtime_error
  ~Map();
  Map(Map&& o) noexcept;
  Map(const Map&) = delete;

  std::string_view str(uint32_t off) const { return strs_ + off; }
  const Header& header() const { return *h_; }
  std::tuple<uint64_t, uint32_t, uint32_t> line_row(uint64_t i) const { return {ln_addr_[i], ln_file_[i], ln_line_[i]}; }
  const BSpan& bspan(uint64_t i) const { return bs_[i]; }
  uint64_t n_lines() const { return h_->n_lines; }
  void use_lines(bool on) { lines_ = on; }  // hswalk_agg.py without --binary: off
  const Entry* entry(uint32_t i) const { return e_ + i; }

  const Entry* resolve_info(uint64_t ptr) const;
  Hit resolve_addr(uint64_t addr) const;
  Hit resolve_leaf(uint64_t pc) const;
  std::optional<Range> exec_range(uint64_t addr) const;
  // hswalk_agg.py Owner: nearest preceding symtab entry in .text
  const Entry* owner(uint64_t addr) const;
  // hswalk_agg.py audit near(): "sym+0xoff" by (addr, symbol) order
  std::string near(uint64_t pc) const;

 private:
  Map() = default;
  Map& operator=(const Map&) = default;     // only for the move constructor
  Hit resolve_extent(uint64_t addr) const;
  uint32_t binding_at_line(uint32_t module, uint32_t file, int64_t line) const;
  std::optional<std::pair<uint32_t, uint32_t>> line_at(uint64_t pc) const;
  template <class T> const T* at(uint64_t off) const {
    return reinterpret_cast<const T*>(base_ + off);
  }

  const char* base_ = nullptr;
  size_t len_ = 0;
  const Header* h_ = nullptr;
  const Entry* e_ = nullptr;
  const ByInfo* bi_ = nullptr;
  const Range* ex_ = nullptr;
  const char* strs_ = nullptr;
  const uint64_t *iv_start_, *iv_end_, *iv_maxend_, *cs_addr_, *ow_addr_, *ln_addr_;
  const uint32_t *iv_idx_, *cs_idx_, *ow_idx_, *ln_file_, *ln_line_;
  const BSpan* bs_ = nullptr;
  bool lines_ = true;
};

// _atomic(e): code that ends at its st_size (a constructor's entry, a C function)
bool atomic(const Map& m, const Entry& e);

}  // namespace hsm
