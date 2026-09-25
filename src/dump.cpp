// hsp dump: an .hsm as text, one entry per line, for diffing two maps of
// the same binary (e.g. one built from the ELF against one from an eventlog).  Sort both outputs before diffing: entry order is not part
// of what the resolvers depend on, except through the tie-break rules that
// `hsp fold` parity checks anyway.
//
//   hsp dump MAP.hsm [--lines] [--spans]
#include <cstdio>
#include <cstring>

#include "hsm.h"

int cmd_dump(int argc, char** argv) {
  if (argc < 1) { std::fprintf(stderr, "usage: hsp dump MAP.hsm [--lines] [--spans] [--stats]\n"); return 2; }
  bool lines = false, spans = false, stats = false;
  for (int i = 1; i < argc; i++) {
    if (!std::strcmp(argv[i], "--lines")) lines = true;
    else if (!std::strcmp(argv[i], "--spans")) spans = true;
    else if (!std::strcmp(argv[i], "--stats")) stats = true;
  }
  hsm::Map m = hsm::Map::open(argv[0]);
  const hsm::Header& h = m.header();
  if (stats) {
    std::printf("entries %lu by_info %lu intervals %lu exec %lu cstarts %lu owner %lu lines %lu bspans %lu strings %lu info_delta %ld\n",
                (unsigned long)h.n_entries, (unsigned long)h.n_byinfo, (unsigned long)h.n_iv, (unsigned long)h.n_exec,
                (unsigned long)h.n_cstarts, (unsigned long)h.n_owner, (unsigned long)h.n_lines, (unsigned long)h.n_bspans,
                (unsigned long)h.n_strings, (long)h.info_delta);
    return 0;
  }
  if (lines) {
    for (uint64_t i = 0; i < h.n_lines; i++) {
      auto [a, f, l] = m.line_row(i);
      std::printf("L %lx %s %u\n", (unsigned long)a, std::string(m.str(f)).c_str(), l);
    }
    return 0;
  }
  if (spans) {
    for (uint64_t i = 0; i < h.n_bspans; i++) {
      const hsm::BSpan& s = m.bspan(i);
      std::printf("S %s %s %s %ld %ld\n", std::string(m.str(s.module)).c_str(), std::string(m.str(s.file)).c_str(),
                  std::string(m.str(s.toplevel)).c_str(), (long)s.lo, (long)s.hi);
    }
    return 0;
  }
  auto p = [&](uint32_t s) { return std::string(m.str(s)); };
  for (uint64_t i = 0; i < h.n_entries; i++) {
    const hsm::Entry& e = *m.entry(i);
    std::printf("%lx %lu %lx\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", (unsigned long)e.addr, (unsigned long)e.size,
                (unsigned long)e.info_ptr, p(e.symbol).c_str(), p(e.package_name).c_str(), p(e.module).c_str(), p(e.name).c_str(),
                p(e.toplevel).c_str(), p(e.src_file).c_str(), p(e.src_span).c_str(), p(e.closure_type_name).c_str(),
                p(e.inlined).c_str(), p(e.bucket).c_str(), p(e.rollup).c_str(), p(e.source_tier).c_str());
  }
  return 0;
}
