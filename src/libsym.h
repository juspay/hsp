// Names for program counters outside the executable: the capture's header
// lists the target's executable mappings (hsp_abi.h), and a mapped file's
// own ELF symbols name the function.  `memcpy [libc.so.6]'; `[libc.so.6]'
// when the file cannot be read or has no symbol there; nothing when the
// address is in no mapping.
#pragma once
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace libsym {

struct Mapping { uint64_t start, end, offset; std::string path; };

class Resolver {
 public:
  enum Kind { SYMBOL, LIBRARY, UNMAPPED };
  explicit Resolver(std::vector<Mapping> maps) : maps_(std::move(maps)) {
    std::sort(maps_.begin(), maps_.end(), [](auto& a, auto& b) { return a.start < b.start; });
  }
  bool empty() const { return maps_.empty(); }

  // the name for pc and how it was found; "" for UNMAPPED
  std::pair<std::string, Kind> name(uint64_t pc) {
    auto it = std::upper_bound(maps_.begin(), maps_.end(), pc, [](uint64_t a, const Mapping& m) { return a < m.start; });
    if (it == maps_.begin() || pc >= (--it)->end) return {"", UNMAPPED};
    const Mapping& m = *it;
    std::string lib = "[" + base(m.path) + "]";
    if (m.path.empty() || m.path[0] != '/') return {lib, LIBRARY};       // [vdso], anonymous code
    const File& f = file(m.path);
    if (auto s = f.symbol(pc - m.start + m.offset)) return {*s + " " + lib, SYMBOL};
    return {lib, LIBRARY};
  }

 private:
  struct Sym { uint64_t addr, size; std::string name; };
  struct Seg { uint64_t off, filesz, vaddr; };
  struct File {
    std::vector<Sym> syms;       // sorted by addr
    std::vector<Seg> segs;       // PT_LOAD
    bool full = false;           // from .symtab (else .dynsym: exported names only)

    // the function containing file offset `off'
    std::optional<std::string> symbol(uint64_t off) const {
      uint64_t va = 0; bool found = false;
      for (const Seg& s : segs)
        if (off >= s.off && off < s.off + s.filesz) { va = off - s.off + s.vaddr; found = true; break; }
      if (!found) return std::nullopt;
      auto it = std::upper_bound(syms.begin(), syms.end(), va, [](uint64_t a, const Sym& s) { return a < s.addr; });
      if (it == syms.begin()) return std::nullopt;
      --it;
      // inside the symbol's extent; hand-written assembly often has size 0,
      // and then the nearest symbol before is only trusted from a full table
      if (va < it->addr + it->size || (it->size == 0 && full)) return it->name;
      return std::nullopt;
    }
  };

  static std::string base(const std::string& p) {
    if (p.empty()) return "anon";
    if (p[0] == '[') return p.substr(1, p.size() > 2 ? p.size() - 2 : 0);
    return p.substr(p.rfind('/') + 1);
  }

  const File& file(const std::string& path) {
    auto [it, fresh] = files_.try_emplace(path);
    if (fresh) load(path, it->second);
    return it->second;
  }

  static void load(const std::string& path, File& f) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    struct stat st{};
    if (fstat(fd, &st) || st.st_size < (off_t)sizeof(Elf64_Ehdr)) { close(fd); return; }
    size_t len = st.st_size;
    void* mem = mmap(nullptr, len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mem == MAP_FAILED) return;
    const unsigned char* m = static_cast<const unsigned char*>(mem);
    auto fits = [&](uint64_t off, uint64_t n) { return off <= len && n <= len - off; };
    const Elf64_Ehdr* eh = reinterpret_cast<const Elf64_Ehdr*>(m);
    if (!std::memcmp(eh->e_ident, ELFMAG, SELFMAG) && eh->e_ident[EI_CLASS] == ELFCLASS64 &&
        fits(eh->e_phoff, uint64_t(eh->e_phnum) * sizeof(Elf64_Phdr)) && fits(eh->e_shoff, uint64_t(eh->e_shnum) * sizeof(Elf64_Shdr))) {
      const Elf64_Phdr* ph = reinterpret_cast<const Elf64_Phdr*>(m + eh->e_phoff);
      for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_LOAD) f.segs.push_back({ph[i].p_offset, ph[i].p_filesz, ph[i].p_vaddr});
      const Elf64_Shdr* sh = reinterpret_cast<const Elf64_Shdr*>(m + eh->e_shoff);
      const Elf64_Shdr* tab = nullptr;
      for (int i = 0; i < eh->e_shnum; i++) {
        if (sh[i].sh_type == SHT_SYMTAB) { tab = &sh[i]; f.full = true; break; }
        if (sh[i].sh_type == SHT_DYNSYM) tab = &sh[i];
      }
      if (tab && tab->sh_link < eh->e_shnum && fits(tab->sh_offset, tab->sh_size)) {
        const Elf64_Shdr& strs = sh[tab->sh_link];
        if (strs.sh_type == SHT_STRTAB && fits(strs.sh_offset, strs.sh_size)) {
          const Elf64_Sym* sym = reinterpret_cast<const Elf64_Sym*>(m + tab->sh_offset);
          const char* str = reinterpret_cast<const char*>(m + strs.sh_offset);
          for (size_t k = 0, n = tab->sh_size / sizeof(Elf64_Sym); k < n; k++) {
            int type = ELF64_ST_TYPE(sym[k].st_info);
            if ((type != STT_FUNC && type != STT_GNU_IFUNC) || sym[k].st_shndx == SHN_UNDEF || sym[k].st_name >= strs.sh_size) continue;
            const char* nm = str + sym[k].st_name;
            size_t nl = strnlen(nm, strs.sh_size - sym[k].st_name);
            if (nl) f.syms.push_back({sym[k].st_value, sym[k].st_size, std::string(nm, nl)});
          }
          // one address, several names (aliases): the longest extent, then the shortest name
          std::sort(f.syms.begin(), f.syms.end(), [](const Sym& a, const Sym& b) {
            return a.addr != b.addr ? a.addr < b.addr : a.size != b.size ? a.size < b.size
                 : a.name.size() != b.name.size() ? a.name.size() > b.name.size() : a.name > b.name;
          });
        }
      }
    }
    munmap(mem, len);
  }

  std::vector<Mapping> maps_;
  std::unordered_map<std::string, File> files_;
};

}  // namespace libsym
