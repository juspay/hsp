// hsp: sampling profiler for GHC programs.
#include <cstdio>
#include <cstring>
#include <exception>

#include "exeid.h"

int cmd_fold(int argc, char** argv);
extern "C" int cmd_record(int argc, char** argv);
int cmd_agent(int argc, char** argv);
int cmd_collect(int argc, char** argv);
int cmd_symmap(int argc, char** argv);
int cmd_dump(int argc, char** argv);

// hsp id BIN: the identity the agent sends and the map carries (exeid.h)
int cmd_id(int argc, char** argv) {
  if (argc < 1) { std::fprintf(stderr, "usage: hsp id BIN\n"); return 2; }
  exeid::Id id; uint64_t size = 0;
  if (!exeid::of_file(argv[0], id, &size)) { std::fprintf(stderr, "hsp id: cannot read %s\n", argv[0]); return 1; }
  std::printf("%s %lu %s\n", exeid::hex(id).c_str(), (unsigned long)size, argv[0]);
  return 0;
}

int main(int argc, char** argv) {
  struct { const char* name; int (*run)(int, char**); const char* help; } cmds[] = {
      {"symmap", cmd_symmap, "BIN (OUT.hsm | --install MAPS_DIR) [--eventlog E] [--no-dwarf] [--user-packages a,b]   name map from the ELF"},
      {"id", cmd_id, "BIN   the binary's identity (SHA-256), as sent by the agent and stored in its map"},
      {"dump", cmd_dump, "MAP.hsm [--lines|--spans|--stats]   a map as text"},
      {"record", cmd_record, "-o FILE [-F hz] [-d depth] [-t secs] (-p PID | -- prog args)   sample a GHC process (root)"},
      {"agent", cmd_agent, "(-p PID | --name COMM) --collector URL [--interval S] [--spool DIR]   continuous: ship stacks (root)"},
      {"collect", cmd_collect, "--listen PORT --maps DIR --pyroscope URL   resolve agents' batches, push to Pyroscope"},
      {"fold", cmd_fold, "CAPTURE MAP.hsm OUTDIR [--max-unresolved PCT] [--no-lines]   report + collapsed stacks"},
  };
  if (argc >= 2)
    for (auto& c : cmds)
      if (!std::strcmp(argv[1], c.name)) {
        try {
          return c.run(argc - 2, argv + 2);
        } catch (const std::exception& e) {
          std::fprintf(stderr, "hsp %s: %s\n", c.name, e.what());
          return 1;
        }
      }
  std::fprintf(stderr, "usage:\n");
  for (auto& c : cmds) std::fprintf(stderr, "  hsp %s %s\n", c.name, c.help);
  return 2;
}
