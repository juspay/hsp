// hsp: sampling profiler for GHC programs.
#include <cstdio>
#include <cstring>
#include <exception>

int cmd_fold(int argc, char** argv);
extern "C" int cmd_record(int argc, char** argv);
int cmd_agent(int argc, char** argv);
int cmd_collect(int argc, char** argv);
int cmd_symmap(int argc, char** argv);
int cmd_dump(int argc, char** argv);

int main(int argc, char** argv) {
  struct { const char* name; int (*run)(int, char**); const char* help; } cmds[] = {
      {"symmap", cmd_symmap, "BIN OUT.hsm [--eventlog E] [--no-dwarf] [--user-packages a,b]   name map from the ELF"},
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
