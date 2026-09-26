# Installing hsp

## Binary
`nix build` in the repo gives `result/bin/hsp` (statically linked against
the nix store; copy the closure or `nix copy` it). Or `make && make install`.

## Without root: capabilities
`hsp agent` and `hsp record` need three capabilities, not root:

| capability | for |
|---|---|
| `CAP_BPF` | loading the BPF program and its maps |
| `CAP_PERFMON` | `perf_event_open` on every CPU; attaching a perf_event BPF program |
| `CAP_SYS_PTRACE` | reading `/proc/PID/exe` and `/proc/PID/maps` of a process owned by another user |

Either set them on the file (`setcap cap_bpf,cap_perfmon,cap_sys_ptrace+ep /usr/local/bin/hsp`)
or, better, grant them per service with systemd's `AmbientCapabilities`
(`dist/systemd/hsp-agent@.service`). `kernel.perf_event_paranoid` up to 2 is
fine with `CAP_PERFMON`; `kernel.unprivileged_bpf_disabled=1` is fine with
`CAP_BPF`. Kernels older than 5.8 have neither capability and need
`CAP_SYS_ADMIN` instead.

The collector needs no capabilities.

## systemd
```
useradd --system --home /var/lib/hsp hsp
install -Dm644 dist/systemd/hsp-agent@.service dist/systemd/hsp-collect.service /etc/systemd/system/
install -Dm644 dist/systemd/agent.env.example /etc/hsp/agent.env       # edit
install -Dm644 dist/systemd/collect.env.example /etc/hsp/collect.env   # edit
install -d -o hsp /var/spool/hsp /var/lib/hsp/maps
systemctl daemon-reload
systemctl enable --now hsp-agent@my-service            # one per GHC service (instance = the process's comm)
systemctl enable --now hsp-collect                     # on the collector host
```

## Maps
The collector pairs every batch with the map of the exact build it came from. The agent sends the binary's identity
(the SHA-256 of the file; `hsp id BIN` prints it) with each batch, `hsp symmap` stores the same id in the map, and the
collector looks for `<maps dir>/<id>.hsm` first. So the CI step is, once per built binary, before it is deployed:

    dist/ci/publish-map.sh /path/to/service-binary collector-host:/var/lib/hsp/maps

(`hsp symmap BIN --install DIR` is the same without the copy.) A map that lands after the binary is already running is
picked up on the next batch, no restart; the agent spools batches until then (`--spool`). A changed map file is reloaded.

Older forms still work: a `maps.tsv` line `<exe path>\t<exe size>\t<file>.hsm`, or a file named `<basename of exe>.hsm`.
A map found that way is refused (`wrong build` in the log and in `hsp_collect_batches_wrong_map_total`) when both it
and the batch carry an id and they differ.

Maps stay mmap'd once used. `/stats` lists them with their batch counts; `--threads` (default 4) is how many batches
resolve at once, `--queue-mb` (default 256) bounds what waits for Pyroscope.

## Metrics
The agent writes Prometheus text to `--metrics-file` every interval (for
node_exporter's textfile collector): ticks, walk outcomes, ring drops, batch
counters, last-interval walk cost, RSS. The collector serves `GET /metrics`.
The two numbers to alert on: `hsp_agent_ring_dropped_total` rising (the ring
is too small for the rate) and `hsp_agent_interval_stop / interval_samples`
falling (an RTS change broke the walk).

## Memory
Agent: the ring buffer (`-r`, default 8 MiB, kernel memory), the batch
(`--max-batch-mb`, default 64: flushed early when reached), the spool
(`--spool-max-mb`, default 256: oldest batches deleted first). Collector:
the mmap'd maps (page cache; ~2 GB touched for a 3 GB txns map under load).
