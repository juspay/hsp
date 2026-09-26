# NixOS module: the collector and per-service agents as systemd units, the
# same shape as dist/systemd/ (user, capabilities, hardening, spool, metrics).
#
#   imports = [ hsp.nixosModules.default ];
#   services.hsp.collect = { enable = true; pyroscope = "http://pyroscope:4040"; };   # the collector host
#   services.hsp.agents.euler-api-txns.collector = "http://collector:4041";           # a service host
#
# The agent instance name is the process's comm (what /proc/PID/comm says).
{ config, lib, pkgs, ... }:
let
  cfg = config.services.hsp;
  hardening = {
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    Restart = "always";
    RestartSec = 5;
  };
  agentUnit = name: a: {
    description = "hsp continuous profiler for ${name}";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    wantedBy = [ "multi-user.target" ];
    startLimitIntervalSec = 300;
    startLimitBurst = 10;
    serviceConfig = hardening // {
      Type = "simple";
      User = cfg.user;
      Group = cfg.group;
      ExecStart = lib.concatStringsSep " " ([
        "${cfg.package}/bin/hsp" "agent" "--name" name
        "--collector" a.collector
        "--interval" (toString a.interval)
        "-F" (toString a.hz)
        "--label-mode" a.labelMode
        "--spool" "/var/spool/hsp/${name}"
        "--spool-max-mb" (toString a.spoolMaxMb)
        "--max-batch-mb" (toString a.maxBatchMb)
      ] ++ lib.optionals (a.host != null) [ "--host" a.host ]
        ++ lib.optionals (a.service != null) [ "--service" a.service ]
        ++ lib.optionals (cfg.metricsDir != null) [ "--metrics-file" "${cfg.metricsDir}/hsp-agent-${name}.prom" ]
        ++ a.extraArgs);
      # CAP_BPF: the program and its maps.  CAP_PERFMON: perf_event_open on every
      # CPU and attaching to it.  CAP_SYS_PTRACE: /proc/PID/{exe,maps} of another
      # user's process.  Nothing else; no root.
      AmbientCapabilities = [ "CAP_BPF" "CAP_PERFMON" "CAP_SYS_PTRACE" ];
      CapabilityBoundingSet = [ "CAP_BPF" "CAP_PERFMON" "CAP_SYS_PTRACE" ];
      ReadWritePaths = [ "/var/spool/hsp" ] ++ lib.optional (cfg.metricsDir != null) cfg.metricsDir;
      StateDirectory = "hsp";
      LogsDirectory = "hsp";
      MemoryMax = a.memoryMax;
      LimitMEMLOCK = "infinity";
    };
  };
in {
  options.services.hsp = {
    package = lib.mkOption {
      type = lib.types.package;
      description = "The hsp package.";
    };
    user = lib.mkOption { type = lib.types.str; default = "hsp"; description = "User the units run as."; };
    group = lib.mkOption { type = lib.types.str; default = "hsp"; description = "Group the units run as."; };
    metricsDir = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = "/var/lib/hsp/metrics";
      description = ''
        Where agents write their Prometheus text file each interval (one per
        agent), for node exporter's textfile collector: point
        services.prometheus.exporters.node.extraFlags at it with
        --collector.textfile.directory. null: no metrics files.
      '';
    };

    collect = {
      enable = lib.mkEnableOption "the hsp collector (one per fleet)";
      listen = lib.mkOption { type = lib.types.str; default = "0.0.0.0:4041"; description = "[ADDR:]PORT the collector listens on."; };
      pyroscope = lib.mkOption {
        type = lib.types.nullOr lib.types.str; default = null;
        description = "Pyroscope base URL to push to, e.g. http://pyroscope:4040. null: resolve and dump only.";
      };
      mapsDir = lib.mkOption {
        type = lib.types.path; default = "/var/lib/hsp/maps";
        description = "Where the name maps live (<id>.hsm, from `hsp symmap --install` / dist/ci/publish-map.sh).";
      };
      dumpDir = lib.mkOption { type = lib.types.nullOr lib.types.path; default = null; description = "Also write each resolved batch as folded text here."; };
      threads = lib.mkOption { type = lib.types.ints.positive; default = 4; description = "Batches resolved concurrently."; };
      queueMb = lib.mkOption { type = lib.types.ints.positive; default = 256; description = "Bound on the profiles waiting for Pyroscope (oldest dropped when full)."; };
      memoryMax = lib.mkOption { type = lib.types.str; default = "8G"; description = "MemoryMax for the unit; the maps are mmap'd, so RSS is the touched part of them."; };
      openFirewall = lib.mkOption { type = lib.types.bool; default = false; description = "Open the listen port in the firewall."; };
    };

    agents = lib.mkOption {
      default = { };
      description = "One agent per GHC service on this host, keyed by the process's comm.";
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          collector = lib.mkOption { type = lib.types.str; example = "http://collector.internal:4041"; description = "Collector URL."; };
          interval = lib.mkOption { type = lib.types.ints.positive; default = 10; description = "Seconds between batches."; };
          hz = lib.mkOption { type = lib.types.ints.positive; default = 49; description = "Samples per second per CPU while the target runs."; };
          labelMode = lib.mkOption { type = lib.types.enum [ "none" "full" "tag" ]; default = "tag"; description = "What of the thread label becomes the root frame."; };
          host = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "The host label (default: hostname)."; };
          service = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "The Pyroscope service name (default: the binary's basename)."; };
          spoolMaxMb = lib.mkOption { type = lib.types.ints.positive; default = 256; description = "Spool bound while the collector is unreachable."; };
          maxBatchMb = lib.mkOption { type = lib.types.ints.positive; default = 64; description = "Flush early at this batch size."; };
          memoryMax = lib.mkOption { type = lib.types.str; default = "256M"; description = "MemoryMax for the unit."; };
          extraArgs = lib.mkOption { type = lib.types.listOf lib.types.str; default = [ ]; example = [ "-d" "256" "--no-thunk" ]; description = "Further hsp agent flags."; };
        };
      });
    };
  };

  config = lib.mkIf (cfg.collect.enable || cfg.agents != { }) {
    users.users.${cfg.user} = { isSystemUser = true; group = cfg.group; home = "/var/lib/hsp"; description = "hsp profiler"; };
    users.groups.${cfg.group} = { };
    systemd.tmpfiles.rules =
      [ "d /var/lib/hsp 0750 ${cfg.user} ${cfg.group} -" ]
      ++ lib.optional (cfg.agents != { }) "d /var/spool/hsp 0750 ${cfg.user} ${cfg.group} -"
      ++ lib.optional (cfg.agents != { } && cfg.metricsDir != null) "d ${cfg.metricsDir} 0755 ${cfg.user} ${cfg.group} -"
      ++ lib.optional cfg.collect.enable "d ${cfg.collect.mapsDir} 0755 ${cfg.user} ${cfg.group} -"
      ++ lib.optional (cfg.collect.enable && cfg.collect.dumpDir != null) "d ${cfg.collect.dumpDir} 0750 ${cfg.user} ${cfg.group} -";

    systemd.services = lib.mapAttrs' (name: a: lib.nameValuePair "hsp-agent-${name}" (agentUnit name a)) cfg.agents
      // lib.optionalAttrs cfg.collect.enable {
        hsp-collect = {
          description = "hsp collector";
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          wantedBy = [ "multi-user.target" ];
          serviceConfig = hardening // {
            Type = "simple";
            User = cfg.user;
            Group = cfg.group;
            ExecStart = lib.concatStringsSep " " ([
              "${cfg.package}/bin/hsp" "collect"
              "--listen" cfg.collect.listen
              "--maps" cfg.collect.mapsDir
              "--threads" (toString cfg.collect.threads)
              "--queue-mb" (toString cfg.collect.queueMb)
            ] ++ lib.optionals (cfg.collect.pyroscope != null) [ "--pyroscope" cfg.collect.pyroscope ]
              ++ lib.optionals (cfg.collect.dumpDir != null) [ "--dump" cfg.collect.dumpDir ]);
            ReadOnlyPaths = [ cfg.collect.mapsDir ];
            ReadWritePaths = lib.optional (cfg.collect.dumpDir != null) cfg.collect.dumpDir;
            StateDirectory = "hsp";
            MemoryMax = cfg.collect.memoryMax;
          };
        };
      };

    networking.firewall.allowedTCPPorts = lib.mkIf (cfg.collect.enable && cfg.collect.openFirewall)
      [ (lib.toInt (lib.last (lib.splitString ":" cfg.collect.listen))) ];
  };
}
