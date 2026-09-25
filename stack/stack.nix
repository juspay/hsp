# The hsp UI stack as a services-flake / process-compose-flake module:
# Pyroscope (storage + queries), Grafana (the UI; nixpkgs' Pyroscope has no
# embedded frontend) provisioned with the data source and the hsp dashboard,
# and an `hsp collect` for agents to send to.
#
# Data lives under ./data/<service> of the directory process-compose runs
# in (flake.nix's wrapper cd's to $HSP_STACK_DIR).  HSP_MAPS at run time is
# where the collector looks for .hsm maps (default ./maps).
{ hsp, grafanaPort, pyroscopePort, collectPort }:
{ pkgs, config, lib, ... }:
{
  services.pyroscope.pyroscope = {
    enable = true;
    httpPort = pyroscopePort;
    # ingester-based single-binary storage: the default dual write produced
    # v2 segments the read path did not find
    extraFlags = [ "-architecture.storage=v1" "-write-path=ingester" ];
    extraConfig = {
      # the module only parameterises the HTTP port; a second instance beside
      # another Pyroscope needs its own gRPC and gossip ports too
      server.grpc_listen_port = pyroscopePort + 5055;
      memberlist.bind_port = pyroscopePort + 3906;
      self_profiling.disable_push = true;
      analytics.reporting_enabled = false;
      limits = {
        # a folded push of a whole capture is tens of MB (default 4 MiB/s)
        ingestion_rate_mb = 512;
        ingestion_burst_size_mb = 1024;
        reject_older_than = "72h";
        # Haskell stacks run to 512-1024 frames
        max_profile_stacktrace_depth = 2048;
        max_profile_size_bytes = 268435456;
        max_profile_stacktrace_samples = 1000000;
        # a txns flame graph is ~120k nodes; at the default 8192 most names vanish into "other"
        max_flamegraph_nodes_default = 262144;
      };
    };
  };

  services.grafana.grafana = {
    enable = true;
    http_port = grafanaPort;
    datasources = [{
      name = "Pyroscope";
      uid = "hsp-pyroscope";
      type = "grafana-pyroscope-datasource";
      access = "proxy";
      url = "http://127.0.0.1:${toString pyroscopePort}";
      isDefault = true;
    }];
    providers = [{
      name = "hsp";
      type = "file";
      options.path = ./grafana/dashboards;
    }];
    # local use: bound to loopback, anonymous admin, no login form
    extraConf = {
      server.http_addr = "127.0.0.1";
      "auth.anonymous" = { enabled = true; org_role = "Admin"; };
      auth.disable_login_form = true;
      analytics = { reporting_enabled = false; check_for_updates = false; check_for_plugin_updates = false; };
      news.news_feed_enabled = false;
      # the background installer of optional apps cannot write into the nix store
      plugins.preinstall_disabled = true;
    };
  };

  settings.processes.collect = {
    command = ''
      mkdir -p "''${HSP_MAPS:-./maps}" ./data/collect-dump
      exec ${hsp}/bin/hsp collect --listen 127.0.0.1:${toString collectPort} \
        --maps "''${HSP_MAPS:-./maps}" --pyroscope http://127.0.0.1:${toString pyroscopePort} \
        --dump ./data/collect-dump
    '';
    depends_on.pyroscope.condition = "process_healthy";
    readiness_probe = {
      http_get = { host = "127.0.0.1"; port = collectPort; path = "/healthz"; };
      period_seconds = 2;
    };
  };
}
