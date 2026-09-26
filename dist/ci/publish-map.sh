#!/usr/bin/env bash
# CI step, after the service binary is built: make its name map and put it
# where the collector looks, named by the binary's identity, before the
# binary is deployed.  The collector loads it on the first batch; if the
# binary is deployed first, agents spool their batches until the map lands.
#
#   dist/ci/publish-map.sh BIN DEST [symmap flags...]
#
#   DEST   the collector's maps directory: a local path, or user@host:/path
#          (rsync over ssh: the file appears atomically under its final name)
#
# Needs: hsp on PATH (or HSP=/path/to/hsp), rsync for a remote DEST.
# Prints the map's identity and where it went.
set -euo pipefail
BIN=$1 DEST=$2; shift 2
HSP=${HSP:-hsp}
ID=$("$HSP" id "$BIN" | cut -d' ' -f1)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
MAP=$("$HSP" symmap "$BIN" --install "$TMP" "$@")     # $TMP/<id>.hsm
[ "$(basename "$MAP")" = "$ID.hsm" ]
case $DEST in
  *:*) rsync -a --partial "$MAP" "$DEST/" ;;          # rsync writes a temp name, then renames
  *)   install -D -m 0644 "$MAP" "$DEST/$ID.hsm.tmp" && mv -f "$DEST/$ID.hsm.tmp" "$DEST/$ID.hsm" ;;
esac
echo "$ID -> $DEST/$ID.hsm ($(du -h "$MAP" | cut -f1))"
