#!/usr/bin/env bash
# Upload the staged app and deploy it to an app that exists and runs. tools/setup_and_deploy.sh runs this as its last
# step; run it alone to deploy a new version (no schema, secret or resource change). Run tools/render.py first.
# It deploys only committed code: it stops if a staged app file differs from app/<file> at git HEAD, and it checks
# the uploaded copies against HEAD the same way before the deploy.
# Usage: python3 -I tools/render.py && bash tools/deploy.sh [config.env]
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CONF="${1:-$REPO/config.env}"
[ -s "$CONF" ] || { echo "config.env not found; copy config.env.example and fill it in"; exit 1; }
set -a; . "$CONF"; set +a
for v in DATABRICKS_PROFILE APP_NAME; do
  [ -n "${!v:-}" ] || { echo "$v is not set in config.env"; exit 1; }
done
P="$DATABRICKS_PROFILE"; APP="$APP_NAME"
SRC="${STAGE_DIR:-$HOME/.webapi-on-lakebase/stage}"
OWNER=$(databricks current-user me --profile "$P" -o json | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["userName"])')
DEST="/Workspace/Users/$OWNER/$APP"
umask 077
[ -s "$SRC/app.yaml" ] || { echo "run tools/render.py first"; exit 1; }
state=$(databricks apps get "$APP" --profile "$P" -o json | python3 -I -c 'import sys,json; print((json.load(sys.stdin).get("compute_status") or {}).get("state"))')
[ "$state" = "ACTIVE" ] || { echo "app compute is $state, not ACTIVE; start it: databricks apps start $APP --profile $P"; exit 1; }

code=(launcher.py artifacts.py server.py pgb.py monitors.py bridge.py requirements.txt)
commit=$(git -C "$REPO" rev-parse --short HEAD)
for f in "${code[@]}"; do
  git -C "$REPO" show "HEAD:app/$f" | cmp -s - "$SRC/$f" \
    || { echo "staged $f differs from app/$f at $commit; commit it, then run tools/render.py again"; exit 1; }
done

files=(app.yaml "${code[@]}")
[ -s "$SRC/queries.json" ] && files+=(queries.json)
databricks workspace mkdirs "$DEST" --profile "$P"
for f in "${files[@]}"; do
  databricks workspace import "$DEST/$f" --file "$SRC/$f" --format AUTO --overwrite --profile "$P"
done
databricks workspace import "$DEST/pgbouncer-1.26.1-linux-amd64-static" --file "$SRC/pgbouncer-1.26.1-linux-amd64-static" \
  --format RAW --overwrite --profile "$P"
tmp=$(mktemp)
for f in "${code[@]}"; do
  databricks workspace export "$DEST/$f" --format AUTO --profile "$P" > "$tmp"
  git -C "$REPO" show "HEAD:app/$f" | cmp -s - "$tmp" || { rm -f "$tmp"; echo "uploaded $f differs from $commit; not deployed"; exit 1; }
done
rm -f "$tmp"
echo "   uploaded app files match commit $commit"
databricks apps deploy "$APP" --source-code-path "$DEST" --profile "$P" -o json \
  | python3 -I -c 'import sys,json
t=sys.stdin.read()
try: s=json.loads(t).get("status") or {}; print("deploy:", s.get("state"), s.get("message"))
except ValueError: print(t[:500])'
