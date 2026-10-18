#!/usr/bin/env bash
# Set up and deploy WebAPI as a Databricks App that logs in to Lakebase as the app's service principal, through
# PgBouncer 1.26.1 and the refresher inside the app. Nothing secret is printed; secret values go through 0600 temp
# files, never the command line. Run tools/render.py first. Settings: config.env (see config.env.example).
#   1. Lakebase: a Postgres role for the app's service principal; CONNECT + CREATE on databricks_postgres (Flyway
#      creates WEBAPI_SCHEMA); USAGE on VOCAB_SCHEMA + SELECT on its tables and views. Stops if WEBAPI_SCHEMA exists.
#   2. Secrets pgb_local_password (WebAPI -> PgBouncer only) and webapi_jasypt_key in SECRET_SCOPE, made once in
#      ~/.webapi-on-lakebase/secrets (0600), and a NEW bridge_secret (WebAPI DB login of app/bridge.py), made in a 0600
#      temp file and deleted after the put: no copy stays on your machine. App resources pgb-local-password,
#      webapi-jasypt-key and webapi-bridge-secret point at them.
#   3. Waits while the app compute is STARTING (apps create starts it), starts it if STOPPED (billable), uploads the
#      staging folder, deploys. Then follow README, "Security": first admin, source, roles (tools/webapi_admin.py).
# The app must exist first: databricks apps create <APP_NAME> --profile <DATABRICKS_PROFILE>
# Stop later: databricks apps stop <APP_NAME> --profile <DATABRICKS_PROFILE>
# Usage: python3 -I tools/render.py && bash tools/setup_and_deploy.sh [config.env]
set -euo pipefail
CONF="${1:-$(cd "$(dirname "$0")/.." && pwd)/config.env}"
[ -s "$CONF" ] || { echo "config.env not found; copy config.env.example and fill it in"; exit 1; }
set -a; . "$CONF"; set +a
for v in DATABRICKS_PROFILE APP_NAME LAKEBASE_ENDPOINT WEBAPI_SCHEMA VOCAB_SCHEMA SECRET_SCOPE; do
  [ -n "${!v:-}" ] || { echo "$v is not set in config.env"; exit 1; }
done
for v in WEBAPI_SCHEMA VOCAB_SCHEMA; do
  case "${!v}" in *[!a-z0-9_]*) echo "$v must be a plain lowercase identifier"; exit 1;; esac
done
P="$DATABRICKS_PROFILE"; APP="$APP_NAME"; SCOPE="$SECRET_SCOPE"; EP="$LAKEBASE_ENDPOINT"
SRC="${STAGE_DIR:-$HOME/.webapi-on-lakebase/stage}"; SEC="$HOME/.webapi-on-lakebase/secrets"
OWNER=$(databricks current-user me --profile "$P" -o json | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["userName"])')
DEST="/Workspace/Users/$OWNER/$APP"
umask 077
[ -s "$SRC/app.yaml" ] || { echo "run tools/render.py first"; exit 1; }
databricks apps get "$APP" --profile "$P" > /dev/null 2>&1 || { echo "app $APP not found; create it: databricks apps create $APP --profile $P"; exit 1; }
URL=$(databricks apps get "$APP" --profile "$P" -o json | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["url"])')
[ "$URL" = "${APP_URL:-}" ] || { echo "APP_URL in config.env differs from the app's URL ($URL); fix it and run tools/render.py again"; exit 1; }

echo "1/3 Lakebase role and grants for the app's service principal"
SP=$(databricks apps get "$APP" --profile "$P" -o json | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["service_principal_client_id"])')
case "$SP" in *[!0-9a-f-]*|"") echo "unexpected service principal id; stopping"; exit 1;; esac
HOST=$(databricks postgres get-endpoint "$EP" --profile "$P" -o json | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["status"]["hosts"]["host"])')
PGPASSWORD=$(databricks postgres generate-database-credential "$EP" --profile "$P" -o json | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["token"])') \
psql "host=$HOST user=$OWNER dbname=databricks_postgres sslmode=require" -v ON_ERROR_STOP=1 -q -t <<SQL
DO \$\$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = '$WEBAPI_SCHEMA') THEN
    RAISE EXCEPTION 'schema $WEBAPI_SCHEMA exists; this setup needs an empty start';
  END IF;
END \$\$;
CREATE EXTENSION IF NOT EXISTS databricks_auth;
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$SP') THEN
    PERFORM databricks_create_role('$SP', 'service_principal');
  END IF;
END \$\$;
GRANT CONNECT, CREATE ON DATABASE databricks_postgres TO "$SP";
GRANT USAGE ON SCHEMA $VOCAB_SCHEMA TO "$SP";
GRANT SELECT ON ALL TABLES IN SCHEMA $VOCAB_SCHEMA TO "$SP";
SELECT 'role: login ' || rolcanlogin || ', super ' || rolsuper || ', tables and views readable: ' ||
       (SELECT count(*) FROM information_schema.tables t WHERE t.table_schema = '$VOCAB_SCHEMA'
          AND has_table_privilege('$SP', format('%I.%I', t.table_schema, t.table_name), 'SELECT'))
  FROM pg_roles WHERE rolname = '$SP';
SQL

echo "2/3 secrets; app resources"
mkdir -p "$SEC"; chmod 700 "$SEC"
for f in pgb_local_pass webapi_jasypt_key; do
  [ -s "$SEC/$f" ] || python3 -I -c 'import secrets,sys; open(sys.argv[1],"w").write(secrets.token_hex(24))' "$SEC/$f"
  chmod 600 "$SEC/$f"
done
databricks secrets list-scopes --profile "$P" -o json | grep -q "\"$SCOPE\"" || databricks secrets create-scope "$SCOPE" --profile "$P"
for pair in pgb_local_password:pgb_local_pass webapi_jasypt_key:webapi_jasypt_key; do
  key="${pair%%:*}"; file="$SEC/${pair##*:}"
  tmp="$(mktemp)"; chmod 600 "$tmp"
  python3 -I -c 'import json,sys; print(json.dumps({"scope":sys.argv[1],"key":sys.argv[2],"string_value":open(sys.argv[3]).read().strip()}))' "$SCOPE" "$key" "$file" > "$tmp"
  databricks secrets put-secret --json "@$tmp" --profile "$P"; rm -f "$tmp"
done
bs="$(mktemp)"; tmp="$(mktemp)"; chmod 600 "$bs" "$tmp"
python3 -I -c 'import secrets,sys; open(sys.argv[1],"w").write(secrets.token_urlsafe(32))' "$bs"
python3 -I -c 'import json,sys; print(json.dumps({"scope":sys.argv[1],"key":"bridge_secret","string_value":open(sys.argv[2]).read().strip()}))' "$SCOPE" "$bs" > "$tmp"
databricks secrets put-secret --json "@$tmp" --profile "$P"; rm -f "$bs" "$tmp"

for i in $(seq 1 80); do  # apps create starts the compute itself: wait while STARTING, start only when STOPPED
  state=$(databricks apps get "$APP" --profile "$P" -o json | python3 -I -c 'import sys,json; print((json.load(sys.stdin).get("compute_status") or {}).get("state"))')
  [ "$state" = "ACTIVE" ] && break
  if [ "$state" = "STOPPED" ]; then echo "   app compute STOPPED -> start (billable)"; databricks apps start "$APP" --profile "$P" >/dev/null; fi
  [ "$i" = 1 ] && echo "   app compute $state: waiting for ACTIVE (up to 20 min)"
  sleep 15
done
[ "$state" = "ACTIVE" ] || { echo "app compute is $state, not ACTIVE; stop here"; exit 1; }
databricks apps update "$APP" --profile "$P" --json "{\"name\":\"$APP\",\"resources\":[
 {\"name\":\"pgb-local-password\",\"secret\":{\"scope\":\"$SCOPE\",\"key\":\"pgb_local_password\",\"permission\":\"READ\"}},
 {\"name\":\"webapi-jasypt-key\",\"secret\":{\"scope\":\"$SCOPE\",\"key\":\"webapi_jasypt_key\",\"permission\":\"READ\"}},
 {\"name\":\"webapi-bridge-secret\",\"secret\":{\"scope\":\"$SCOPE\",\"key\":\"bridge_secret\",\"permission\":\"READ\"}}]}" >/dev/null
databricks apps get "$APP" --profile "$P" -o json | python3 -I -c 'import sys,json; print("   resources:", sorted(r["name"] for r in json.load(sys.stdin).get("resources") or []))'

echo "3/3 upload and deploy"
databricks workspace mkdirs "$DEST" --profile "$P"
files=(app.yaml launcher.py server.py pgb.py monitors.py bridge.py requirements.txt)
[ -s "$SRC/queries.json" ] && files+=(queries.json)
for f in "${files[@]}"; do
  databricks workspace import "$DEST/$f" --file "$SRC/$f" --format AUTO --overwrite --profile "$P"
done
databricks workspace import "$DEST/pgbouncer-1.26.1-linux-amd64-static" --file "$SRC/pgbouncer-1.26.1-linux-amd64-static" \
  --format RAW --overwrite --profile "$P"
databricks apps deploy "$APP" --source-code-path "$DEST" --profile "$P" -o json \
  | python3 -I -c 'import sys,json
t=sys.stdin.read()
try: s=json.loads(t).get("status") or {}; print("deploy:", s.get("state"), s.get("message"))
except ValueError: print(t[:500])'
echo "done. Next: README, \"Security\" (python3 -I tools/webapi_admin.py me, then the first admin, the source, the roles)"
