#!/usr/bin/env bash
# Remove what tools/setup_and_deploy.sh and WebAPI created: schema WEBAPI_SCHEMA (owned by the app's service principal,
# made by Flyway), the service principal's Postgres role and grants, the app APP_NAME (its service principal goes with
# it), secret scope SECRET_SCOPE, the app source folder in your workspace, and the local PgBouncer password file.
# It deletes an app and its identity: read it before you run it. Stop the app first. Nothing secret is printed.
# Ends with checks; every line should say "gone". The jasypt key file in ~/.webapi-on-lakebase/secrets stays.
# Usage: bash tools/teardown.sh [config.env]
set -euo pipefail
CONF="${1:-$(cd "$(dirname "$0")/.." && pwd)/config.env}"
[ -s "$CONF" ] || { echo "config.env not found"; exit 1; }
set -a; . "$CONF"; set +a
for v in DATABRICKS_PROFILE APP_NAME LAKEBASE_ENDPOINT WEBAPI_SCHEMA SECRET_SCOPE; do
  [ -n "${!v:-}" ] || { echo "$v is not set in config.env"; exit 1; }
done
case "$WEBAPI_SCHEMA" in *[!a-z0-9_]*) echo "WEBAPI_SCHEMA must be a plain lowercase identifier"; exit 1;; esac
P="$DATABRICKS_PROFILE"; EP="$LAKEBASE_ENDPOINT"; APP="$APP_NAME"; SCOPE="$SECRET_SCOPE"; SCHEMA="$WEBAPI_SCHEMA"
OWNER=$(databricks current-user me --profile "$P" -o json | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["userName"])')
DIRS=("/Workspace/Users/$OWNER/$APP")
SP=$(databricks apps get "$APP" --profile "$P" -o json | python3 -I -c 'import sys,json; print(json.load(sys.stdin)["service_principal_client_id"])')
case "$SP" in *[!0-9a-f-]*|"") echo "unexpected service principal id; stopping"; exit 1;; esac
state=$(databricks apps get "$APP" --profile "$P" -o json | python3 -I -c 'import sys,json; print((json.load(sys.stdin).get("compute_status") or {}).get("state"))')
[ "$state" = "STOPPED" ] || { echo "app compute is $state; stop it first"; exit 1; }

HOST=$(databricks postgres get-endpoint "$EP" --profile "$P" -o json | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["status"]["hosts"]["host"])')
pg() { PGPASSWORD=$(databricks postgres generate-database-credential "$EP" --profile "$P" -o json | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["token"])') \
       psql "host=$HOST user=$OWNER dbname=databricks_postgres sslmode=require" -v ON_ERROR_STOP=1 -q "$@"; }

echo "1/4 schema $SCHEMA and the app service principal's Postgres role"
# The project owner cannot drop a schema the service principal owns, so it joins the service principal's role first.
pg <<SQL
DO \$\$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$SP') THEN
    EXECUTE format('GRANT %I TO CURRENT_USER', '$SP');
  END IF;
END \$\$;
DROP SCHEMA IF EXISTS $SCHEMA CASCADE;
DO \$\$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$SP') THEN
    EXECUTE format('DROP OWNED BY %I', '$SP');
    EXECUTE format('REVOKE %I FROM CURRENT_USER', '$SP');
    EXECUTE format('DROP ROLE %I', '$SP');
  END IF;
END \$\$;
SQL
echo "   ok"

echo "2/4 app $APP (its service principal goes with it)"
databricks apps delete "$APP" --profile "$P" > /dev/null && echo "   deleted"

echo "3/4 secret scope $SCOPE and the workspace source folder"
databricks secrets delete-scope "$SCOPE" --profile "$P" && echo "   scope deleted"
for d in "${DIRS[@]}"; do databricks workspace delete "$d" --recursive --profile "$P" && echo "   deleted $(basename "$d")"; done

echo "4/4 local PgBouncer password file"
rm -f "$HOME/.webapi-on-lakebase/secrets/pgb_local_pass" && echo "   removed"

echo "checks:"
pg -At <<SQL
SELECT 'schema '  || CASE WHEN EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = '$SCHEMA') THEN 'LEFT' ELSE 'gone' END;
SELECT 'pg role ' || CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$SP') THEN 'LEFT' ELSE 'gone' END;
SQL
databricks apps get "$APP" --profile "$P" > /dev/null 2>&1 && echo "app LEFT" || echo "app gone"
databricks secrets list-scopes --profile "$P" -o json | grep -q "\"$SCOPE\"" && echo "scope LEFT" || echo "scope gone"
for d in "${DIRS[@]}"; do databricks workspace get-status "$d" --profile "$P" > /dev/null 2>&1 && echo "folder $(basename "$d") LEFT" || echo "folder $(basename "$d") gone"; done
N=$(databricks service-principals list --profile "$P" -o json --filter "applicationId eq \"$SP\"" | python3 -I -c 'import sys,json;print(len(json.load(sys.stdin) or []))')
[ "$N" = "0" ] && echo "app service principal gone" || echo "app service principal LEFT (it may take a minute; run the check again)"
[ -e "$HOME/.webapi-on-lakebase/secrets/pgb_local_pass" ] && echo "local password file LEFT" || echo "local password file gone"
