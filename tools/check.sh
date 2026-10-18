#!/usr/bin/env bash
# Run every offline test (tests/test_*.py) and a syntax check of the shell tools. Exit 0 = all pass.
# No network, no Databricks, no Lakebase. Needs uv (https://docs.astral.sh/uv/).
# Usage: bash tools/check.sh
set -uo pipefail
cd "$(dirname "$0")/.."
log=$(mktemp); fail=0
for s in tools/*.sh; do
  bash -n "$s" || { echo "FAIL syntax $s"; fail=1; }
done
for t in tests/test_*.py; do
  if uv run --no-project --python 3.11 --with bcrypt==5.0.0 --with "psycopg[binary]==3.3.4" python -I "$t" > "$log" 2>&1; then
    echo "PASS $t"
  else
    echo "FAIL $t"; grep -E "^ *FAIL" "$log" | head -5 || tail -5 "$log"; fail=1
  fi
done
rm -f "$log"
[ "$fail" = 0 ] && echo "ALL PASS" || echo "SOME FAIL"
exit "$fail"
