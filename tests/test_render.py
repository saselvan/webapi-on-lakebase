"""Offline tests of tools/render.py with a made-up config and a fake binary (no Databricks).

Good config -> app.yaml staged with the values and no placeholder. Each bad case exits non-zero and writes no app.yaml:
a missing setting, a wrong binary hash, a staging folder inside the repo, a template with a placeholder render does
not know, and a template with a native-login password.
Usage: python3 -I tests/test_render.py   (exit 0 = pass)
"""
import hashlib, os, re, subprocess, sys, tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RENDER = os.path.join(REPO, "tools", "render.py")
TEMPLATE = os.path.join(REPO, "app", "app.yaml.template")
tmp = tempfile.mkdtemp(prefix="webapi-render-test.")
binary = os.path.join(tmp, "pgb-static")
open(binary, "wb").write(b"fake static binary")
SETTINGS = {
    "DATABRICKS_PROFILE": "example", "APP_NAME": "webapi-example",
    "LAKEBASE_ENDPOINT": "projects/example/branches/production/endpoints/primary",
    "LAKEBASE_HOST": "db-host.example.org", "WEBAPI_SCHEMA": "webapi_test", "VOCAB_SCHEMA": "vocab",
    "SECRET_SCOPE": "webapi-app", "SOURCE_KEY": "VOCAB", "TICK_CONCEPT_ID": "4321",
    "PGB_BINARY": binary, "PGB_SHA256": hashlib.sha256(b"fake static binary").hexdigest(),
}


def run(name, stage=None, template=TEMPLATE, **change):
    conf = {**SETTINGS, **change}
    cfg = os.path.join(tmp, f"{name}.env")
    with open(cfg, "w") as f:
        f.write("# test config\n" + "".join(f"{k}={v}\n" for k, v in conf.items() if v is not None))
    stage = stage or os.path.join(tmp, f"stage-{name}")
    r = subprocess.run([sys.executable, "-I", RENDER, "--config", cfg, "--stage", stage, "--template", template],
                       capture_output=True, text=True)
    return r, os.path.join(stage, "app.yaml")


# Good config
r, out = run("good")
assert r.returncode == 0, r.stdout + r.stderr
text = open(out).read()
assert not re.search(r"__[A-Z_]+__", text), "placeholder left"
for v in ('value: "db-host.example.org"', "value: webapi_test", 'value: "VOCAB"', 'value: "4321"',
          "value: webapi_test.BATCH_", f'value: "{SETTINGS["PGB_SHA256"]}"'):
    assert v in text, v
assert oct(os.stat(out).st_mode & 0o777) == "0o600"
stage = os.path.dirname(out)
for f in ("launcher.py", "server.py", "pgb.py", "monitors.py", "requirements.txt", "pgbouncer-1.26.1-linux-amd64-static"):
    assert os.path.isfile(os.path.join(stage, f)), f
assert not os.path.exists(os.path.join(stage, "queries.json"))
assert "db-host" not in r.stdout + r.stderr, "the host was printed"
assert "30 env vars" in r.stdout, r.stdout  # every env entry parsed, names with digits too
print("PASS: good config renders every value, 0600, files staged, host not printed")


def refused(name, why, **kw):
    r, out = run(name, **kw)
    assert r.returncode != 0, f"{name}: accepted"
    assert why in r.stdout + r.stderr, f"{name}: {r.stdout + r.stderr}"
    assert not os.path.exists(out), f"{name}: app.yaml written"
    print(f"PASS: refused {name} ({why})")


refused("missing-host", "LAKEBASE_HOST is not set", LAKEBASE_HOST=None)
refused("wrong-hash", "differs from PGB_SHA256", PGB_SHA256="0" * 64)
refused("stage-in-repo", "outside the repo", stage=os.path.join(REPO, "stage-test"))
assert not os.path.exists(os.path.join(REPO, "stage-test"))
bad = os.path.join(tmp, "extra.template")
open(bad, "w").write(open(TEMPLATE).read() + "  - {name: EXTRA, value: \"__NOT_A_SETTING__\"}\n")
refused("unknown-placeholder", "placeholder was not replaced", template=bad)
native = os.path.join(tmp, "native.template")
open(native, "w").write(open(TEMPLATE).read() + "  - {name: DATASOURCE_PASSWORD, valueFrom: webapi-pg-password}\n")
refused("native-login", "native login", template=native)
print("PASS: tests/test_render.py")
