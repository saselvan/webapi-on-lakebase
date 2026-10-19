"""Offline tests of the CDM-in-Delta path: a refused JDBC driver stops the launcher, and tools/webapi_admin.py
source-add-cdm.

**What this protects:** the Java code WebAPI loads (only the pinned Databricks JDBC jar may enter WEB-INF/lib), and the
CDM login token (it lives only in WebAPI's encrypted password field: never in the URL, a printed line or a file in the
repo).

**Attacker list (minimum, extended):**
The driver fetch itself (tampered zip, other jar, `../` entries, symlinks, the pinned values) is in test_artifacts.py.
7. A refused driver stops the launcher: main() raises before Java starts.
9. A login smuggled into the URL through CDM_HTTP_PATH (`;UID=`, `;PWD=`, `;AuthMech=`): refused.
10. A schema name with SQL or a separator (`;`, a space, a quote, no catalog): refused.
11. The token file group- or world-readable, a symlink, or inside the repo: refused.
12. A token with a `;` or a space or a newline in it (two values in one file): refused.
13. WebAPI echoes the token in its answer: the printed line holds `<token>`, never the value.
14. The body: dialect spark, username `token`, krbAuthMethod `password` (WebAPI 2.15.2 answers 500 without it),
    the token only in `password`, Vocabulary priority 0 (the Lakebase source stays the default vocabulary).

Usage: python3 -I tests/test_cdm_source.py   (exit 0 = pass)
"""
import contextlib, importlib.util, io, json, os, shutil, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="cdm-source-test.")
for f in ("launcher.py", "artifacts.py"):
    shutil.copy(os.path.join(HERE, "..", "app", f), TMP)
sys.path.insert(0, TMP)
import launcher  # noqa: E402

FAILS = []
TOKEN = "dapi" + "0f1e2d3c4b5a69788796a5b4c3d2e1f0"  # a test value, not a real token


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        FAILS.append(name)


def raises(fn, kind=Exception):
    try:
        fn()
    except kind as e:
        return e
    except BaseException as e:  # noqa: BLE001
        return e if kind is BaseException else None
    return None


# 7: a refused driver stops main() before Java starts
STARTED = []
os.environ["APP_WORK"] = os.path.join(TMP, "main_work")
launcher.fetch_jre = lambda w: "/bin/false"
launcher.fetch_webapi = lambda w: os.path.join(TMP, "webapi")
launcher.fetch_atlas = lambda w: None
launcher.fetch_jdbc = lambda w, r: (_ for _ in ()).throw(RuntimeError("JDBC jar sha256 mismatch: test"))
launcher.subprocess.Popen = lambda *a, **k: STARTED.append(a)
err = raises(launcher.main, BaseException)
check("7 refused driver stops the launcher before Java", isinstance(err, RuntimeError) and "JDBC" in str(err) and STARTED == [],
      f"{err!r} {STARTED}")

# ---- tools/webapi_admin.py source-add-cdm ----
REPO = os.path.join(TMP, "repo")
os.makedirs(os.path.join(REPO, "tools"))
shutil.copy(os.path.join(HERE, "..", "tools", "webapi_admin.py"), os.path.join(REPO, "tools"))
SECRETS = os.path.join(TMP, "secrets")
os.makedirs(SECRETS)
TOKEN_FILE = os.path.join(SECRETS, "cdm_token")
with open(TOKEN_FILE, "w") as f:
    f.write(TOKEN + "\n")
os.chmod(TOKEN_FILE, 0o600)
CONF = {"DATABRICKS_PROFILE": "test", "APP_NAME": "test-app", "LAKEBASE_ENDPOINT": "projects/p/branches/b/endpoints/e",
        "VOCAB_SCHEMA": "vocab", "CDM_SOURCE_KEY": "CDM", "CDM_HTTP_PATH": "/sql/1.0/warehouses/0123abcd",
        "CDM_SCHEMA": "cat.cdm", "CDM_VOCAB_SCHEMA": "cat.vocab", "CDM_RESULTS_SCHEMA": "cat.results",
        "CDM_TEMP_SCHEMA": "cat.scratch", "CDM_TOKEN_FILE": TOKEN_FILE}
with open(os.path.join(REPO, "config.env"), "w") as f:
    f.write("".join(f"{k}={v}\n" for k, v in CONF.items()))
spec = importlib.util.spec_from_file_location("webapi_admin", os.path.join(REPO, "tools", "webapi_admin.py"))
argv, sys.argv = sys.argv, ["webapi_admin.py"]
adm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adm)
sys.argv = argv
HOST = "workspace.example.com"


def exits(fn):
    return raises(fn, SystemExit) is not None


src = adm.cdm_source(CONF, HOST, TOKEN)
check("14 body: spark, username token, krbAuthMethod password, token only in password",
      src["dialect"] == "spark" and src["username"] == "token" and src.get("krbAuthMethod") == "password"
      and src["password"] == TOKEN and TOKEN not in json.dumps({k: v for k, v in src.items() if k != "password"}), str(src))
check("14 body: URL has AuthMech=3 and no login", src["connectionString"] ==
      f"jdbc:databricks://{HOST}:443/default;transportMode=http;ssl=1;httpPath=/sql/1.0/warehouses/0123abcd;AuthMech=3"
      and not any(x in src["connectionString"].upper() for x in ("UID=", "PWD=", "PASSWORD")), src["connectionString"])
check("14 body: 4 daimons, Vocabulary priority 0", [(d["daimonType"], d["tableQualifier"], d["priority"]) for d in src["daimons"]]
      == [("CDM", "cat.cdm", 0), ("Vocabulary", "cat.vocab", 0), ("Results", "cat.results", 1), ("Temp", "cat.scratch", 0)],
      str(src["daimons"]))

for bad in ("/sql/1.0/warehouses/0123abcd;PWD=x", "/sql/1.0/warehouses/0123abcd;UID=token", "/sql/1.0/warehouses/ab;AuthMech=11",
            "/sql/1.0/warehouses/ab cd", "", "/sql/1.0/endpoints/ab"):
    check(f"9 CDM_HTTP_PATH refused: {bad!r}", exits(lambda: adm.cdm_source(dict(CONF, CDM_HTTP_PATH=bad), HOST, TOKEN)))
for bad in ("cdm", "cat.cdm;DROP", "cat.cd m", "cat.'cdm'", "a.b.c", ""):
    check(f"10 schema refused: {bad!r}", exits(lambda: adm.cdm_source(dict(CONF, CDM_SCHEMA=bad), HOST, TOKEN)))
check("10 host with a separator refused", exits(lambda: adm.cdm_source(CONF, HOST + ";PWD=x", TOKEN)))
check("10 source key with a separator refused", exits(lambda: adm.cdm_source(dict(CONF, CDM_SOURCE_KEY="D;x"), HOST, TOKEN)))

check("11 0600 token file read", adm.read_token(TOKEN_FILE) == TOKEN)
for mode in (0o640, 0o604, 0o644):
    os.chmod(TOKEN_FILE, mode)
    check(f"11 token file mode {oct(mode)} refused", exits(lambda: adm.read_token(TOKEN_FILE)))
os.chmod(TOKEN_FILE, 0o600)
LINK = os.path.join(SECRETS, "cdm_token_link")
os.symlink(TOKEN_FILE, LINK)
check("11 token file symlink refused", raises(lambda: adm.read_token(LINK), BaseException) is not None)
IN_REPO = os.path.join(REPO, "cdm_token")
shutil.copy(TOKEN_FILE, IN_REPO)
os.chmod(IN_REPO, 0o600)
check("11 token file inside the repo refused", exits(lambda: adm.read_token(IN_REPO)))
for bad in (TOKEN + ";PWD=x", TOKEN + " " + TOKEN, TOKEN + "\n" + TOKEN, "short"):
    p = os.path.join(SECRETS, "bad_token")
    with open(p, "w") as f:
        f.write(bad)
    os.chmod(p, 0o600)
    check(f"12 token value refused: {bad[-8:]!r}", exits(lambda: adm.read_token(p)))
    os.remove(p)

SENT = []
adm.cli = lambda *a: {"details": {"host": "https://" + HOST + "/"}} if a[:2] == ("auth", "describe") else {}
adm.call = lambda method, path, tok, body=None, headers=None: (SENT.append((method, path, body)) or
                                                                 (200, json.dumps({"echo": TOKEN, "key": "CDM"}).encode()))
out = io.StringIO()
with contextlib.redirect_stdout(out):
    adm.source_add_cdm("user-token")
printed = out.getvalue()
check("13 echoed token masked in the printed line", TOKEN not in printed and "<token>" in printed, printed)
sent = SENT[0][2].decode() if SENT else ""
check("13 one POST /WebAPI/source/ with the token only in password", len(SENT) == 1 and SENT[0][:2] == ("POST", "/WebAPI/source/")
      and sent.count(TOKEN) == 1 and f'"password": "{TOKEN}"' in sent, str(SENT[:1])[:300])

shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{'ALL PASS' if not FAILS else str(len(FAILS)) + ' FAIL'}")
sys.exit(1 if FAILS else 0)
