"""Offline tests of the CDM-in-Delta path: the launcher's JDBC driver fetch, and tools/webapi_admin.py source-add-cdm.

**What this protects:** the Java code WebAPI loads (only the pinned Databricks JDBC jar may enter WEB-INF/lib), and the
CDM login token (it lives only in WebAPI's encrypted password field: never in the URL, a printed line or a file in the
repo).

**Attacker list (minimum, extended):**
1. A tampered zip (its SHA-256 differs): refused, nothing written to WEB-INF/lib, the zip removed.
2. A zip with the pinned hash but a different jar inside: refused, nothing written.
3. A zip without the pinned entry: refused with a RuntimeError, nothing written.
4. A zip with a `../` entry next to the jar: nothing written outside WEB-INF/lib (the zip is never extracted).
5. A jar, or a symlink to a file outside, already at WEB-INF/lib/DatabricksJDBC42.jar: refused, the outside file unchanged.
6. WEB-INF/lib missing, or a symlink to a folder outside: refused, nothing written there.
7. A refused driver stops the launcher: main() raises before Java starts.
8. The pinned URL, zip hash, entry and jar hash are the published values (https, databricks-bi-artifacts).
9. A login smuggled into the URL through CDM_HTTP_PATH (`;UID=`, `;PWD=`, `;AuthMech=`): refused.
10. A schema name with SQL or a separator (`;`, a space, a quote, no catalog): refused.
11. The token file group- or world-readable, a symlink, or inside the repo: refused.
12. A token with a `;` or a space or a newline in it (two values in one file): refused.
13. WebAPI echoes the token in its answer: the printed line holds `<token>`, never the value.
14. The body: dialect spark, username `token`, krbAuthMethod `password` (WebAPI 2.15.2 answers 500 without it),
    the token only in `password`, Vocabulary priority 0 (the Lakebase source stays the default vocabulary).

Usage: python3 -I tests/test_cdm_source.py   (exit 0 = pass)
"""
import contextlib, hashlib, importlib.util, io, json, os, shutil, sys, tempfile, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="cdm-source-test.")
shutil.copy(os.path.join(HERE, "..", "app", "launcher.py"), TMP)
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


# ---- launcher.fetch_jdbc ----
PINNED = (launcher.JDBC_ZIP, launcher.JDBC_ZIP_SHA, launcher.JDBC_ENTRY, launcher.JDBC_JAR_SHA)
check("8 pinned values", PINNED == (
    "https://databricks-bi-artifacts.s3.us-east-2.amazonaws.com/simbaspark-drivers/jdbc/2.6.36/DatabricksJDBC42-2.6.36.1062.zip",
    "886fb56d96029cfc8e21bd7520ce7888c1ca81a13d9dea58f5c852127959bab0",
    "DatabricksJDBC42-2.6.36.1062/DatabricksJDBC42.jar",
    "83ba88ba02c4765630f99ba5e2a193b511a5c8eb867b6d44941a562100e21563"), str(PINNED))

JAR = b"PK-fake-databricks-jdbc-jar"


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


def case(name, zip_bytes, zip_sha=None, jar_sha=None, lib="dir", dest=None):
    """A fresh WebAPI root; returns (exception or None, root, work, outside)."""
    base = os.path.join(TMP, name)
    work, root, outside = (os.path.join(base, d) for d in ("work", "webapi", "outside"))
    for d in (work, root, outside):
        os.makedirs(d)
    if lib == "dir":
        os.makedirs(os.path.join(root, "WEB-INF", "lib"))
    elif lib == "link":
        os.makedirs(os.path.join(root, "WEB-INF"))
        os.symlink(outside, os.path.join(root, "WEB-INF", "lib"))
    if dest == "file":
        open(os.path.join(root, "WEB-INF", "lib", launcher.JDBC_JAR), "wb").write(b"old")
    elif dest == "link":
        open(os.path.join(outside, "victim.jar"), "wb").write(b"victim")
        os.symlink(os.path.join(outside, "victim.jar"), os.path.join(root, "WEB-INF", "lib", launcher.JDBC_JAR))
    launcher.urllib.request.urlretrieve = lambda url, path: open(path, "wb").write(zip_bytes)
    launcher.JDBC_ZIP_SHA = zip_sha or hashlib.sha256(zip_bytes).hexdigest()
    launcher.JDBC_JAR_SHA = jar_sha or hashlib.sha256(JAR).hexdigest()
    err = raises(lambda: launcher.fetch_jdbc(work, root), RuntimeError)
    return err, root, work, outside


def lib_files(root):
    lib = os.path.join(root, "WEB-INF", "lib")
    return sorted(os.listdir(lib)) if os.path.isdir(lib) and not os.path.islink(lib) else []


def tree(path):
    return sorted(os.path.relpath(os.path.join(d, f), path) for d, _, fs in os.walk(path) for f in fs)


good = make_zip([(PINNED[2], JAR)])
err, root, work, _ = case("good", good)
dest = os.path.join(root, "WEB-INF", "lib", launcher.JDBC_JAR)
check("good zip: jar written, zip removed", err is None and open(dest, "rb").read() == JAR and os.listdir(work) == [],
      f"{err} {os.listdir(work)}")
check("good zip: jdbc event logged with the jar hash", any(e.get("event") == "jdbc" and e.get("sha256") == launcher.JDBC_JAR_SHA
                                                          for e in launcher.EVENTS), str(launcher.EVENTS[-1:]))

err, root, work, _ = case("tampered_zip", good, zip_sha="0" * 64)
check("1 tampered zip refused, nothing written, zip removed", err is not None and "zip sha256" in str(err)
      and lib_files(root) == [] and os.listdir(work) == [], f"{err} {lib_files(root)} {os.listdir(work)}")

err, root, work, _ = case("other_jar", make_zip([(PINNED[2], b"PK-other-jar")]))
check("2 other jar refused, nothing written", err is not None and "jar sha256" in str(err) and lib_files(root) == [],
      f"{err} {lib_files(root)}")

err, root, work, _ = case("no_entry", make_zip([("other/DatabricksJDBC42.jar", JAR)]))
check("3 missing entry refused, nothing written, zip removed", err is not None and "not in the JDBC zip" in str(err)
      and lib_files(root) == [] and os.listdir(work) == [], f"{err!r} {lib_files(root)}")

err, root, work, outside = case("traversal", make_zip([("../../outside/evil.jar", b"EVIL"), (PINNED[2], JAR)]))
base = os.path.dirname(root)
check("4 '../' entry: only the jar written, nothing outside", err is None and lib_files(root) == [launcher.JDBC_JAR]
      and tree(base) == sorted([os.path.join("webapi", "WEB-INF", "lib", launcher.JDBC_JAR)]), f"{err} {tree(base)}")

err, root, _, _ = case("dest_file", good, dest="file")
check("5a jar already there refused, old file kept", err is not None and "already" in str(err)
      and open(os.path.join(root, "WEB-INF", "lib", launcher.JDBC_JAR), "rb").read() == b"old", str(err))
err, root, _, outside = case("dest_link", good, dest="link")
check("5b symlink at the target refused, outside file unchanged", err is not None
      and open(os.path.join(outside, "victim.jar"), "rb").read() == b"victim", str(err))

err, root, _, _ = case("lib_missing", good, lib=None)
check("6a WEB-INF/lib missing refused", err is not None and "WEB-INF/lib" in str(err), str(err))
err, root, _, outside = case("lib_link", good, lib="link")
check("6b WEB-INF/lib symlink refused, nothing outside", err is not None and os.listdir(outside) == [],
      f"{err} {os.listdir(outside)}")

# 7: a refused driver stops main() before Java starts
STARTED = []
os.environ["APP_WORK"] = os.path.join(TMP, "main_work")
launcher.fetch_jre = lambda w: "/bin/false"
launcher.fetch_webapi = lambda w: os.path.join(TMP, "good", "webapi")
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
      src["dialect"] == "spark" and src["username"] == "token" and src["krbAuthMethod"] == "password"
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
