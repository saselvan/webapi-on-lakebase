"""Offline tests of the app: no Databricks, no Lakebase, no Java.

1. The launcher keeps its start-up events in order and never keeps the command line.
2. The front server returns them on /ops/status with cold_done.
3. Without queries.json: /ops/run answers 404, the cold paths record a note, and the server keeps answering.
4. The launcher's PgBouncer check refuses an unset and a wrong PGB_SHA256 before anything starts.
Usage: python3 -I tests/test_app.py   (exit 0 = pass)
"""
import hashlib, json, os, shutil, socket, sys, tempfile, threading, time, types, urllib.error, urllib.request

APP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app")
TMP = tempfile.mkdtemp(prefix="webapi-app-test.")
for f in ("launcher.py", "server.py", "pgb.py", "monitors.py", "bridge.py"):  # a copy, so the test never writes into the repo
    shutil.copy(os.path.join(APP, f), TMP)
sys.path.insert(0, TMP)
import launcher, server  # noqa: E402

# 1. Launcher events kept in order, the command line never kept
launcher.log("pgb", pgb="token", why="start", length=2250)
launcher.log("pgb", pgb="listening", pid=76)
launcher.log("start", cmd=["java", "-Dsecret=x"])
kinds = [(e["event"], e.get("pgb")) for e in launcher.EVENTS]
assert kinds == [("pgb", "token"), ("pgb", "listening"), ("start", None)], kinds
assert all("cmd" not in e for e in launcher.EVENTS), "cmd kept in EVENTS"


# 2. Front server on a free port, with a fake Java process
class FakeJava:
    pid = 4242

    def poll(self):
        return None


s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
os.environ["DATABRICKS_APP_PORT"] = str(port)
server.JAVA_PORT = 9  # nothing listens: the cold-path waiter keeps waiting, as before WebAPI is up
threading.Thread(target=server.serve, args=(FakeJava(), "/nonexistent"), kwargs={"events": launcher.EVENTS},
                 daemon=True).start()


def get(path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


for _ in range(50):
    try:
        code, st = get("/ops/status")
        break
    except OSError:
        time.sleep(0.1)
else:
    sys.exit("front server did not answer")
assert code == 200
assert [(e["event"], e.get("pgb")) for e in st["launcher"]] == kinds, st["launcher"]
assert st["cold_done"] is False and st["java_pid"] == 4242
server.STATE["cold_done"] = True
assert get("/ops/status")[1]["cold_done"] is True
print("PASS: launcher events in order, no cmd, served by /ops/status with cold_done")

# 3. No queries.json staged next to server.py
assert not os.path.exists(os.path.join(TMP, "queries.json"))
code, body = get("/ops/run?label=x")
assert code == 404 and "queries.json" in body["error"], (code, body)
assert server.STATE["running"] is None and "x" not in server.STATE["runs"], "a run started without queries"
server.cold_paths()
assert server.STATE["cold"] == [{"note": "no queries.json; cold paths skipped"}], server.STATE["cold"]
assert get("/ops/status")[0] == 200
print("PASS: no queries.json -> /ops/run 404, cold paths skipped with a note, server still answers")

# 4. PgBouncer binary check, before any token or process
sys.modules["databricks"] = types.ModuleType("databricks")
sys.modules["databricks.sdk"] = types.SimpleNamespace(WorkspaceClient=lambda: (_ for _ in ()).throw(
    AssertionError("reached the token step")))
with open(os.path.join(TMP, launcher.PGB_BINARY), "wb") as f:
    f.write(b"not really pgbouncer")
good = hashlib.sha256(b"not really pgbouncer").hexdigest()
work = os.path.join(TMP, "work"); os.makedirs(work)
for value, want in ((None, "not set"), ("0" * 64, "mismatch")):
    os.environ.pop("PGB_SHA256", None)
    if value:
        os.environ["PGB_SHA256"] = value
    try:
        launcher.start_pgbouncer(work)
        sys.exit(f"start_pgbouncer accepted PGB_SHA256={value!r}")
    except RuntimeError as e:
        assert want in str(e), e
os.environ["PGB_SHA256"] = good
try:
    launcher.start_pgbouncer(work)
    sys.exit("the right hash did not reach the token step")
except AssertionError as e:
    assert "token step" in str(e)
print("PASS: PgBouncer check refuses an unset and a wrong PGB_SHA256; the right one goes on")
shutil.rmtree(TMP, ignore_errors=True)
print("PASS: tests/test_app.py")
