"""Front server and load runner, inside the WebAPI app.

WebAPI listens on 127.0.0.1:JAVA_PORT. This server owns DATABRICKS_APP_PORT:
  /WebAPI/...      forwarded to WebAPI (with APP_BRIDGE=on: as the user the Apps proxy signed in, see bridge.py)
  /atlas/...       ATLAS's static files from the launcher's ATLAS folder (GET only; same gate as /WebAPI; 503 if
                   the launcher could not fetch ATLAS). Paths resolve inside that folder only; symlinks out give 404.
  /ops/status      WebAPI pid, RSS, uptime, JVM heap after the last GC, cold-path samples and cold_done, runs so far,
                   and the launcher's start-up events (token, PgBouncer listening, Java start) in order
  /ops/run?label=&levels=1,8,32&warmup=30&seconds=180   start one load run in the background (one at a time)
  /ops/results?label=   every sample of that run, as JSON
  PgBouncer mode (APP_DB=pgbouncer):
  /ops/conn[?full=1]    PgBouncer and refresher status, ticker and sampler results (no secrets)
  POST /ops/rotate      force a token rotation now
  POST /ops/terminate   the SP ends its own Lakebase sessions except the sampler's
  /ops/run also takes rotate=1 (one forced rotation in the middle of each level's measured phase)
  and terminate_at=<s> (end the sessions <s> seconds into the first level)

The load runner talks to WebAPI on 127.0.0.1 (the REST layer, no Apps proxy), from the same container.
A user loops the click path: search -> open the top concept -> its ancestors and descendants, on source SOURCE_KEY.
(ancestorAndDescendant: WebAPI's per-source role grants it; that role has no right for /concept/{id}/descendants.)
Each request is one sample: level, user, step, query index, start time, ms, HTTP status, bytes. No query text is
kept in a sample. Queries come from queries.json (you write it; staged with the app, never in the repo); the top
concept id is read from the first 2 KB of the search body, so the client does not parse multi-MB JSON under load.
Without queries.json the cold paths are skipped and /ops/run answers 404; everything else works.

APP_BRIDGE=on: WebAPI security is on and every request passes bridge.py's gate. /ops/* answers only the identities
in OPS_ADMINS (404 for the rest), and the controls (/ops/run, /ops/rotate, /ops/terminate) also need OPS_CONTROL=on.
The load runner and the ticker log in to WebAPI as bridge.INTERNAL_ID.
"""
import http.client, http.server, json, os, re, socketserver, threading, time, urllib.parse

import bridge

JAVA_PORT = int(os.environ.get("APP_JAVA_PORT", "8081"))
SOURCE_KEY = os.environ.get("SOURCE_KEY", "VOCAB")
HERE = os.path.dirname(os.path.abspath(__file__))
STATE = {"started": time.time(), "java_pid": None, "gc_log": None, "cold": [], "runs": {}, "running": None,
         "pgb": None, "mon": None}
LOCK = threading.Lock()
CONCEPT_ID = re.compile(rb'"CONCEPT_ID"\s*:\s*(\d+)')
BRIDGE = None  # bridge.Bridge when APP_BRIDGE=on
CONTROLS = {"/ops/run", "/ops/rotate", "/ops/terminate"}
ATLAS_ROOT = None  # the launcher's ATLAS folder, or None when the fetch failed
ATLAS_TYPES = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
               ".css": "text/css; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml",
               ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
               ".ico": "image/x-icon", ".webp": "image/webp", ".woff": "font/woff", ".woff2": "font/woff2",
               ".ttf": "font/ttf", ".eot": "application/vnd.ms-fontobject", ".xml": "application/xml",
               ".map": "application/json", ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8"}
NO_CACHE = {"index.html", "js/config-local.js"}
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization", "proxy-authenticate"}


def queries():
    """The query list, or None when queries.json was not staged (the load runner is optional)."""
    path = os.path.join(HERE, "queries.json")
    if not os.path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)  # list of URL-encoded query strings, in a fixed order


def timed_get(conn, path):
    t0 = time.perf_counter()
    for attempt in (0, 1):
        hdrs = {}
        if BRIDGE:
            tok = BRIDGE.token(bridge.INTERNAL_ID)
            hdrs["Authorization"] = f"Bearer {tok}"
        conn.request("GET", path, headers=hdrs)
        r = conn.getresponse()
        body = r.read()
        if not (BRIDGE and r.status == 401 and not attempt):
            break
        BRIDGE.drop(bridge.INTERNAL_ID, tok)  # one fresh login, then the request again (inside the timed sample)
    return round((time.perf_counter() - t0) * 1000, 2), r.status, body


def click_path(conn, qi, q, record):
    """One click path; record(step, qi, t_start, ms, status, nbytes) per request."""
    t = time.time(); ms, st, body = timed_get(conn, f"/WebAPI/vocabulary/{SOURCE_KEY}/search?query={q}")
    record("search", qi, t, ms, st, len(body))
    m = CONCEPT_ID.search(body[:2048])
    if st != 200 or not m:
        return
    cid = int(m.group(1))
    for step, path in (("concept", f"/WebAPI/vocabulary/{SOURCE_KEY}/concept/{cid}"),
                       ("ancestorAndDescendant", f"/WebAPI/vocabulary/{SOURCE_KEY}/concept/{cid}/ancestorAndDescendant")):
        t = time.time(); ms, st, body = timed_get(conn, path)
        record(step, qi, t, ms, st, len(body))


def new_conn():
    return http.client.HTTPConnection("127.0.0.1", JAVA_PORT, timeout=120)


def cold_paths(n=3):
    """Right after WebAPI first answers: n click paths, one at a time, before any load. Kept as 'cold'."""
    qs = queries()
    if qs is None:
        STATE["cold"].append({"note": "no queries.json; cold paths skipped"})
        return
    conn = new_conn()
    for qi in range(n):
        click_path(conn, qi, qs[qi], lambda *s: STATE["cold"].append(dict(zip(("step", "qi", "t", "ms", "status", "bytes"), s))))
    conn.close()


def _after(delay, fn, note, run):
    """Call fn after delay seconds; keep its time and result in the run (no secrets)."""
    def go():
        time.sleep(delay)
        try:
            res = fn()
        except Exception as e:
            res = f"error {type(e).__name__}"
        run.setdefault("actions", []).append({"t": round(time.time(), 3), "action": note, "result": res})
    threading.Thread(target=go, daemon=True).start()


def load_run(label, levels, warmup, seconds, rotate=False, terminate_at=None):
    qs = queries()
    samples, errors = [], []
    run = {"label": label, "levels": levels, "warmup_s": warmup, "measure_s": seconds, "t0": time.time(),
           "heap_before": heap(), "rss_before_kb": rss_kb(), "samples": samples, "errors": errors}
    with LOCK:
        STATE["runs"][label] = run
    for n_level, level in enumerate(levels):
        t_start = time.time()
        stop_at = t_start + warmup + seconds
        lk = threading.Lock()
        if rotate and STATE["pgb"]:
            _after(warmup + seconds / 2, lambda: STATE["pgb"].rotate("forced_load"), f"rotate level {level}", run)
        if terminate_at is not None and n_level == 0 and STATE["mon"]:
            _after(terminate_at, STATE["mon"].terminate, f"terminate level {level}", run)

        def user(u):
            conn = new_conn(); i = u * 997  # each user starts at a different query, same fixed list
            while time.time() < stop_at:
                qi = i % len(qs); i += 1
                phase = "warmup" if time.time() < t_start + warmup else "measure"
                try:
                    click_path(conn, qi, qs[qi], lambda step, q, t, ms, st, nb: samples.append(  # list.append is atomic
                        {"level": level, "user": u, "phase": phase, "step": step, "qi": q, "t": round(t, 3),
                         "ms": ms, "status": st, "bytes": nb}))
                except Exception as e:  # keep every failure; reconnect and go on
                    with lk:
                        errors.append({"level": level, "user": u, "qi": qi, "t": round(time.time(), 3), "error": f"{type(e).__name__}: {e}"})
                    conn.close(); conn = new_conn()
            conn.close()

        threads = [threading.Thread(target=user, args=(u,), daemon=True) for u in range(level)]
        [t.start() for t in threads]; [t.join() for t in threads]
        run.setdefault("level_heap", {})[level] = heap()
    run["heap_after"], run["rss_after_kb"], run["t1"] = heap(), rss_kb(), time.time()
    with LOCK:
        STATE["running"] = None


def rss_kb():
    pid = STATE["java_pid"]
    try:
        return int(next(l.split()[1] for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")))
    except Exception:
        return None


def heap():
    """Last line of the JVM GC log that shows heap before->after(total)."""
    try:
        lines = [l for l in open(STATE["gc_log"]) if "->" in l]
        return lines[-1].strip()[-160:] if lines else None
    except Exception:
        return None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def _admins(self):
        return {a.strip().lower() for a in os.environ.get("OPS_ADMINS", "").split(",") if a.strip()}

    def _gate(self, path):
        """True when the request may go on; otherwise the error is already sent."""
        if not BRIDGE:
            return True
        if path is None:
            self._json(400, {"error": "ambiguous path"}); return False
        ident = bridge.identity(self.headers)
        if path == "/ops" or path.startswith("/ops/"):
            ok = ident is not None and ident in self._admins()
            if ok and path in CONTROLS:
                ok = os.environ.get("OPS_CONTROL", "off") == "on"
            if not ok:
                self._json(404, {"error": "not found"}); return False
            return True
        if bridge.blocked(path):
            self._json(403, {"error": "sign-in goes through the workspace"}); return False
        if ident is None:
            self._json(401, {"error": "no workspace identity"}); return False
        return True

    def _forward(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        if BRIDGE:
            if not self._gate(bridge.normalize_path(self.path)):
                return
            try:
                st, hdrs, data = BRIDGE.request(self.command, self.path, body,
                                                {k: v for k, v in self.headers.items() if k.lower() not in HOP | {"host"}},
                                                bridge.identity(self.headers))
            except PermissionError:
                return self._json(502, {"error": "WebAPI login refused"})
            except Exception as e:
                return self._json(502, {"error": f"WebAPI not reachable: {type(e).__name__}"})
            self.send_response(st)
            for k, v in hdrs:
                if k.lower() not in HOP | {"content-length"}:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
            return
        conn = new_conn()
        try:
            conn.request(self.command, self.path, body, {k: v for k, v in self.headers.items() if k.lower() not in HOP | {"host"}})
            r = conn.getresponse(); data = r.read()
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in HOP | {"content-length"}:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
        except Exception as e:
            self._json(502, {"error": f"WebAPI not reachable: {type(e).__name__}"})
        finally:
            conn.close()

    def _atlas(self, raw_path):
        """One ATLAS file. The gate runs first (400 ambiguous, 401 no identity), then the file must resolve inside
        ATLAS_ROOT after symlinks are followed."""
        path = bridge.normalize_path(self.path)
        if not self._gate(path):
            return
        if ATLAS_ROOT is None:
            err = next((e.get("error") for e in reversed(STATE.get("launcher") or []) if e.get("event") == "atlas_error"), None)
            return self._json(503, {"error": "ATLAS is not available", "reason": err})
        if raw_path == "/atlas":
            self.send_response(302); self.send_header("Location", "/atlas/"); self.send_header("Content-Length", "0")
            self.end_headers(); return
        rel = path[len("/atlas/"):] or "index.html"
        top = os.path.realpath(ATLAS_ROOT)
        full = os.path.realpath(os.path.join(top, rel))
        if not full.startswith(top + os.sep) or not os.path.isfile(full):
            return self._json(404, {"error": "not found"})
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ATLAS_TYPES.get(os.path.splitext(full)[1].lower(), "application/octet-stream"))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-cache" if rel in NO_CACHE else "max-age=3600")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path); qs = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/atlas" or u.path.startswith("/atlas/"):
            return self._atlas(u.path)
        if BRIDGE and u.path.startswith("/ops") and not self._gate(bridge.normalize_path(self.path)):
            return
        if u.path == "/ops/status":
            with LOCK:
                runs = {k: {x: v[x] for x in v if x not in ("samples", "errors")} | {"n_samples": len(v["samples"]), "n_errors": len(v["errors"])}
                        for k, v in STATE["runs"].items()}
            return self._json(200, {"uptime_s": round(time.time() - STATE["started"], 1), "java_pid": STATE["java_pid"],
                                    "webapi_ready_s": STATE.get("webapi_ready_s"), "rss_kb": rss_kb(), "heap": heap(), "cold": STATE["cold"],
                                    "cold_done": STATE.get("cold_done", False), "launcher": STATE.get("launcher", []),
                                    "running": STATE["running"], "runs": runs,
                                    "bridge": BRIDGE.status() if BRIDGE else None})
        if u.path == "/ops/run":
            if queries() is None:
                return self._json(404, {"error": "no queries.json staged with the app"})
            label = qs.get("label") or f"run{len(STATE['runs']) + 1}"
            with LOCK:
                if STATE["running"] or label in STATE["runs"]:
                    return self._json(409, {"error": "a run is active or the label is used", "running": STATE["running"]})
                STATE["running"] = label
            levels = [int(x) for x in qs.get("levels", "1,8,32").split(",")]
            ta = qs.get("terminate_at")
            threading.Thread(target=load_run, args=(label, levels, int(qs.get("warmup", 30)), int(qs.get("seconds", 180)),
                                                    qs.get("rotate") == "1", int(ta) if ta else None), daemon=True).start()
            return self._json(202, {"started": label, "levels": levels})
        if u.path == "/ops/results":
            run = STATE["runs"].get(qs.get("label", ""))
            return self._json(200, run) if run else self._json(404, {"error": "no such run"})
        if u.path == "/ops/conn":
            if not STATE["pgb"]:
                return self._json(404, {"error": "not in pgbouncer mode"})
            return self._json(200, {"pgb": STATE["pgb"].status(), "mon": STATE["mon"].status(full=qs.get("full") == "1")})
        return self._forward()

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if BRIDGE and u.path.startswith("/ops") and not self._gate(bridge.normalize_path(self.path)):
            return
        if u.path == "/ops/rotate" and STATE["pgb"]:
            return self._json(200, {"rotated": STATE["pgb"].rotate("forced")})
        if u.path == "/ops/terminate" and STATE["mon"]:
            return self._json(200, {"ended": STATE["mon"].terminate()})
        return self._forward()

    do_PUT = do_DELETE = _forward


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def serve(java_proc, gc_log, pgb=None, mon=None, events=None, bridge_=None, atlas_root=None):
    global BRIDGE, ATLAS_ROOT
    BRIDGE, ATLAS_ROOT = bridge_, atlas_root
    STATE["java_pid"], STATE["gc_log"], STATE["pgb"], STATE["mon"] = java_proc.pid, gc_log, pgb, mon
    STATE["launcher"] = events if events is not None else []

    def wait_then_cold():
        while java_proc.poll() is None:
            try:
                c = new_conn(); c.request("GET", "/WebAPI/info"); r = c.getresponse(); r.read(); c.close()
                ok = r.status == 200
                if ok and BRIDGE:
                    BRIDGE.token(bridge.INTERNAL_ID)  # the first login; a refusal is kept in /ops/status bridge
                if ok:
                    STATE["webapi_ready_s"] = round(time.time() - STATE["started"], 1)
                    print(json.dumps({"event": "webapi_ready", "seconds": STATE["webapi_ready_s"]}), flush=True)
                    cold_paths()
                    STATE["cold_done"] = True
                    print(json.dumps({"event": "cold_done", "samples": STATE["cold"]}), flush=True)
                    return
            except OSError:
                pass
            time.sleep(1)

    threading.Thread(target=wait_then_cold, daemon=True).start()
    Server(("0.0.0.0", int(os.environ.get("DATABRICKS_APP_PORT", "8000"))), Handler).serve_forever()
