"""Offline test of ticket 02: ATLAS from the pinned image, served at /atlas behind the bridge's gate.

No network: launcher.fetch_pinned_image is replaced by a fake that writes an ATLAS tree, then the real fetch_atlas
and the real front server run on it. Hostile rows: the image's own config-local.js with sign-in OFF and a foreign
WebAPI host (it must never be served), a config-local.js that is a symlink to a file outside the tree, a symlink
inside the tree to a secret outside it, every encoding of '..', a request with no identity, a fake WebAPI that
counts any /atlas request it sees (none may reach it).
Usage: python3 -I tests/test_atlas.py   (needs bcrypt: pip install -r app/requirements.txt; exit 0 = pass)
"""
import http.client, http.server, json, os, re, shutil, socketserver, sys, tempfile, threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import bridge, launcher, server  # noqa: E402

SECRET = "s" * 20 + "-atlas-test-secret-0123456789"  # a test value, not a real secret
OUTSIDE = "OUTSIDE-SECRET-6f1c"  # text of a file outside the ATLAS tree: must never be in any answer
IMAGE_CONFIG = 'define([],function(){return {api:{url:"https://evil.example.com/WebAPI/"},userAuthenticationEnabled:false};});'
FAILS = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        FAILS.append(name)


TMP = tempfile.mkdtemp(prefix="atlas-test.")
WORK = os.path.join(TMP, "work")
os.makedirs(WORK)
with open(os.path.join(TMP, "secret.txt"), "w") as f:
    f.write(OUTSIDE)
CALLS = []


def fake_fetch(image_name, index_digest, path_prefix, target_folder, work, platform_arch=None):
    """Writes what the pinned ATLAS image holds, plus the hostile rows."""
    CALLS.append((image_name, index_digest, path_prefix))
    files = {"index.html": "<html>ATLAS-INDEX</html>", "js/main.js": "var atlasMain = 1;",
             "js/config-local.js": IMAGE_CONFIG, "css/app.css": "body{}", "images/logo.png": "PNG",
             "images/icon.svg": "<svg/>", "fonts/a.woff2": "W2", "js/x.json": "{}"}
    for rel, text in files.items():
        os.makedirs(os.path.join(target_folder, os.path.dirname(rel)), exist_ok=True)
        with open(os.path.join(target_folder, rel), "w") as f:
            f.write(text)
    os.symlink(os.path.join(TMP, "secret.txt"), os.path.join(target_folder, "images", "leak.png"))  # hostile
    return target_folder, len(files)


# --- launcher: fetch_atlas ---------------------------------------------------------------------------------------
real_fetch = launcher.fetch_pinned_image
launcher.fetch_pinned_image = fake_fetch
root = launcher.fetch_atlas(WORK)
check("L1 fetch_atlas returns the ATLAS folder", root == os.path.join(WORK, "atlas"), root)
check("L2 fetch_atlas pins image, digest and prefix",
      CALLS == [("ohdsi/atlas", launcher.ATLAS_INDEX, "usr/share/nginx/html/atlas/")]
      and re.fullmatch(r"sha256:[0-9a-f]{64}", launcher.ATLAS_INDEX or "") is not None, CALLS)
cfg = open(os.path.join(root, "js", "config-local.js")).read() if root else ""
check("L3 the generated config replaces the image's own", cfg == launcher.ATLAS_CONFIG and "evil" not in cfg, cfg[:80])
check("L4 generated config: sign-in on, no login providers, terms off",
      "userAuthenticationEnabled: true" in cfg and "authProviders: []" in cfg and "enableTermsAndConditions: false" in cfg)
check("L5 generated config: WebAPI on the app's own address only",
      'window.location.origin + "/WebAPI/"' in cfg and not re.search(r"https?://", cfg), cfg)
check("L6 an atlas event is logged", any(e["event"] == "atlas" for e in launcher.EVENTS))

# hostile: the image's config-local.js is a symlink to a file outside the tree; the write must not go through it
target = os.path.join(TMP, "outside-config.js")
with open(target, "w") as f:
    f.write("OUTSIDE-CONFIG")
os.remove(os.path.join(root, "js", "config-local.js"))
os.symlink(target, os.path.join(root, "js", "config-local.js"))
launcher.write_atlas_config(root)
check("L7 config write replaces a symlink, never writes through it",
      open(target).read() == "OUTSIDE-CONFIG" and not os.path.islink(os.path.join(root, "js", "config-local.js"))
      and open(os.path.join(root, "js", "config-local.js")).read() == launcher.ATLAS_CONFIG)


def failing(*a, **k):
    raise RuntimeError("layer digest mismatch: want sha256:aa, got sha256:bb")


launcher.fetch_pinned_image = failing
n0 = len(launcher.EVENTS)
check("L8 a failed ATLAS fetch returns None", launcher.fetch_atlas(os.path.join(TMP, "work2")) is None)
err = [e for e in launcher.EVENTS[n0:] if e["event"] == "atlas_error"]
check("L9 a failed ATLAS fetch logs atlas_error with the reason", bool(err) and "digest mismatch" in err[0].get("error", ""), err)


def no_index(image_name, index_digest, path_prefix, target_folder, work, platform_arch=None):
    os.makedirs(os.path.join(target_folder, "js"), exist_ok=True)
    return target_folder, 0


launcher.fetch_pinned_image = no_index
check("L10 an image without index.html gives None", launcher.fetch_atlas(os.path.join(TMP, "work3")) is None)
launcher.fetch_pinned_image = real_fetch


# --- front server: /atlas ----------------------------------------------------------------------------------------
class Seen:
    paths = []


class FakeWebAPI(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _any(self):
        Seen.paths.append(self.path)
        b = b'{"fake":"webapi"}'
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    do_GET = do_POST = _any


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def serve(handler):
    srv = TS(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


java_port = serve(FakeWebAPI)
server.JAVA_PORT = java_port
server.BRIDGE = bridge.Bridge(java_port, SECRET)
server.ATLAS_ROOT = root
front = serve(server.Handler)
OWNER = "owner@example.com"


def get(path, ident=OWNER, method="GET"):
    c = http.client.HTTPConnection("127.0.0.1", front, timeout=10)
    h = {"X-Forwarded-Email": ident} if ident else {}
    c.putrequest(method, path, skip_host=False, skip_accept_encoding=True)  # send the path exactly as written
    for k, v in h.items():
        c.putheader(k, v)
    c.endheaders()
    r = c.getresponse(); body = r.read(); c.close()
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), body


st, h, b = get("/atlas/")
check("S1 /atlas/ with an identity: the ATLAS page", st == 200 and b == b"<html>ATLAS-INDEX</html>"
      and h.get("content-type", "").startswith("text/html"), (st, b[:60]))
st, h, b = get("/atlas")
check("S2 /atlas redirects to /atlas/", st in (301, 302) and h.get("location") == "/atlas/", (st, h.get("location")))
for p in ("/atlas/", "/atlas/js/main.js", "/atlas/js/config-local.js"):
    st, h, b = get(p, ident=None)
    check(f"S3 no identity -> 401: {p}", st == 401 and b"ATLAS" not in b and b"atlasMain" not in b, (st, b[:60]))
st, h, b = get("/atlas/", ident="not-an-identity")
check("S4 a malformed identity -> 401", st == 401, st)
for p in ("/atlas/../launcher.py", "/atlas/%2e%2e/secret.txt", "/atlas/js/..%2F..%2Fsecret.txt", "/atlas//etc/passwd",
          "/atlas/js\\..\\secret.txt", "/atlas/%252e%252e/secret.txt", "/atlas/./index.html", "/atlas/js/%2E%2E/%2E%2E/secret.txt"):
    st, h, b = get(p)
    check(f"S5 ambiguous path -> 400: {p}", st == 400 and OUTSIDE.encode() not in b, (st, b[:60]))
st, h, b = get("/atlas/images/leak.png")
check("S6 a symlink inside the tree to a file outside -> 404", st == 404 and OUTSIDE.encode() not in b, (st, b[:60]))
st, h, b = get("/atlas/js/config-local.js")
check("S7 /atlas/js/config-local.js is the generated config", st == 200 and b.decode() == launcher.ATLAS_CONFIG
      and h.get("content-type", "").startswith("application/javascript"), (st, b[:80]))
check("S7b config-local.js is not cached", "no-cache" in h.get("cache-control", ""), h.get("cache-control"))
for p, ct in (("/atlas/js/main.js", "application/javascript"), ("/atlas/css/app.css", "text/css"),
              ("/atlas/images/logo.png", "image/png"), ("/atlas/images/icon.svg", "image/svg+xml"),
              ("/atlas/fonts/a.woff2", "font/woff2"), ("/atlas/js/x.json", "application/json")):
    st, h, b = get(p)
    check(f"S8 content type {ct}: {p}", st == 200 and h.get("content-type", "").startswith(ct)
          and h.get("x-content-type-options") == "nosniff", (st, h.get("content-type")))
st, h, b = get("/atlas/js/main.js?v=2")
check("S9 a query string still serves the file", st == 200 and b == b"var atlasMain = 1;", st)
st, h, b = get("/atlas/nope.js")
check("S10 a missing file -> 404", st == 404, st)
st, h, b = get("/atlas/js/")
check("S11 a folder without index.html -> 404", st == 404, st)
check("S12 no /atlas request ever reached WebAPI", not [p for p in Seen.paths if "atlas" in p.lower()], Seen.paths)

server.ATLAS_ROOT = None
launcher.EVENTS.append({"event": "atlas_error", "error": "RuntimeError: layer digest mismatch"})
server.STATE["launcher"] = launcher.EVENTS
st, h, b = get("/atlas/")
check("S13 ATLAS not fetched -> 503 with the reason", st == 503 and b"digest mismatch" in b, (st, b[:80]))
st, h, b = get("/atlas/", ident=None)
check("S14 ATLAS not fetched, no identity -> 401 (the gate comes first)", st == 401, st)
st, h, b = get("/WebAPI/info")
check("S15 WebAPI still answers while ATLAS is missing", st == 200 and b'"fake"' in b, (st, b[:60]))

shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{'ALL PASS' if not FAILS else str(len(FAILS)) + ' FAIL'}")
sys.exit(1 if FAILS else 0)
