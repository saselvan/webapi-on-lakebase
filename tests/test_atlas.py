"""Offline test of ticket 02: ATLAS from the pinned image, served at /atlas behind the bridge's gate.

No network: the real artifacts.fetch runs against a fake registry (a transport fake and a test pin, because a fake
cannot match the real digest) that serves an ATLAS tree; the real fetch_atlas and the real front server run on it. Hostile rows: the image's own config-local.js with sign-in OFF and a foreign
WebAPI host (it must never be served), a config-local.js that is a symlink to a file outside the tree, a symlink
inside the tree to a secret outside it, every encoding of '..', a request with no identity, a fake WebAPI that
counts any /atlas request it sees (none may reach it).
Usage: python3 -I tests/test_atlas.py   (needs bcrypt: pip install -r app/requirements.txt; exit 0 = pass)
"""
import hashlib, http.client, http.server, io, json, os, re, shutil, socketserver, sys, tarfile, tempfile, threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import artifacts, bridge, launcher, server  # noqa: E402

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
PREFIX = "usr/share/nginx/html/atlas/"
ATLAS_FILES = {"index.html": "<html>ATLAS-INDEX</html>", "js/main.js": "var atlasMain = 1;",
               "js/config-local.js": IMAGE_CONFIG, "css/app.css": "body{}", "images/logo.png": "PNG",
               "images/icon.svg": "<svg/>", "fonts/a.woff2": "W2", "js/x.json": "{}"}


class Resp:
    def __init__(self, status, body=b"", location=None):
        self.status, self.location, self._b = status, location, io.BytesIO(body)

    def read(self, n=-1):
        return self._b.read(n)

    def close(self):
        pass


def registry(files, tamper=False):
    """A fake Docker Hub holding one image: files under PREFIX, plus a symlink to the outside secret (hostile).
    Returns (transport, pin)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for rel, text in files.items():
            ti = tarfile.TarInfo(PREFIX + rel)
            ti.size = len(text.encode())
            t.addfile(ti, io.BytesIO(text.encode()))
        ti = tarfile.TarInfo(PREFIX + "images/leak.png")
        ti.type, ti.linkname = tarfile.SYMTYPE, os.path.join(TMP, "secret.txt")
        t.addfile(ti)
    layer = buf.getvalue()
    ld = "sha256:" + hashlib.sha256(layer).hexdigest()
    manifest = json.dumps({"layers": [{"digest": ld}]}).encode()
    md = "sha256:" + hashlib.sha256(manifest).hexdigest()
    index = json.dumps({"manifests": [{"digest": md, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                       "platform": {"os": "linux", "architecture": "amd64"}}]}).encode()
    idd = "sha256:" + hashlib.sha256(index).hexdigest()
    reg = "https://registry-1.docker.io/v2/test/atlas"
    routes = {"https://auth.docker.io/token?service=registry.docker.io&scope=repository:test/atlas:pull":
              Resp(200, b'{"token": "t"}'), f"{reg}/manifests/{idd}": Resp(200, index),
              f"{reg}/manifests/{md}": Resp(200, manifest), f"{reg}/blobs/{ld}": Resp(200, layer + (b"X" if tamper else b""))}
    pin = {"kind": "image", "repo": "test/atlas", "index": idd, "prefix": PREFIX, "hosts": ("auth.docker.io", "registry-1.docker.io")}
    return (lambda url, headers: routes.get(url, Resp(404))), pin


real_fetch = artifacts.fetch


def fresh(name):
    os.makedirs(os.path.join(TMP, name))
    return os.path.join(TMP, name)


def use(files, tamper=False):
    transport, pin = registry(files, tamper)

    def fake(name, dest, **kw):
        CALLS.append(name)
        return real_fetch(name, dest, transport=transport, pins={name: pin}, **kw)
    launcher.artifacts.fetch = fake


# --- launcher: fetch_atlas ---------------------------------------------------------------------------------------
os.environ["APP_ARCH"] = "amd64"
use(ATLAS_FILES)
n0 = len(launcher.EVENTS)
root = launcher.fetch_atlas(WORK)
check("L1 fetch_atlas returns the ATLAS folder", root == os.path.join(WORK, "atlas"), root)
pin = artifacts.PINS["atlas"]
check("L2 fetch_atlas fetches the atlas pin: image, digest and prefix",
      CALLS == ["atlas"] and (pin["kind"], pin["repo"], pin["prefix"]) == ("image", "ohdsi/atlas", PREFIX)
      and re.fullmatch(r"sha256:[0-9a-f]{64}", pin["index"]) is not None, CALLS)
cfg = open(os.path.join(root, "js", "config-local.js")).read() if root else ""
check("L3 the generated config replaces the image's own", cfg == launcher.ATLAS_CONFIG and "evil" not in cfg, cfg[:80])
check("L4 generated config: sign-in on, no login providers, terms off",
      "userAuthenticationEnabled: true" in cfg and "authProviders: []" in cfg and "enableTermsAndConditions: false" in cfg)
check("L5 generated config: WebAPI on the app's own address only",
      'window.location.origin + "/WebAPI/"' in cfg and not re.search(r"https?://", cfg), cfg)
check("L6 an atlas event is logged", any(e["event"] == "atlas" for e in launcher.EVENTS))
check("L6b the image's symlink is skipped and logged", root is not None
      and not os.path.lexists(os.path.join(root, "images", "leak.png"))
      and any(e["event"] == "link_skipped" and e.get("path") == "images/leak.png" for e in launcher.EVENTS[n0:]))
os.symlink(os.path.join(TMP, "secret.txt"), os.path.join(root, "images", "leak.png"))  # hostile, for the server checks

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

use(ATLAS_FILES, tamper=True)
n0 = len(launcher.EVENTS)
check("L8 a failed ATLAS fetch returns None", launcher.fetch_atlas(fresh("work2")) is None)
err = [e for e in launcher.EVENTS[n0:] if e["event"] == "atlas_error"]
check("L9 a failed ATLAS fetch logs atlas_error with the reason", bool(err) and "digest mismatch" in err[0].get("error", ""), err)

use({"js/main.js": "var atlasMain = 1;"})
n0 = len(launcher.EVENTS)
check("L10 an image without index.html gives None", launcher.fetch_atlas(fresh("work3")) is None
      and any("index.html" in e.get("error", "") for e in launcher.EVENTS[n0:] if e["event"] == "atlas_error"))
launcher.artifacts.fetch = real_fetch


# --- front server: /atlas ----------------------------------------------------------------------------------------
class Seen:
    paths = []


class FakeWebAPI(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _any(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        Seen.paths.append(self.path)
        b = b'{"fake":"webapi"}'
        self.send_response(200)
        if self.path == "/WebAPI/user/login/db":
            self.send_header("Bearer", "tok-1")  # the bridge's DB login; WebAPI sends the token in this header
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

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
