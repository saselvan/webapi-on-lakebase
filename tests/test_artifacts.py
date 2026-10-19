"""Offline tests of app/artifacts.py: every pinned artifact is fetched through fetch(name, dest, *, transport, log, pins).

**What this protects:** the files the app runs. Every byte is checked against a digest in the code before it is
written; files land only under dest and never through a symlink; the registry token never goes to a redirect host;
every host contacted is logged, and the README names every known host.

No network: a fake transport answers each URL from a table (status, redirect location, body). The tests give their own
pin table (pins=...), because a fake can never match the real digests. Checks P1-P4 read the real PINS.

**Attacker list.** Old test (removed with this file's commit) -> check here:
  test_image_fetch 0 wrong index digest -> I1 · 1 baseline -> I2 · 2, 14 `../` entry -> I3 · 3 absolute entry -> I4
  · 4 tampered layer -> I5 · 5 tampered manifest -> I6 · 6 only another platform -> I7 · 7 leading ./ -> I8
  · 8 symlink to outside -> I9 · 9 whiteout escape -> I10 · 10 entry outside the prefix -> I11 · 11 any prefix -> I12
  · 12 two platforms, amd64 not first -> I13 · 13 prefix//../ -> I14 · 15 double slash (absolute rel) -> I15
  · 16 whiteout `.wh...` -> I16 · 17 sibling folder, same name length -> I11 · (docstring 10) entry without
  platform -> I18
  test_cdm_source 1 tampered zip -> Z1 · 2 other jar -> Z2 · 3 no entry -> Z3 · 4 zip `../` entry -> Z4
  · 5a jar already there -> Z5 · 5b symlink at the target -> Z6 · 6a parent folder missing -> Z7
  · 6b dest is a symlink -> Z8 · good zip -> Z0 · 8 pinned values -> P1-P4
New: J1-J4 the JRE tarball (path checks it never had, links skipped and logged) · R1-R6 redirects, hosts and HTTP
errors · L1-L3 layer replace and whiteout of this fetch's own files, FIFO refused · D1 README names every known host.

Usage: python3 -I tests/test_artifacts.py   (exit 0 = pass)
"""
import glob, hashlib, io, json, os, shutil, sys, tarfile, tempfile, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix="artifacts-test.")
shutil.copy(os.path.join(REPO, "app", "artifacts.py"), TMP)  # a copy, so the test never writes into the repo
sys.path.insert(0, TMP)
import artifacts  # noqa: E402

FAILS = []
os.environ["APP_ARCH"] = "amd64"


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        FAILS.append(name)


def sha(data):
    return hashlib.sha256(data).hexdigest()


# ---- fake network --------------------------------------------------------------------------------------------------
class Resp:
    def __init__(self, status, body=b"", location=None):
        self.status, self.location, self._b = status, location, io.BytesIO(body)

    def read(self, n=-1):
        return self._b.read(n)

    def close(self):
        pass


class Net:
    """URL -> Resp (or a function that returns one). Keeps every (url, headers) it was asked for."""
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        r = self.routes.get(url)
        return Resp(404) if r is None else (r() if callable(r) else r)


class Log:
    def __init__(self):
        self.events = []

    def __call__(self, event, **kw):
        self.events.append({"event": event, **kw})

    def of(self, event):
        return [e for e in self.events if e["event"] == event]


def tar_bytes(entries):
    """entries: (name, bytes) for a file, (name, ("sym", target)) / ("hard", target) / ("fifo",) / ("dir",)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, body in entries:
            ti = tarfile.TarInfo(name)
            if isinstance(body, tuple):
                ti.type = {"sym": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE,
                           "dir": tarfile.DIRTYPE}[body[0]]
                if body[0] in ("sym", "hard"):
                    ti.linkname = body[1]
                if body[0] == "dir":
                    ti.mode = 0o755
                t.addfile(ti)
            else:
                ti.size, ti.mode = len(body), 0o755 if name.endswith("/java") else 0o644
                t.addfile(ti, io.BytesIO(body))
    return buf.getvalue()


REG = "https://registry-1.docker.io/v2/test/image"
CDN = "https://cdn.example.test/blob/"
TOKEN_URL = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:test/image:pull"
IMAGE_HOSTS = ("auth.docker.io", "registry-1.docker.io", "cdn.example.test")
PREFIX = "var/lib/ohdsi/webapi/"


def image(layers, platforms=("amd64",), tamper_layer=False, tamper_manifest=False, index_digest=None,
          cdn=CDN, no_platform_entry=False):
    """Routes for a fake registry: index -> per-platform manifest -> layers (each blob redirects to the CDN).
    Returns (routes, pins)."""
    routes = {TOKEN_URL: Resp(200, json.dumps({"token": "REGISTRY-TOKEN"}).encode())}
    entries = []
    if no_platform_entry:
        junk = json.dumps({"layers": []}).encode()
        entries.append({"digest": "sha256:" + sha(junk), "mediaType": "application/vnd.oci.image.manifest.v1+json"})
        routes[f"{REG}/manifests/sha256:{sha(junk)}"] = Resp(200, junk)
    for arch in platforms:
        blobs = []
        for entries_ in layers:
            data = tar_bytes(entries_ if arch == "amd64" else [(n, b"arm64 " + b if isinstance(b, bytes) else b)
                                                               for n, b in entries_])
            d = "sha256:" + sha(data)
            blobs.append({"digest": d, "mediaType": "application/vnd.oci.image.layer.v1.tar", "size": len(data)})
            routes[f"{REG}/blobs/{d}"] = (lambda d=d: Resp(307, location=cdn + d))
            routes[cdn + d] = (lambda data=data: Resp(200, data + (b"X" if tamper_layer else b"")))
        m = json.dumps({"schemaVersion": 2, "layers": blobs}).encode()
        md = "sha256:" + sha(m)
        routes[f"{REG}/manifests/{md}"] = Resp(200, m + (b" " if tamper_manifest else b""))
        entries.append({"digest": md, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "platform": {"os": "linux", "architecture": arch}})
    idx = json.dumps({"schemaVersion": 2, "manifests": entries}).encode()
    idd = "sha256:" + sha(idx)
    routes[f"{REG}/manifests/{index_digest or idd}"] = Resp(200, idx)
    pins = {"img": {"kind": "image", "repo": "test/image", "index": index_digest or idd, "prefix": PREFIX,
                    "hosts": IMAGE_HOSTS}}
    return routes, pins


def run(name, routes, pins, dest=None):
    """fetch(name) into a fresh case folder; returns (error or None, result, dest, case folder, net, log)."""
    case = tempfile.mkdtemp(dir=TMP)
    with open(os.path.join(case, "sentinel"), "w") as f:
        f.write("keep")
    dest = dest or os.path.join(case, "out")
    net, log = Net(routes), Log()
    try:
        return None, artifacts.fetch(name, dest, transport=net, log=log, pins=pins), dest, case, net, log
    except RuntimeError as e:
        return e, None, dest, case, net, log


def files(path):
    return sorted(os.path.relpath(os.path.join(d, f), path) for d, _, fs in os.walk(path) for f in fs)


def leftovers():
    return glob.glob(os.path.join(tempfile.gettempdir(), "pinned-*"))


# ---- images --------------------------------------------------------------------------------------------------------
GOOD = [[(PREFIX + "WebAPI.jar", b"jar"), (PREFIX + "WEB-INF/web.xml", b"<web/>")]]

r, p = image(GOOD, index_digest="sha256:" + "9" * 64)
err, *_ = run("img", r, p)
check("I1 index with a wrong digest refused", err is not None and "digest" in str(err), err)

r, p = image(GOOD)
err, res, dest, case, net, log = run("img", r, p)
check("I2 baseline: files under dest, nothing else", err is None and res == dest
      and files(dest) == ["WEB-INF/web.xml", "WebAPI.jar"] and open(os.path.join(dest, "WebAPI.jar"), "rb").read() == b"jar",
      f"{err} {files(dest) if os.path.isdir(dest) else None}")
check("I2 summary event: index and file count", any(e.get("index") == p["img"]["index"] and e.get("files") == 2
                                                    for e in log.of("img")), log.events)

for code, entries, label in (("I3", [(PREFIX + "../../escape.txt", b"x")], "`../` entry"),
                             ("I4", [(os.path.join(TMP, "abs-escape.txt"), b"x")], "absolute entry"),
                             ("I14", [(PREFIX + "/../etc/passwd", b"x")], "prefix//../ entry"),
                             ("I15", [(PREFIX + "/" + os.path.join(TMP, "dbl.txt").lstrip("/"), b"x")], "double slash"),
                             ("I10", [(PREFIX + ".wh.../../tmp/erase_me", b"")], "whiteout escape"),
                             ("I16", [(PREFIX + ".wh...", b"")], "whiteout `.wh...`")):
    r, p = image([[(PREFIX + "WebAPI.jar", b"jar")] + entries])
    err, res, dest, case, *_ = run("img", r, p)
    outside = [f for f in files(case) if not f.startswith("out" + os.sep) and f != "sentinel"]
    check(f"{code} {label} refused, nothing outside dest", err is not None and outside == []
          and os.path.exists(os.path.join(case, "sentinel")) and not os.path.exists(os.path.join(TMP, "abs-escape.txt")),
          f"{err} {outside}")

r, p = image(GOOD, tamper_layer=True)
err, *_ = run("img", r, p)
check("I5 tampered layer refused", err is not None and "digest" in str(err), err)
r, p = image(GOOD, tamper_manifest=True)
err, *_ = run("img", r, p)
check("I6 tampered manifest refused", err is not None and "digest" in str(err), err)
r, p = image(GOOD, platforms=("arm64",))
err, *_ = run("img", r, p)
check("I7 only another platform: refused", err is not None and "linux/amd64" in str(err), err)

r, p = image([[("./" + PREFIX + "WebAPI.jar", b"jar")]])
err, res, dest, *_ = run("img", r, p)
check("I8 leading ./ normalized", err is None and files(dest) == ["WebAPI.jar"], err)

r, p = image([[(PREFIX + "WebAPI.jar", b"jar"), (PREFIX + "link", ("sym", "../../../etc/passwd")),
               (PREFIX + "hard", ("hard", "etc/passwd"))]])
err, res, dest, case, net, log = run("img", r, p)
check("I9 links skipped, each one logged", err is None and files(dest) == ["WebAPI.jar"]
      and not os.path.lexists(os.path.join(dest, "link")) and len(log.of("link_skipped")) == 2, f"{err} {log.of('link_skipped')}")

r, p = image([[(PREFIX + "WebAPI.jar", b"jar"), ("etc/passwd", b"no"), ("var/lib/ohdsi/OTHERS/secret.txt", b"no")]])
err, res, dest, *_ = run("img", r, p)
check("I11 entries outside the prefix (incl. a same-length sibling) not written", err is None and files(dest) == ["WebAPI.jar"],
      f"{err} {files(dest) if os.path.isdir(dest) else None}")

r, p = image([[("app/config/settings.yml", b"port: 1"), ("app/config/data/index.json", b"{}")]])
p["img"]["prefix"] = "app/config/"
err, res, dest, *_ = run("img", r, p)
check("I12 any prefix works", err is None and files(dest) == ["data/index.json", "settings.yml"], err)

r, p = image(GOOD, platforms=("arm64", "amd64"))
err, res, dest, *_ = run("img", r, p)
check("I13 two platforms: amd64 picked, not the first", err is None and open(os.path.join(dest, "WebAPI.jar"), "rb").read() == b"jar",
      err)
r, p = image(GOOD, no_platform_entry=True)
err, res, dest, *_ = run("img", r, p)
check("I18 an index entry without platform is skipped", err is None and files(dest) == ["WEB-INF/web.xml", "WebAPI.jar"], err)

# ---- layers: this fetch may replace and remove its own files; FIFOs are refused --------------------------------------
r, p = image([[(PREFIX + "a.txt", b"one"), (PREFIX + "b.txt", b"two"), (PREFIX + "d/c.txt", b"c")],
              [(PREFIX + "a.txt", b"ONE"), (PREFIX + ".wh.b.txt", b""), (PREFIX + ".wh.d", b"")]])
err, res, dest, *_ = run("img", r, p)
check("L1 a later layer replaces a file of an earlier layer", err is None and open(os.path.join(dest, "a.txt"), "rb").read() == b"ONE",
      err)
check("L2 whiteouts remove a file and a folder of an earlier layer", err is None and files(dest) == ["a.txt"]
      and not os.path.exists(os.path.join(dest, "d")), files(dest) if os.path.isdir(dest) else err)
r, p = image([[(PREFIX + "WebAPI.jar", b"jar"), (PREFIX + "pipe", ("fifo",))]])
err, *_ = run("img", r, p)
check("L3 a FIFO entry refused", err is not None, err)

# ---- redirects, hosts, HTTP errors ---------------------------------------------------------------------------------
r, p = image(GOOD)
err, res, dest, case, net, log = run("img", r, p)
reg = [h for u, h in net.calls if u.startswith(REG + "/manifests/")]
cdn = [h for u, h in net.calls if u.startswith(CDN)]
check("R1 the registry gets the token; the redirect host never does",
      err is None and reg and all(h.get("Authorization") == "Bearer REGISTRY-TOKEN" for h in reg)
      and cdn and not any(k.lower() == "authorization" for h in cdn for k in h), f"{err} {cdn[:1]}")
hosts = [(e["host"], e["known"]) for e in log.of("host")]
check("R2 every host logged once, all known", sorted(hosts) == sorted((h, True) for h in IMAGE_HOSTS), hosts)

r, p = image(GOOD, cdn="https://other-cdn.example.net/blob/")
err, res, dest, case, net, log = run("img", r, p)
check("R3 an unlisted redirect host is flagged, not refused", err is None and ("other-cdn.example.net", False) in
      [(e["host"], e["known"]) for e in log.of("host")], f"{err} {log.of('host')}")

r, p = image(GOOD, cdn="http://cdn.example.test/blob/")
err, *_ = run("img", r, p)
check("R4 a redirect to plain http refused", err is not None and "https" in str(err), err)

loop = {"https://loop.example.test/a": Resp(302, location="https://loop.example.test/a")}
err, *_ = run("z", loop, {"z": {"kind": "zip_entry", "url": "https://loop.example.test/a", "sha256": "0" * 64,
                                 "entry": "x.jar", "entry_sha256": "0" * 64, "file": "x.jar", "hosts": ("loop.example.test",)}})
check("R5 a redirect loop stops", err is not None and "redirect" in str(err), err)
err, *_ = run("z", {}, {"z": {"kind": "zip_entry", "url": "https://gone.example.test/x.zip", "sha256": "0" * 64,
                               "entry": "x.jar", "entry_sha256": "0" * 64, "file": "x.jar", "hosts": ("gone.example.test",)}})
check("R6 an HTTP error refused", err is not None and "404" in str(err), err)

# ---- the JDBC driver (zip_entry) -----------------------------------------------------------------------------------
JAR = b"PK-fake-databricks-jdbc-jar"
ZIP_URL = "https://bucket.example.test/driver.zip"
ENTRY = "Driver-1/Driver.jar"


def zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, d in entries:
            z.writestr(n, d)
    return buf.getvalue()


def zcase(zb, zip_sha=None, jar_sha=None, setup=None, parent=True):
    pins = {"jdbc": {"kind": "zip_entry", "url": ZIP_URL, "sha256": zip_sha or sha(zb), "entry": ENTRY,
                     "entry_sha256": jar_sha or sha(JAR), "file": "Driver.jar", "hosts": ("bucket.example.test",)}}
    case = tempfile.mkdtemp(dir=TMP)
    lib, outside = os.path.join(case, "WEB-INF", "lib"), os.path.join(case, "outside")
    os.makedirs(outside)
    if setup:
        setup(case, lib, outside)
    elif parent:
        os.makedirs(lib)
    before = set(leftovers())
    net, log = Net({ZIP_URL: Resp(200, zb)}), Log()
    try:
        res, err = artifacts.fetch("jdbc", lib, transport=net, log=log, pins=pins), None
    except RuntimeError as e:
        res, err = None, e
    return err, res, lib, outside, log, set(leftovers()) - before


def lib_files(lib):
    return sorted(os.listdir(lib)) if os.path.isdir(lib) and not os.path.islink(lib) else []


good = zip_bytes([(ENTRY, JAR)])
err, res, lib, _, log, left = zcase(good)
check("Z0 good zip: jar written, no temp file left, event with the jar hash", err is None and res == os.path.join(lib, "Driver.jar")
      and open(res, "rb").read() == JAR and not left and any(e.get("sha256") == sha(JAR) for e in log.of("jdbc")),
      f"{err} {left} {log.events}")
err, res, lib, _, _, left = zcase(good, zip_sha="0" * 64)
check("Z1 tampered zip refused, nothing written, no temp file left", err is not None and "sha256" in str(err)
      and lib_files(lib) == [] and not left, f"{err} {left}")
err, res, lib, *_ = zcase(zip_bytes([(ENTRY, b"PK-other")]))
check("Z2 another jar refused, nothing written", err is not None and "sha256" in str(err) and lib_files(lib) == [], err)
err, res, lib, _, _, left = zcase(zip_bytes([("other/Driver.jar", JAR)]))
check("Z3 zip without the entry refused, nothing written", err is not None and ENTRY in str(err) and lib_files(lib) == []
      and not left, err)
err, res, lib, outside, *_ = zcase(zip_bytes([("../../outside/evil.jar", b"EVIL"), (ENTRY, JAR)]))
check("Z4 zip `../` entry: only the jar written, nothing outside", err is None and lib_files(lib) == ["Driver.jar"]
      and os.listdir(outside) == [], err)


def jar_there(case, lib, outside):
    os.makedirs(lib)
    open(os.path.join(lib, "Driver.jar"), "wb").write(b"old")


def link_there(case, lib, outside):
    os.makedirs(lib)
    open(os.path.join(outside, "victim.jar"), "wb").write(b"victim")
    os.symlink(os.path.join(outside, "victim.jar"), os.path.join(lib, "Driver.jar"))


def lib_link(case, lib, outside):
    os.makedirs(os.path.dirname(lib))
    os.symlink(outside, lib)


err, res, lib, *_ = zcase(good, setup=jar_there)
check("Z5 a file already at the target refused, old file kept", err is not None and "already" in str(err)
      and open(os.path.join(lib, "Driver.jar"), "rb").read() == b"old", err)
err, res, lib, outside, *_ = zcase(good, setup=link_there)
check("Z6 a symlink at the target refused, the outside file unchanged", err is not None
      and open(os.path.join(outside, "victim.jar"), "rb").read() == b"victim", err)
err, *_ = zcase(good, parent=False)
check("Z7 the parent of dest missing: refused", err is not None, err)
err, res, lib, outside, *_ = zcase(good, setup=lib_link)
check("Z8 dest is a symlink: refused, nothing outside", err is not None and os.listdir(outside) == [], err)

# ---- the JRE (tarball) ---------------------------------------------------------------------------------------------
JRE_URL = "https://github.example.test/jre.tar.gz"
JTOP = "jdk8u492-b09-jre/"


def jcase(entries, redirect=True):
    data = tar_bytes(entries)
    asset = "https://assets.example.test/jre.tar.gz"
    routes = {JRE_URL: Resp(302, location=asset) if redirect else Resp(200, data), asset: Resp(200, data)}
    pins = {"jre": {"kind": "tarball", "url": {"amd64": JRE_URL}, "sha256": {"amd64": sha(data)}, "prefix": JTOP,
                    "hosts": ("github.example.test", "assets.example.test")}}
    return run("jre", routes, pins)


err, res, dest, case, net, log = jcase([(JTOP + "bin/java", b"#!java"), (JTOP + "lib/rt.jar", b"rt"),
                                        (JTOP + "lib/amd64/server/libjsig.so", ("sym", "../libjsig.so")),
                                        (JTOP + "lib/amd64/libjsig.so", b"so")])
java = os.path.join(dest, "bin", "java")
check("J1 JRE: prefix stripped, bin/java written and executable", err is None and os.path.isfile(java) and os.access(java, os.X_OK),
      f"{err} {files(dest) if os.path.isdir(dest) else None}")
check("J2 JRE: the link skipped and logged", err is None and not os.path.lexists(os.path.join(dest, "lib/amd64/server/libjsig.so"))
      and [e["path"] for e in log.of("link_skipped")] == ["lib/amd64/server/libjsig.so"], log.of("link_skipped"))
err, res, dest, case, *_ = jcase([(JTOP + "bin/java", b"#!java"), (JTOP + "../escape.txt", b"x")])
check("J3 JRE: a `../` entry refused (extractall wrote it before)", err is not None
      and not os.path.exists(os.path.join(case, "escape.txt")), err)
data = tar_bytes([(JTOP + "bin/java", b"#!java")])
err, *_ = run("jre", {JRE_URL: Resp(200, data + b"X")},
              {"jre": {"kind": "tarball", "url": {"amd64": JRE_URL}, "sha256": {"amd64": sha(data)}, "prefix": JTOP,
                       "hosts": ("github.example.test",)}})
check("J4 JRE: a tampered tarball refused", err is not None and "sha256" in str(err), err)

# ---- the real pins and the README ----------------------------------------------------------------------------------
P = artifacts.PINS
check("P1 four pins", sorted(P) == ["atlas", "jdbc", "jre", "webapi"], sorted(P))
check("P2 JDBC: the published values", (P["jdbc"]["url"], P["jdbc"]["sha256"], P["jdbc"]["entry"], P["jdbc"]["entry_sha256"]) == (
    "https://databricks-bi-artifacts.s3.us-east-2.amazonaws.com/simbaspark-drivers/jdbc/2.6.36/DatabricksJDBC42-2.6.36.1062.zip",
    "886fb56d96029cfc8e21bd7520ce7888c1ca81a13d9dea58f5c852127959bab0",
    "DatabricksJDBC42-2.6.36.1062/DatabricksJDBC42.jar",
    "83ba88ba02c4765630f99ba5e2a193b511a5c8eb867b6d44941a562100e21563") and P["jdbc"]["file"] == "DatabricksJDBC42.jar")
check("P3 images: WebAPI 2.15.2 and ATLAS 2.15.0 index digests", (P["webapi"]["repo"], P["webapi"]["index"], P["atlas"]["repo"],
                                                                    P["atlas"]["index"]) == (
    "ohdsi/webapi", "sha256:bc5cffde0d6f29bccc994876bf3cb290e8c3f4e5c087ab28c7163343c0b67393",
    "ohdsi/atlas", "sha256:6814e8c5b5366b50bc197b1eb2881689e5852784742b91b9636eec514f5a555e"))
check("P4 JRE: Temurin 8u492-b09 for amd64 and arm64", P["jre"]["sha256"] == {
    "amd64": "8eef3d4a837bb7a9e45d30a7579d84d5b76a4321f4376573311e6bf89e48f9b0",
    "arm64": "d5e50cb002600007dbdfac523605d26196607fa5212db0942ef05cdce9fe2892"}
    and all(u.startswith("https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u492-b09/")
            for u in P["jre"]["url"].values()) and P["jre"]["prefix"] == JTOP)
readme = open(os.path.join(REPO, "README.md")).read()
missing = sorted({h for pin in P.values() for h in pin["hosts"] if f"`{h}`" not in readme})
check("D1 the README names every known host", not missing, missing)

shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{'ALL PASS' if not FAILS else str(len(FAILS)) + ' FAIL'}")
sys.exit(1 if FAILS else 0)
