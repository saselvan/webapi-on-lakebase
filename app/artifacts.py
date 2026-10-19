"""The pinned artifacts the launcher downloads at start, and the one function that fetches them.

fetch(name, dest) writes only bytes that match a digest in PINS, only under dest, and never through a symlink:
- every download is checked by SHA-256 before one byte of it is written under dest (images: the index, the platform
  manifest and each layer);
- tar and zip entry names with an absolute path, NUL, or an empty, "." or ".." segment are refused; entries outside
  the pin's prefix are skipped; symlinks and hard links are skipped and logged (link_skipped); devices and FIFOs are
  refused;
- dest is opened with O_NOFOLLOW and every folder under it too, so a symlink anywhere under dest stops the fetch;
- it replaces or removes only paths this fetch wrote (later layers, whiteouts); any other file already at a target
  is refused.

Every host contacted (redirect targets too) is logged once per fetch as a "host" event, with known=False if the pin
does not list it. An unlisted host is flagged, never refused: the README names every known host for egress rules.
Redirects are followed here, over https only, and never carry the registry token (S3 answers 400 to a second auth).

Pins are a JRE tarball, two image directories and one jar from a zip. PgBouncer is not one: its digest is config.
"""
import hashlib, json, os, platform, tarfile, tempfile, urllib.error, urllib.parse, urllib.request, zipfile

DOCKER_HOSTS = ("auth.docker.io", "registry-1.docker.io",  # layers come from CloudFront or S3, by client location
                "production.cloudfront.docker.com", "docker-images-prod.s3.dualstack.us-east-1.amazonaws.com")
PINS = {
    "jre": {
        "kind": "tarball",  # Temurin 8u492-b09, the Java build of the pinned WebAPI image
        "url": {
            "amd64": "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u492-b09/"
                     "OpenJDK8U-jre_x64_linux_hotspot_8u492b09.tar.gz",
            "arm64": "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u492-b09/"
                     "OpenJDK8U-jre_aarch64_linux_hotspot_8u492b09.tar.gz",
        },
        "sha256": {
            "amd64": "8eef3d4a837bb7a9e45d30a7579d84d5b76a4321f4376573311e6bf89e48f9b0",
            "arm64": "d5e50cb002600007dbdfac523605d26196607fa5212db0942ef05cdce9fe2892",
        },
        "prefix": "jdk8u492-b09-jre/",
        "hosts": ("github.com", "release-assets.githubusercontent.com"),
    },
    "webapi": {
        "kind": "image",  # WebAPI 2.15.2
        "repo": "ohdsi/webapi",
        "index": "sha256:bc5cffde0d6f29bccc994876bf3cb290e8c3f4e5c087ab28c7163343c0b67393",
        "prefix": "var/lib/ohdsi/webapi/",
        "hosts": DOCKER_HOSTS,
    },
    "atlas": {
        "kind": "image",  # ATLAS 2.15.0
        "repo": "ohdsi/atlas",
        "index": "sha256:6814e8c5b5366b50bc197b1eb2881689e5852784742b91b9636eec514f5a555e",
        "prefix": "usr/share/nginx/html/atlas/",
        "hosts": DOCKER_HOSTS,
    },
    "jdbc": {
        "kind": "zip_entry",  # Databricks JDBC 2.6.36: only the one jar is read from the zip
        "url": "https://databricks-bi-artifacts.s3.us-east-2.amazonaws.com/simbaspark-drivers/jdbc/2.6.36/"
               "DatabricksJDBC42-2.6.36.1062.zip",
        "sha256": "886fb56d96029cfc8e21bd7520ce7888c1ca81a13d9dea58f5c852127959bab0",
        "entry": "DatabricksJDBC42-2.6.36.1062/DatabricksJDBC42.jar",
        "entry_sha256": "83ba88ba02c4765630f99ba5e2a193b511a5c8eb867b6d44941a562100e21563",
        "file": "DatabricksJDBC42.jar",
        "hosts": ("databricks-bi-artifacts.s3.us-east-2.amazonaws.com",),
    },
}
ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
MANIFEST_TYPES = ",".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json",
])
REDIRECTS = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 5
MAX_JSON = 4 << 20
CHUNK = 1 << 20


class _Resp:
    def __init__(self, status, location, body):
        self.status, self.location, self._body = status, location, body

    def read(self, n=-1):
        return self._body.read(n)

    def close(self):
        self._body.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def URLLIB(url, headers):
    """One HTTP GET, redirects not followed: fetch() follows them. Returns status, location, read(n), close()."""
    try:
        r = _OPENER.open(urllib.request.Request(url, headers=headers), timeout=300)
    except urllib.error.HTTPError as e:
        return _Resp(e.code, e.headers.get("Location"), e)
    return _Resp(r.status, r.headers.get("Location"), r)


class _Net:
    def __init__(self, name, hosts, transport, log):
        self.name, self.hosts, self.transport, self.log, self.seen = name, set(hosts), transport, log, set()

    def get(self, url, headers=None):
        headers = dict(headers or {})
        for _ in range(MAX_REDIRECTS + 1):
            u = urllib.parse.urlsplit(url)
            if u.scheme != "https" or not u.hostname:
                raise RuntimeError(f"{self.name}: refused a URL that is not https: {u.scheme}://{u.hostname}{u.path}")
            if u.hostname not in self.seen:
                self.seen.add(u.hostname)
                self.log("host", artifact=self.name, host=u.hostname, known=u.hostname in self.hosts)
            r = self.transport(url, headers)
            if r.status in REDIRECTS and r.location:
                r.close()
                url = urllib.parse.urljoin(url, r.location)
                headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
                continue
            if r.status != 200:
                r.close()
                raise RuntimeError(f"{self.name}: HTTP {r.status} from {u.hostname}{u.path}")
            return r
        raise RuntimeError(f"{self.name}: too many redirects")

    def json(self, url, headers=None, digest=None):
        r = self.get(url, headers)
        try:
            data = r.read(MAX_JSON + 1)
        finally:
            r.close()
        if len(data) > MAX_JSON:
            raise RuntimeError(f"{self.name}: response too large from {urllib.parse.urlsplit(url).hostname}")
        if digest:
            got = "sha256:" + hashlib.sha256(data).hexdigest()
            if got != digest:
                raise RuntimeError(f"{self.name}: digest mismatch: want {digest}, got {got}")
        return json.loads(data)

    def download(self, url, sha256, headers=None):
        """Stream url to a temp file and return its path, only if its SHA-256 is sha256 (hex)."""
        r = self.get(url, headers)
        fd, path = tempfile.mkstemp(prefix="pinned-")
        try:
            h = hashlib.sha256()
            with os.fdopen(fd, "wb") as f:
                for chunk in iter(lambda: r.read(CHUNK), b""):
                    h.update(chunk)
                    f.write(chunk)
            if h.hexdigest() != sha256:
                raise RuntimeError(f"{self.name}: sha256 digest mismatch: want {sha256}, got {h.hexdigest()}")
        except BaseException:
            os.remove(path)
            raise
        finally:
            r.close()
        return path


class _Tree:
    """Writes under dest through folder file descriptors opened with O_NOFOLLOW. Keeps what this fetch wrote."""
    def __init__(self, dest):
        self.dest = dest
        if not os.path.isdir(os.path.dirname(os.path.abspath(dest))):
            raise RuntimeError(f"the parent folder of {dest} is missing")
        try:
            os.mkdir(dest, 0o755)
        except FileExistsError:
            pass
        try:
            self.fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise RuntimeError(f"{dest} is a symlink or not a folder") from None
        self.mine = {}  # rel -> ("f" or "d", layer)
        self.layer = 0

    def close(self):
        os.close(self.fd)

    def files(self):
        return sum(1 for kind, _ in self.mine.values() if kind == "f")

    def _folder(self, parts):
        fd, rel = os.dup(self.fd), ""
        for p in parts:
            rel = f"{rel}/{p}" if rel else p
            try:
                os.mkdir(p, 0o755, dir_fd=fd)
                self.mine[rel] = ("d", self.layer)
            except FileExistsError:
                pass
            try:
                nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError:
                raise RuntimeError(f"{rel} under {self.dest} is a symlink or not a folder") from None
            finally:
                os.close(fd)
            fd = nfd
        return fd

    def mkdir(self, rel):
        os.close(self._folder(rel.split("/")))

    def write(self, rel, src, mode):
        parts = rel.split("/")
        fd = self._folder(parts[:-1])
        try:
            try:
                os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
                there = True
            except FileNotFoundError:
                there = False
            if there:
                if self.mine.get(rel, ("",))[0] != "f":
                    raise RuntimeError(f"{rel} is already in {self.dest}")
                os.unlink(parts[-1], dir_fd=fd)
            out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
            with os.fdopen(out, "wb") as f:
                os.fchmod(f.fileno(), mode)
                if isinstance(src, bytes):
                    f.write(src)
                else:
                    for chunk in iter(lambda: src.read(CHUNK), b""):
                        f.write(chunk)
            self.mine[rel] = ("f", self.layer)
        finally:
            os.close(fd)

    def remove(self, rel, keep_top=False):
        """Whiteout: remove rel (with keep_top, only what is under it) where an earlier layer of this fetch wrote it."""
        under = [k for k, (_, layer) in self.mine.items() if layer < self.layer
                 and ((k == rel and not keep_top) or k.startswith(rel + "/") or (keep_top and not rel))]
        for k in sorted(under, key=lambda k: k.count("/"), reverse=True):
            parts = k.split("/")
            fd = self._folder(parts[:-1])
            try:
                if self.mine[k][0] == "f":
                    os.unlink(parts[-1], dir_fd=fd)
                else:
                    os.rmdir(parts[-1], dir_fd=fd)
                del self.mine[k]
            except OSError:
                pass  # a folder that still holds files of the current layer stays
            finally:
                os.close(fd)


def _clean(name):
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if name in ("", "."):
        return ""
    if "\x00" in name or name.startswith("/") or any(s in ("", ".", "..") for s in name.split("/")):
        raise RuntimeError(f"unsafe entry name: {name!r}")
    return name


def _apply_tar(path, tree, prefix, name, log):
    top = prefix.rstrip("/")
    with tarfile.open(path) as t:  # gzip or plain tar, autodetected
        for m in t:
            n = _clean(m.name)
            if not n.startswith(top + "/"):
                continue
            rel = n[len(top) + 1:]
            folder, _, base = rel.rpartition("/")
            if base == ".wh..wh..opq":
                tree.remove(folder, keep_top=True)
                continue
            if base.startswith(".wh."):
                if base[4:] in ("", ".", ".."):
                    raise RuntimeError(f"unsafe whiteout: {m.name!r}")
                tree.remove(f"{folder}/{base[4:]}" if folder else base[4:])
                continue
            if m.issym() or m.islnk():
                log("link_skipped", artifact=name, path=rel)
            elif m.isdir():
                tree.mkdir(rel)
            elif m.isreg():
                with t.extractfile(m) as src:
                    tree.write(rel, src, (m.mode & 0o755) | 0o600)
            else:
                raise RuntimeError(f"device or FIFO entry refused: {m.name!r}")


def _arch():
    a = os.environ.get("APP_ARCH") or platform.machine()
    if a not in ARCH:
        raise RuntimeError(f"unknown architecture: {a}")
    return ARCH[a]


def _tarball(name, pin, net, tree, log):
    arch = _arch()
    path = net.download(pin["url"][arch], pin["sha256"][arch])
    try:
        _apply_tar(path, tree, pin["prefix"], name, log)
    finally:
        os.remove(path)
    log(name, sha256=pin["sha256"][arch], files=tree.files())
    return tree.dest


def _image(name, pin, net, tree, log):
    arch, repo = _arch(), pin["repo"]
    token = net.json(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull")["token"]
    auth = {"Authorization": f"Bearer {token}"}
    base = f"https://registry-1.docker.io/v2/{repo}"
    index = net.json(f"{base}/manifests/{pin['index']}", {**auth, "Accept": MANIFEST_TYPES}, pin["index"])
    entry = next((m for m in index.get("manifests", []) if m.get("platform", {}).get("os") == "linux"
                  and m.get("platform", {}).get("architecture") == arch), None)
    if not entry:
        raise RuntimeError(f"{name}: no manifest for linux/{arch} in index {pin['index']}")
    manifest = net.json(f"{base}/manifests/{entry['digest']}", {**auth, "Accept": entry["mediaType"]}, entry["digest"])
    log("manifest", artifact=name, index=pin["index"], platform=f"linux/{arch}", digest=entry["digest"])
    for i, layer in enumerate(manifest["layers"]):
        algo, _, hexd = layer["digest"].partition(":")
        if algo != "sha256":
            raise RuntimeError(f"{name}: layer digest is not sha256: {layer['digest']}")
        path = net.download(f"{base}/blobs/{layer['digest']}", hexd, auth)
        try:
            tree.layer = i
            _apply_tar(path, tree, pin["prefix"], name, log)
        finally:
            os.remove(path)
    log(name, index=pin["index"], files=tree.files())
    return tree.dest


def _zip_entry(name, pin, net, tree, log):
    path = net.download(pin["url"], pin["sha256"])
    try:
        with zipfile.ZipFile(path) as z:
            data = z.read(pin["entry"])
    except KeyError:
        raise RuntimeError(f"{name}: {pin['entry']} not in the zip") from None
    finally:
        os.remove(path)
    got = hashlib.sha256(data).hexdigest()
    if got != pin["entry_sha256"]:
        raise RuntimeError(f"{name}: {pin['entry']} sha256 mismatch: {got}")
    tree.write(pin["file"], data, 0o644)
    log(name, sha256=got, jar=pin["file"])
    return os.path.join(tree.dest, pin["file"])


KINDS = {"tarball": _tarball, "image": _image, "zip_entry": _zip_entry}


def fetch(name, dest, *, transport=URLLIB, log=None, pins=PINS):
    """Fetch the pinned artifact name into dest (created if missing; its parent must exist). Returns dest, or the
    written file for a zip_entry pin. Raises RuntimeError on any refusal; what was written stays for the caller."""
    log = log or (lambda event, **kw: None)
    pin = pins[name]
    net = _Net(name, pin["hosts"], transport, log)
    try:
        tree = _Tree(dest)
    except OSError as e:
        raise RuntimeError(f"{name}: {type(e).__name__}: {e}") from e
    try:
        return KINDS[pin["kind"]](name, pin, net, tree, log)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError, KeyError) as e:
        raise RuntimeError(f"{name}: {type(e).__name__}: {e}") from e
    finally:
        tree.close()
