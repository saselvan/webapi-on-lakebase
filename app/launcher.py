"""Run OHDSI WebAPI 2.15.2 as a Databricks App, in the workspace's region, against WebAPI's database on Lakebase.

Databricks Apps has no Java runtime and no root, so the launcher brings its own:
1. the Temurin 8u492-b09 JRE (the Java build of the pinned WebAPI image), checked by SHA-256;
2. /var/lib/ohdsi/webapi from the pinned image ohdsi/webapi@sha256:bc5cffde... (its linux/amd64 manifest),
   fetched from Docker Hub by digest; the manifest and every layer are checked by SHA-256.
Then it runs WebAPI on 127.0.0.1:APP_JAVA_PORT, and server.py on DATABRICKS_APP_PORT (forwards /WebAPI, serves /ops).

Secrets (PGB_LOCAL_PASSWORD, JASYPT_ENCRYPTOR_PASSWORD, BRIDGE_SECRET) arrive as env vars from app secret resources.

APP_DB=pgbouncer: before Java starts, the launcher checks the static PgBouncer binary against PGB_SHA256, mints a
token for the app's service principal, starts PgBouncer on 127.0.0.1:6432 and its refresher (pgb.py), and points
WebAPI at it with the LOCAL password (secret PGB_LOCAL_PASSWORD). A native-login secret must not be attached: the
launcher refuses to start if DATASOURCE_PASSWORD is set in this mode.
APP_DB=native (the default) logs WebAPI in with DATASOURCE_PASSWORD and WEBAPI_DATASOURCE_URL instead.

APP_BRIDGE=on turns WebAPI security on behind the Apps proxy (bridge.py). It needs APP_DB=pgbouncer, the secret
BRIDGE_SECRET and SECURITY_PROVIDER=AtlasRegularSecurity with only the DB login on. The launcher makes a new bcrypt
hash of the secret, builds WebAPI's DB-login query from it, points that login at PgBouncer, and keeps the raw secret
out of Java's environment. It refuses to start on any other security setting.
"""
import urllib.error
import hashlib, json, os, platform, shutil, signal, subprocess, sys, tarfile, threading, time, urllib.request

JRE = {
    "x86_64": ("OpenJDK8U-jre_x64_linux_hotspot_8u492b09.tar.gz",
               "8eef3d4a837bb7a9e45d30a7579d84d5b76a4321f4376573311e6bf89e48f9b0"),
    "aarch64": ("OpenJDK8U-jre_aarch64_linux_hotspot_8u492b09.tar.gz",
                "d5e50cb002600007dbdfac523605d26196607fa5212db0942ef05cdce9fe2892"),
}
JRE_BASE = "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u492-b09/"
IMAGE_REPO = "ohdsi/webapi"
IMAGE_INDEX = "sha256:bc5cffde0d6f29bccc994876bf3cb290e8c3f4e5c087ab28c7163343c0b67393"  # WebAPI 2.15.2
PLATFORM_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}
WEBAPI_PREFIX = "var/lib/ohdsi/webapi/"
GC_LOG = "/tmp/webapi-app/gc.log"
PGB_BINARY = "pgbouncer-1.26.1-linux-amd64-static"  # pgbouncer/Dockerfile.static
PGB_WEBAPI_URL = "jdbc:postgresql://127.0.0.1:6432/webapi?sslmode=disable&ApplicationName=webapi-pgb"
PGB_AUTH_URL = "jdbc:postgresql://127.0.0.1:6432/webapi?sslmode=disable&ApplicationName=webapi-pgb-auth"
AUTH_OFF = ("WINDOWS", "KERBEROS", "OPENID", "FACEBOOK", "GITHUB", "GOOGLE", "LDAP", "AD", "CAS")
MANIFEST_TYPES = ",".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json",
])


EVENTS = []  # every launcher log event, kept for /ops/status: the app log drops start-up lines (no secrets, no cmd)


def log(event, **kw):
    row = {"event": event, "t": round(time.time(), 3), **kw}
    EVENTS.append({x: v for x, v in row.items() if x != "cmd"})
    print(json.dumps(row), flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_jre(work):
    """Download and verify the pinned JRE; return the java binary path."""
    name, sha = JRE[platform.machine()]
    path = os.path.join(work, name)
    urllib.request.urlretrieve(JRE_BASE + name, path)
    got = sha256_file(path)
    if got != sha:
        raise RuntimeError(f"JRE sha256 mismatch: {got}")
    with tarfile.open(path) as t:
        t.extractall(work)
    os.remove(path)
    java = next(os.path.join(work, d, "bin", "java") for d in os.listdir(work) if d.startswith("jdk8u"))
    log("jre", sha256=got, java=java)
    return java


def _registry_get(url, token, accept=None):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", **({"Accept": accept} if accept else {})})
    return urllib.request.urlopen(req, timeout=120)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _open_blob(url, token):
    """Blobs redirect to object storage; follow the redirect WITHOUT the registry token
    (urllib forwards Authorization, and S3 refuses a request with a second auth mechanism: HTTP 400)."""
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        return urllib.request.build_opener(_NoRedirect).open(req, timeout=120)
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 307, 308):
            raise
        return urllib.request.urlopen(e.headers["Location"], timeout=300)


def _digest_bytes(data, digest):
    got = "sha256:" + hashlib.sha256(data).hexdigest()
    if got != digest:
        raise RuntimeError(f"digest mismatch: want {digest}, got {got}")


def platform_manifest(token, image_repo=IMAGE_REPO, index_digest=IMAGE_INDEX, platform_arch="amd64"):
    """Resolve a pinned index to a platform manifest; both are checked by digest.

    Args:
        token: Docker Hub auth token.
        image_repo: image name (e.g. "ohdsi/webapi").
        index_digest: pinned index digest (e.g. "sha256:abc123...").
        platform_arch: target architecture (e.g. "amd64").

    Returns: manifest dict.
    Raises: RuntimeError if index/manifest digests don't match or platform not found.
    """
    base = f"https://registry-1.docker.io/v2/{image_repo}/manifests/"
    index = _registry_get(base + index_digest, token, MANIFEST_TYPES).read()
    _digest_bytes(index, index_digest)

    # Find the matching platform manifest
    entry = next((m for m in json.loads(index)["manifests"]
                  if m.get("platform", {}).get("os") == "linux" and m.get("platform", {}).get("architecture") == platform_arch),
                 None)
    if not entry:
        raise RuntimeError(f"no manifest for linux/{platform_arch} in index {index_digest}")

    manifest = _registry_get(base + entry["digest"], token, entry["mediaType"]).read()
    _digest_bytes(manifest, entry["digest"])
    log("manifest", index=index_digest, platform=f"linux/{platform_arch}", digest=entry["digest"])
    return json.loads(manifest)


def fetch_webapi_pinned(image_name, index_digest, path_prefix, target_folder, work, platform_arch=None):
    """Download files from a pinned Docker image by digest; validate supply chain at each step.

    Args:
        image_name: Docker image name (e.g. "ohdsi/webapi").
        index_digest: pinned index digest (e.g. "sha256:abc123...").
        path_prefix: prefix path inside the image to extract (e.g. "var/lib/ohdsi/webapi/").
        target_folder: local folder to extract files into.
        work: work directory for intermediate blobs.
        platform_arch: target architecture (default: this machine's architecture, or from APP_ARCH env).

    Returns: target_folder path.

    Rejects:
        - Manifests/layers whose digest doesn't match the pinned hash.
        - Wrong platform manifest.
        - Tar entries with ../, absolute paths, or symlinks pointing outside the prefix.
        - Whiteouts attempting to delete outside the prefix.
    """
    if platform_arch is None:
        platform_arch = os.environ.get("APP_ARCH") or PLATFORM_ARCH[platform.machine()]

    os.makedirs(target_folder, exist_ok=True)
    tok = json.load(urllib.request.urlopen(
        f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{image_name}:pull", timeout=60))["token"]

    manifest = platform_manifest(tok, image_name, index_digest, platform_arch)

    for layer in manifest["layers"]:
        blob = os.path.join(work, "layer.blob")
        with _open_blob(f"https://registry-1.docker.io/v2/{image_name}/blobs/{layer['digest']}", tok) as r, open(blob, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)

        # Validate layer digest before extraction
        got_digest = "sha256:" + sha256_file(blob)
        if got_digest != layer["digest"]:
            raise RuntimeError(f"layer digest mismatch: want {layer['digest']}, got {got_digest}")

        _apply_layer(blob, target_folder, path_prefix)
        os.remove(blob)

    if not os.path.isfile(os.path.join(target_folder, "WebAPI.jar")) and not os.path.isdir(os.path.join(target_folder, "WEB-INF")):
        raise RuntimeError("WebAPI directory not found in the image layers")

    log("webapi", layers=len(manifest["layers"]), files=sum(len(f) for _, _, f in os.walk(target_folder)))
    return target_folder


def _apply_layer(blob_path, root, prefix=WEBAPI_PREFIX):
    """Extract only files under prefix from one layer; honour whiteouts from later layers.

    Rejects: tar entries with ../ or absolute paths, symlinks pointing outside prefix,
    whiteouts attempting to modify outside prefix.
    """
    with tarfile.open(blob_path) as t:  # gzip or plain tar, autodetected
        for m in t:
            normalized = m.name.lstrip("./")
            if not normalized.startswith(prefix):
                continue
            rel = normalized[len(prefix):]

            # Reject entries with ../ or absolute paths
            if ".." in rel or rel.startswith("/"):
                raise RuntimeError(f"tar entry escapes prefix: {m.name}")

            base = os.path.basename(rel)
            if base.startswith(".wh."):
                # Whiteout: must be for a file within the prefix
                whiteout_target_rel = rel[:-len(base)] + base[4:]  # remove .wh. prefix
                if ".." in whiteout_target_rel or whiteout_target_rel.startswith("/"):
                    raise RuntimeError(f"whiteout escapes prefix: {m.name}")
                target = os.path.join(root, whiteout_target_rel)
                shutil.rmtree(target, ignore_errors=True) if os.path.isdir(target) else (os.path.exists(target) and os.remove(target))
                continue

            # Reject symlinks (they could point outside the prefix)
            if m.issym() or m.islnk() or m.isdev():
                continue  # WebAPI's tree is plain files and directories

            m.name = rel
            if rel:
                t.extract(m, root)


def fetch_webapi(work):
    """Download WebAPI's directory from the pinned image; return its path.

    Uses the new validated fetch_webapi_pinned with today's pinned values.
    """
    root = os.path.join(work, "webapi")
    return fetch_webapi_pinned(IMAGE_REPO, IMAGE_INDEX, WEBAPI_PREFIX, root, work)


def java_cmd(java, root):
    opts = os.environ.get("DEFAULT_JAVA_OPTS", "-Djava.security.egd=file:///dev/./urandom").split()
    opts += os.environ.get("APP_HEAP", "-Xms1g -Xmx3g").split()
    opts += [f"-Dserver.port={os.environ.get('APP_JAVA_PORT', '8081')}", "-Dserver.address=127.0.0.1",
             "-XX:+PrintGCDetails", "-XX:+PrintGCDateStamps", f"-Xloggc:{GC_LOG}"]
    return [java, *opts, "-cp", ".:WebAPI.jar:WEB-INF/lib/*.jar", "org.springframework.boot.loader.WarLauncher"]


def start_pgbouncer(work):
    """PgBouncer + refresher as the app's service principal. Returns the PgBouncer object."""
    from databricks.sdk import WorkspaceClient
    from pgb import PgBouncer
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), PGB_BINARY)
    want = os.environ.get("PGB_SHA256", "")  # the SHA-256 of YOUR static binary, from config.env via app.yaml
    if not want:
        raise RuntimeError("PGB_SHA256 is not set")
    if sha256_file(src) != want:
        raise RuntimeError("PgBouncer binary sha256 mismatch")
    binary = os.path.join(work, "pgbouncer")
    shutil.copy(src, binary); os.chmod(binary, 0o700)
    w, ep = WorkspaceClient(), os.environ["LAKEBASE_ENDPOINT"]
    pgb = PgBouncer(binary, work, os.environ["LAKEBASE_HOST"], os.environ["DATABRICKS_CLIENT_ID"],
                    os.environ["PGB_LOCAL_PASSWORD"], lambda: w.postgres.generate_database_credential(endpoint=ep).token,
                    int(os.environ.get("PGB_REFRESH_S", "900")), log=lambda d: log("pgb", **d))
    pgb.start()
    return pgb


def bridge_env(env):
    """Check the security settings and add WebAPI's DB-login settings to env. Returns the Bridge."""
    import bridge
    if env.get("APP_DB") != "pgbouncer":
        raise RuntimeError("APP_BRIDGE=on needs APP_DB=pgbouncer")
    if env.get("SECURITY_PROVIDER") != "AtlasRegularSecurity":
        raise RuntimeError("APP_BRIDGE=on needs SECURITY_PROVIDER=AtlasRegularSecurity")
    if env.get("SECURITY_AUTH_JDBC_ENABLED") != "true":
        raise RuntimeError("APP_BRIDGE=on needs SECURITY_AUTH_JDBC_ENABLED=true")
    on = [m for m in AUTH_OFF if env.get(f"SECURITY_AUTH_{m}_ENABLED") != "false"]
    if on:
        raise RuntimeError(f"APP_BRIDGE=on: these logins must be set to false: {','.join(on)}")
    if env.get("SECURITY_DEFAULTGLOBALREADPERMISSIONS") != "false":
        raise RuntimeError("APP_BRIDGE=on needs SECURITY_DEFAULTGLOBALREADPERMISSIONS=false")
    secret = env.pop("BRIDGE_SECRET", "")
    b = bridge.Bridge(int(env.get("APP_JAVA_PORT", "8081")), secret)
    env["SECURITY_DB_DATASOURCE_AUTHENTICATIONQUERY"] = bridge.auth_query(bridge.make_hash(secret))
    env["SECURITY_DB_DATASOURCE_URL"] = PGB_AUTH_URL
    env["SECURITY_DB_DATASOURCE_PASSWORD"] = env["DATASOURCE_PASSWORD"]
    return b


def security(env):
    """The Bridge when APP_BRIDGE=on (env gets WebAPI's DB-login settings), else None. Refuses mixed settings."""
    if env.get("APP_BRIDGE", "off") == "on":
        br = bridge_env(env)
        log("bridge", provider=env["SECURITY_PROVIDER"], db_login="pgbouncer")
        return br
    if env.get("SECURITY_PROVIDER", "DisabledSecurity") != "DisabledSecurity" or env.get("BRIDGE_SECRET"):
        raise RuntimeError("security settings without APP_BRIDGE=on; set APP_BRIDGE=on or remove them")
    return None


def main():
    work = os.environ.get("APP_WORK", "/tmp/webapi-app")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    t0 = time.monotonic()
    java = fetch_jre(work)
    root = fetch_webapi(work)
    pgb = None
    if os.environ.get("APP_DB", "native") == "pgbouncer":
        if os.environ.get("DATASOURCE_PASSWORD") or os.environ.get("WEBAPI_DATASOURCE_URL"):
            raise RuntimeError("APP_DB=pgbouncer: a native-login password or URL is attached; detach it")
        pgb = start_pgbouncer(work)
        os.environ["DATASOURCE_PASSWORD"] = os.environ["PGB_LOCAL_PASSWORD"]
        os.environ["WEBAPI_DATASOURCE_URL"] = PGB_WEBAPI_URL
    for k in ("DATASOURCE_PASSWORD", "JASYPT_ENCRYPTOR_PASSWORD", "WEBAPI_DATASOURCE_URL"):
        if not os.environ.get(k):
            raise RuntimeError(f"missing env var {k}")
    env = dict(os.environ)
    env["FLYWAY_DATASOURCE_PASSWORD"] = env["DATASOURCE_PASSWORD"]
    env["DATASOURCE_URL"] = env["FLYWAY_DATASOURCE_URL"] = env["WEBAPI_DATASOURCE_URL"]
    br = security(env)
    os.environ.pop("BRIDGE_SECRET", None)
    cmd = java_cmd(java, root)
    log("start", prep_seconds=round(time.monotonic() - t0, 1), cmd=cmd)
    proc = subprocess.Popen(cmd, cwd=root, env=env)  # WebAPI on 127.0.0.1:APP_JAVA_PORT; logs to stdout
    signal.signal(signal.SIGTERM, lambda *_: (proc.terminate(), sys.exit(0)))
    threading.Thread(target=lambda: (proc.wait(), log("webapi_exit", rc=proc.returncode), os._exit(1)), daemon=True).start()
    import server
    mon = None
    if pgb:
        from monitors import Monitors
        mon = Monitors(int(os.environ.get("APP_JAVA_PORT", "8081")), os.environ["LAKEBASE_HOST"],
                       os.environ["DATABRICKS_CLIENT_ID"], lambda: pgb.token, bridge_=br)
        mon.start()
    server.serve(proc, GC_LOG, pgb=pgb, mon=mon, events=EVENTS, bridge_=br)  # front server on DATABRICKS_APP_PORT


if __name__ == "__main__":
    if sys.argv[1:] == ["--fetch-only"]:  # laptop check: download and verify, do not start WebAPI
        w = os.environ.get("APP_WORK", "/tmp/webapi-app")
        os.makedirs(w, exist_ok=True)
        print(fetch_webapi(w))
    else:
        main()
