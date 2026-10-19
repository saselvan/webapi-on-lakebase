"""Run OHDSI WebAPI 2.15.2 as a Databricks App, in the workspace's region, against WebAPI's database on Lakebase.

Databricks Apps has no Java runtime and no root, so the launcher brings its own pinned artifacts (app/artifacts.py
fetches each one and checks every byte against a digest in its PINS):
1. the Temurin 8u492-b09 JRE (the Java build of the pinned WebAPI image);
2. /var/lib/ohdsi/webapi from the pinned image ohdsi/webapi@sha256:bc5cffde..., fetched from Docker Hub by digest;
3. ATLAS 2.15.0 (/usr/share/nginx/html/atlas) from the pinned image ohdsi/atlas@sha256:6814e8c5..., with its
   config-local.js replaced by ATLAS_CONFIG. If that fails, WebAPI still starts and /atlas answers 503;
4. Databricks JDBC 2.6.36 (for a CDM in Delta, read through a SQL warehouse) into WebAPI's WEB-INF/lib. A wrong file
   stops the launcher.
Then it runs WebAPI on 127.0.0.1:APP_JAVA_PORT, and server.py on DATABRICKS_APP_PORT (forwards /WebAPI, serves
/atlas and /ops).

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
import hashlib, json, os, shutil, signal, subprocess, sys, threading, time

import artifacts

ATLAS_CONFIG = """define([], function () {
  // Written by app/launcher.py at start; it replaces the image's own config-local.js.
  // WebAPI is this app's /WebAPI/. Sign-in is on: ATLAS asks /WebAPI/user/me, and the front server answers as the
  // user the Databricks Apps proxy signed in (app/bridge.py). There are no login providers: users never log in to ATLAS.
  return {
    api: { name: "WebAPI", url: window.location.origin + "/WebAPI/" },
    userAuthenticationEnabled: true,
    authProviders: [],
    enableTermsAndConditions: false,
    enableSkipLogin: false
  };
});
"""
GC_LOG = "/tmp/webapi-app/gc.log"
PGB_BINARY = "pgbouncer-1.26.1-linux-amd64-static"  # pgbouncer/Dockerfile.static
PGB_WEBAPI_URL = "jdbc:postgresql://127.0.0.1:6432/webapi?sslmode=disable&ApplicationName=webapi-pgb"
PGB_AUTH_URL = "jdbc:postgresql://127.0.0.1:6432/webapi?sslmode=disable&ApplicationName=webapi-pgb-auth"
AUTH_OFF = ("WINDOWS", "KERBEROS", "OPENID", "FACEBOOK", "GITHUB", "GOOGLE", "LDAP", "AD", "CAS")


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
    """The pinned JRE into work/jre; return the java binary path."""
    java = os.path.join(artifacts.fetch("jre", os.path.join(work, "jre"), log=log), "bin", "java")
    if not os.path.isfile(java):
        raise RuntimeError("bin/java not found in the JRE")
    return java


def fetch_webapi(work):
    """WebAPI's directory from the pinned image into work/webapi; return its path."""
    root = artifacts.fetch("webapi", os.path.join(work, "webapi"), log=log)
    if not os.path.isfile(os.path.join(root, "WebAPI.jar")) and not os.path.isdir(os.path.join(root, "WEB-INF")):
        raise RuntimeError("WebAPI directory not found in the image layers")
    return root


def write_atlas_config(root):
    """Write ATLAS's config-local.js from ATLAS_CONFIG. A file or symlink already there is removed first."""
    path = os.path.join(root, "js", "config-local.js")
    if os.path.lexists(path):
        os.remove(path)
    with open(path, "x") as f:
        f.write(ATLAS_CONFIG)


def fetch_atlas(work):
    """ATLAS 2.15.0 from the pinned image, with the generated config. Returns its folder, or None after an
    atlas_error event: WebAPI still starts, and /atlas answers 503 with the reason."""
    try:
        root = artifacts.fetch("atlas", os.path.join(work, "atlas"), log=log)
        if not os.path.isfile(os.path.join(root, "index.html")):
            raise RuntimeError("index.html not found in the ATLAS image")
        write_atlas_config(root)
    except Exception as e:
        log("atlas_error", error=f"{type(e).__name__}: {e}"[:300])
        return None
    return root


def fetch_jdbc(work, root):
    """Databricks JDBC 2.6.36 into WebAPI's WEB-INF/lib; return the jar path. A jar or symlink already at the target,
    or a lib folder that is a symlink, is refused."""
    return artifacts.fetch("jdbc", os.path.join(root, "WEB-INF", "lib"), log=log)


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
    fetch_jdbc(work, root)
    atlas = fetch_atlas(work)
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
    server.serve(proc, GC_LOG, pgb=pgb, mon=mon, events=EVENTS, bridge_=br, atlas_root=atlas)  # front server on DATABRICKS_APP_PORT


if __name__ == "__main__":
    if sys.argv[1:] == ["--fetch-only"]:  # laptop check: download and verify, do not start WebAPI
        w = os.environ.get("APP_WORK", "/tmp/webapi-app")
        shutil.rmtree(w, ignore_errors=True)
        os.makedirs(w)
        r = fetch_webapi(w)
        print(r)
        print(fetch_jdbc(w, r))
        print(fetch_atlas(w))
    else:
        main()
