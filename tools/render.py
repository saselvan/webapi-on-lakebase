"""Stage the WebAPI app in a folder outside the repo and render its app.yaml from config.env.

Copies app/*.py, requirements.txt, your static PgBouncer binary and (optional) your queries.json into the staging
folder, fills the placeholders of app/app.yaml.template, and refuses to write app.yaml if:
  a setting is missing or malformed, a placeholder is left, the template carries a native-login password or JDBC URL,
  WebAPI security is not on exactly as app/bridge.py needs it (AtlasRegularSecurity, only the DB login, no global read,
  the bridge secret as an app resource, no DB-login query or password in the file), the binary's SHA-256 differs from
  PGB_SHA256, or the staging folder is inside the repo (the host must stay out of git).
Prints no host and no secret.
Usage: python3 -I tools/render.py [--config config.env] [--stage ~/.webapi-on-lakebase/stage] [--template <file>]
"""
import argparse, hashlib, os, re, shutil, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, "app")
APP_FILES = ("launcher.py", "artifacts.py", "server.py", "pgb.py", "monitors.py", "bridge.py", "requirements.txt")
BINARY = "pgbouncer-1.26.1-linux-amd64-static"  # the name app/launcher.py looks for
RULES = {  # setting -> pattern its value must match
    "LAKEBASE_HOST": r"[A-Za-z0-9.-]+",
    "LAKEBASE_ENDPOINT": r"projects/[a-z0-9-]+/branches/[a-z0-9-]+/endpoints/[a-z0-9-]+",
    "WEBAPI_SCHEMA": r"[a-z_][a-z0-9_]*",
    "SOURCE_KEY": r"[A-Za-z0-9_]+",
    "TICK_CONCEPT_ID": r"[0-9]*",  # empty = the ticker skips the concept path
    "PGB_SHA256": r"[0-9a-f]{64}",
    "PGB_BINARY": r".+",
    "APP_URL": r"https://[a-z0-9.-]+",
    "OPS_ADMINS": r"(?:[a-z0-9._+-]+@[a-z0-9.-]+|[0-9a-f-]{36})(?:,(?:[a-z0-9._+-]+@[a-z0-9.-]+|[0-9a-f-]{36}))*|",
    "OPS_CONTROL": r"on|off|",  # empty = off
}
OPTIONAL = {"TICK_CONCEPT_ID", "QUERIES_JSON", "OPS_ADMINS", "OPS_CONTROL"}
SECURITY = {  # env name -> (kind, value) the rendered app.yaml must hold
    "APP_BRIDGE": ("value", "on"),
    "BRIDGE_SECRET": ("valueFrom", "webapi-bridge-secret"),
    "SECURITY_PROVIDER": ("value", "AtlasRegularSecurity"),
    "SECURITY_AUTH_JDBC_ENABLED": ("value", "true"),
    "SECURITY_DEFAULTGLOBALREADPERMISSIONS": ("value", "false"),
}
AUTH_OFF = ("WINDOWS", "KERBEROS", "OPENID", "FACEBOOK", "GITHUB", "GOOGLE", "LDAP", "AD", "CAS")  # as app/launcher.py
SET_BY_LAUNCHER = ("SECURITY_DB_DATASOURCE_PASSWORD", "SECURITY_DB_DATASOURCE_AUTHENTICATIONQUERY", "SECURITY_DB_DATASOURCE_URL")
ENV_LINE = re.compile(r"^\s*- \{name: ([A-Za-z0-9_]+), (value|valueFrom): (.*)\}\s*$")


def fail(msg):
    sys.exit(f"render: {msg}")


def read_config(path):
    """KEY=value lines; # comments on their own line; surrounding quotes removed."""
    if not os.path.isfile(path):
        fail(f"{path} not found; copy config.env.example to config.env and fill it in")
    conf = {}
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, sep, v = line.partition("=")
        if not sep:
            fail(f"not a KEY=value line in {os.path.basename(path)}")
        conf[k.strip()] = v.strip().strip('"').strip("'")
    return conf


def check(conf):
    for k, pat in RULES.items():
        v = conf.get(k, "")
        if k == "OPS_ADMINS":
            v = v.lower()  # the bridge compares lowercased identities
        if not v and k not in OPTIONAL:
            fail(f"{k} is not set")
        if not re.fullmatch(pat, v):
            fail(f"{k} is malformed")
    q = conf.get("QUERIES_JSON", "")
    if q and not os.path.isfile(os.path.expanduser(q)):
        fail("QUERIES_JSON is set but the file does not exist")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def render(template_text, conf):
    text = template_text
    conf = {**conf, "OPS_ADMINS": conf.get("OPS_ADMINS", "").lower(), "OPS_CONTROL": conf.get("OPS_CONTROL") or "off"}
    for k in ("LAKEBASE_HOST", "LAKEBASE_ENDPOINT", "WEBAPI_SCHEMA", "SOURCE_KEY", "TICK_CONCEPT_ID", "PGB_SHA256",
              "APP_URL", "OPS_ADMINS", "OPS_CONTROL"):
        text = text.replace(f"__{k}__", conf.get(k, ""))
    if re.search(r"__[A-Z_]+__", text):
        fail("a placeholder was not replaced")
    env = {}
    for line in text.splitlines():
        m = ENV_LINE.match(line)
        if m:
            env[m.group(1)] = (m.group(2), m.group(3).strip().strip('"'))
    if "DATASOURCE_PASSWORD" in env or "WEBAPI_DATASOURCE_URL" in env:
        fail("native login in the template")
    if env.get("APP_DB") != ("value", "pgbouncer") or env.get("PGB_LOCAL_PASSWORD") != ("valueFrom", "pgb-local-password"):
        fail("the template is not in PgBouncer mode")
    for k, want in SECURITY.items():
        if env.get(k) != want:
            fail(f"security is not on as the bridge needs it: {k}")
    others = [m for m in AUTH_OFF if env.get(f"SECURITY_AUTH_{m}_ENABLED") != ("value", "false")]
    if others:
        fail(f"security is not on as the bridge needs it: these logins must be false: {','.join(others)}")
    if any(k in env for k in SET_BY_LAUNCHER):
        fail("the DB-login query or password is in the template; the launcher sets them")
    return text, env


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(REPO, "config.env"))
    ap.add_argument("--stage", default=None, help="default: STAGE_DIR from config.env, else ~/.webapi-on-lakebase/stage")
    ap.add_argument("--template", default=os.path.join(APP, "app.yaml.template"))
    a = ap.parse_args()
    conf = read_config(a.config)
    a.stage = a.stage or conf.get("STAGE_DIR") or "~/.webapi-on-lakebase/stage"
    stage = os.path.realpath(os.path.expanduser(a.stage))
    if stage == os.path.realpath(REPO) or stage.startswith(os.path.realpath(REPO) + os.sep):
        fail("the staging folder must be outside the repo")
    check(conf)
    binary = os.path.expanduser(conf["PGB_BINARY"])
    if not os.path.isfile(binary):
        fail("PGB_BINARY does not exist")
    if sha256(binary) != conf["PGB_SHA256"]:
        fail("the binary's SHA-256 differs from PGB_SHA256")
    text, env = render(open(a.template).read(), conf)
    os.makedirs(stage, exist_ok=True)
    os.umask(0o077)
    for f in APP_FILES:
        shutil.copy(os.path.join(APP, f), stage)
    shutil.copy(binary, os.path.join(stage, BINARY))
    if conf.get("QUERIES_JSON"):
        shutil.copy(os.path.expanduser(conf["QUERIES_JSON"]), os.path.join(stage, "queries.json"))
    elif os.path.exists(os.path.join(stage, "queries.json")):
        os.remove(os.path.join(stage, "queries.json"))  # an old copy must not ride along
    out = os.path.join(stage, "app.yaml")
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    print(f"app.yaml OK, {len(env)} env vars, binary sha256 matches PGB_SHA256, staged in {a.stage}")


if __name__ == "__main__":
    main()
