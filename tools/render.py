"""Stage the WebAPI app in a folder outside the repo and render its app.yaml from config.env.

Copies app/*.py, requirements.txt, your static PgBouncer binary and (optional) your queries.json into the staging
folder, fills the placeholders of app/app.yaml.template, and refuses to write app.yaml if:
  a setting is missing or malformed, a placeholder is left, the template carries a native-login password or JDBC URL,
  the binary's SHA-256 differs from PGB_SHA256, or the staging folder is inside the repo (the host must stay out of git).
Prints no host and no secret.
Usage: python3 -I tools/render.py [--config config.env] [--stage ~/.webapi-on-lakebase/stage] [--template <file>]
"""
import argparse, hashlib, os, re, shutil, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, "app")
APP_FILES = ("launcher.py", "server.py", "pgb.py", "monitors.py", "requirements.txt")
BINARY = "pgbouncer-1.26.1-linux-amd64-static"  # the name app/launcher.py looks for
RULES = {  # setting -> pattern its value must match
    "LAKEBASE_HOST": r"[A-Za-z0-9.-]+",
    "LAKEBASE_ENDPOINT": r"projects/[a-z0-9-]+/branches/[a-z0-9-]+/endpoints/[a-z0-9-]+",
    "WEBAPI_SCHEMA": r"[a-z_][a-z0-9_]*",
    "SOURCE_KEY": r"[A-Za-z0-9_]+",
    "TICK_CONCEPT_ID": r"[0-9]*",  # empty = the ticker skips the concept path
    "PGB_SHA256": r"[0-9a-f]{64}",
    "PGB_BINARY": r".+",
}
OPTIONAL = {"TICK_CONCEPT_ID", "QUERIES_JSON"}
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
    for k in ("LAKEBASE_HOST", "LAKEBASE_ENDPOINT", "WEBAPI_SCHEMA", "SOURCE_KEY", "TICK_CONCEPT_ID", "PGB_SHA256"):
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
