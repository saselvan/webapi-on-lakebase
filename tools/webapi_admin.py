"""WebAPI admin steps and checks through your app's URL (the Apps proxy), with WebAPI security on.

You call as yourself (U2M token from `databricks auth token`); the token is never printed. Settings: config.env.
Run in this order after the first deploy (README, "Security"):
  me                           GET /WebAPI/user/me: your login, number of rights (the first call makes your WebAPI user)
  grant <login> admin          SQL as the Lakebase project owner: the FIRST admin (WebAPI has no REST path for it)
  source-add                   POST /WebAPI/source/: source SOURCE_KEY on VOCAB_SCHEMA through PgBouncer. WebAPI stores
                               the password encrypted and makes the role "Source user (<SOURCE_KEY>)"
  source-add-cdm               POST /WebAPI/source/: source CDM_SOURCE_KEY, your OMOP CDM in Delta through the SQL
                               warehouse CDM_HTTP_PATH (Databricks JDBC, AuthMech=3). The token in CDM_TOKEN_FILE goes
                               only in WebAPI's encrypted password field, never in the URL
  role-add <role> <login>      PUT /WebAPI/role/{roleId}/users/{userId} (admin right role:*:users:*:put)
  role-create <role>           POST /WebAPI/role (admin right role:post)
  role-perm <role> <right>     SQL as the project owner: give a role one existing right. WebAPI's admin may add rights
                               by REST only to the public role (role:1:permissions:*:put), so this step is SQL
  get <path>                   status, length and the first 300 bytes of any app path
  forged                       forged X-Forwarded-Email / -User headers; prints who WebAPI saw (must be you)
Usage: python3 -I tools/webapi_admin.py [--config config.env] <command> [args]
"""
import json, os, re, stat, subprocess, sys, urllib.error, urllib.request, uuid

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARGS = sys.argv[1:]
CONFIG = os.path.join(REPO, "config.env")
if ARGS[:1] == ["--config"]:
    CONFIG, ARGS = ARGS[1], ARGS[2:]


def read_config(path):
    """KEY=value lines; # comments on their own line (as tools/render.py)."""
    conf = {}
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            conf[k.strip()] = v.strip().strip('"').strip("'")
    return conf


C = read_config(CONFIG)
PROF = C["DATABRICKS_PROFILE"]  # required; never guessed
APP = C["APP_NAME"]
EP = C["LAKEBASE_ENDPOINT"]
SCHEMA = C.get("WEBAPI_SCHEMA") or "webapi"
for name, v in (("WEBAPI_SCHEMA", SCHEMA), ("VOCAB_SCHEMA", C.get("VOCAB_SCHEMA", ""))):
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", v):
        sys.exit(f"{name} must be a plain lowercase identifier")
SEC = os.path.expanduser("~/.webapi-on-lakebase/secrets")
KEY = C.get("SOURCE_KEY") or "VOCAB"
SOURCE = {"name": f"Vocabulary {KEY} (Lakebase, via PgBouncer)", "key": KEY, "dialect": "postgresql",
          "connectionString": "jdbc:postgresql://127.0.0.1:6432/vocab?sslmode=disable&ApplicationName=webapi-pgb-vocab",
          "username": "webapi", "krbAuthMethod": "password",  # without krbAuthMethod WebAPI 2.15.2 answers 500
          "daimons": [{"daimonType": "Vocabulary", "tableQualifier": C["VOCAB_SCHEMA"], "priority": 1}]}


CDM_DAIMONS = (("CDM", "CDM_SCHEMA", 0), ("Vocabulary", "CDM_VOCAB_SCHEMA", 0), ("Results", "CDM_RESULTS_SCHEMA", 1),
               ("Temp", "CDM_TEMP_SCHEMA", 0))  # Vocabulary priority 0: SOURCE_KEY stays the default vocabulary


def read_token(path):
    """The CDM login token: a regular file you own, mode 0600, outside this repo. Never printed."""
    path = os.path.abspath(os.path.expanduser(path))
    if os.path.realpath(path).startswith(os.path.realpath(REPO) + os.sep):
        sys.exit("CDM_TOKEN_FILE must be outside the repo")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            sys.exit("CDM_TOKEN_FILE must be a regular file you own, mode 0600 (chmod 600)")
        tok = f.read().strip()
    if not re.fullmatch(r"[A-Za-z0-9._~-]{20,}", tok):
        sys.exit("CDM_TOKEN_FILE must hold one token")
    return tok


def cdm_source(conf, host, secret):
    """The source-add-cdm body. The URL holds no login: a login in the URL wins over the username and password fields
    (WebAPI's AbstractDaoService), and WebAPI stores only those two fields encrypted, the URL in plain text."""
    key = conf.get("CDM_SOURCE_KEY") or "CDM"
    path = conf.get("CDM_HTTP_PATH", "")
    if not re.fullmatch(r"[A-Za-z0-9]{1,20}", key):
        sys.exit("CDM_SOURCE_KEY must be letters and digits")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}", host):
        sys.exit("workspace host not understood")
    if not re.fullmatch(r"/sql/1\.0/warehouses/[a-f0-9]+", path):
        sys.exit("CDM_HTTP_PATH must be /sql/1.0/warehouses/<id> (the warehouse's connection details)")
    daimons = []
    for kind, name, prio in CDM_DAIMONS:
        if not re.fullmatch(r"[A-Za-z0-9_]+\.[A-Za-z0-9_]+", conf.get(name, "")):
            sys.exit(f"{name} must be <catalog>.<schema>")
        daimons.append({"daimonType": kind, "tableQualifier": conf[name], "priority": prio})
    url = f"jdbc:databricks://{host}:443/default;transportMode=http;ssl=1;httpPath={path};AuthMech=3"
    if secret in url:
        sys.exit("refused: the token would be in the URL")
    return {"name": f"CDM {key} (Delta, via a SQL warehouse)", "key": key, "dialect": "spark", "connectionString": url,
            "username": "token", "password": secret, "krbAuthMethod": "password", "daimons": daimons}


def cli(*a):
    return json.loads(subprocess.check_output(["databricks", *a, "--profile", PROF, "-o", "json"]))


def app_url():
    return cli("apps", "get", APP)["url"].rstrip("/")


def token():
    return cli("auth", "token")["access_token"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def call(method, path, tok, body=None, headers=None):
    h = {"Authorization": f"Bearer {tok}", **(headers or {})}
    req = urllib.request.Request(app_url() + path, data=body, method=method, headers=h)
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=120) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def show(st, data):
    print(json.dumps({"status": st, "bytes": len(data), "head": data[:300].decode(errors="replace")}))


def me(tok):
    st, data = call("GET", "/WebAPI/user/me", tok)
    if st != 200:
        return show(st, data)
    d = json.loads(data)
    print(json.dumps({"status": st, "login": d.get("login"), "roles": sorted(r.get("role", r.get("name", "?")) if isinstance(r, dict)
                      else r for r in d.get("roles", [])), "n_permissions": len(d.get("permissions") or d.get("permissionIdx") or [])}))


def grant(login, role):
    import psycopg
    owner = cli("current-user", "me")["userName"]
    host = cli("postgres", "get-endpoint", EP)["status"]["hosts"]["host"]
    pw = cli("postgres", "generate-database-credential", EP)["token"]
    with psycopg.connect(host=host, dbname="databricks_postgres", user=owner, password=pw, sslmode="require", autocommit=True) as c:
        c.execute(f"SET search_path TO {SCHEMA}")
        u = c.execute("SELECT id FROM sec_user WHERE lower(login) = lower(%s)", (login,)).fetchone()
        r = c.execute("SELECT id FROM sec_role WHERE name = %s", (role,)).fetchone()
        if not u or not r:
            sys.exit(f"no such {'user (log in once first)' if not u else 'role'}")
        c.execute("INSERT INTO sec_user_role (user_id, role_id, origin) SELECT %s, %s, 'SYSTEM' WHERE NOT EXISTS "
                  "(SELECT 1 FROM sec_user_role WHERE user_id = %s AND role_id = %s)", (u[0], r[0], u[0], r[0]))
        n = c.execute("SELECT count(*) FROM sec_user_role WHERE user_id = %s AND role_id = %s", (u[0], r[0])).fetchone()[0]
    print(json.dumps({"login": login, "role": role, "rows": n}))


def source_add(tok):
    src = dict(SOURCE, password=open(os.path.join(SEC, "pgb_local_pass")).read().strip())
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"source\"\r\nContent-Type: application/json\r\n\r\n"
            f"{json.dumps(src)}\r\n--{b}--\r\n").encode()
    st, data = call("POST", "/WebAPI/source/", tok, body, {"Content-Type": f"multipart/form-data; boundary={b}"})
    show(st, data.replace(src["password"].encode(), b"<pw>"))


def source_add_cdm(tok):
    secret = read_token(C.get("CDM_TOKEN_FILE", ""))
    host = cli("auth", "describe")["details"]["host"].replace("https://", "").rstrip("/")
    src = cdm_source(C, host, secret)
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"source\"\r\nContent-Type: application/json\r\n\r\n"
            f"{json.dumps(src)}\r\n--{b}--\r\n").encode()
    st, data = call("POST", "/WebAPI/source/", tok, body, {"Content-Type": f"multipart/form-data; boundary={b}"})
    show(st, data.replace(secret.encode(), b"<token>"))


def role_create(tok, role):
    st, data = call("POST", "/WebAPI/role", tok, json.dumps({"role": role}).encode(), {"Content-Type": "application/json"})
    show(st, data)


def role_perm(role, right):
    import psycopg
    owner = cli("current-user", "me")["userName"]
    host = cli("postgres", "get-endpoint", EP)["status"]["hosts"]["host"]
    pw = cli("postgres", "generate-database-credential", EP)["token"]
    with psycopg.connect(host=host, dbname="databricks_postgres", user=owner, password=pw, sslmode="require", autocommit=True) as c:
        c.execute(f"SET search_path TO {SCHEMA}")
        r = c.execute("SELECT id FROM sec_role WHERE name = %s", (role,)).fetchone()
        p = c.execute("SELECT id FROM sec_permission WHERE value = %s", (right,)).fetchone()
        if not r or not p:
            sys.exit(f"no such {'role' if not r else 'right'}")
        c.execute("INSERT INTO sec_role_permission (id, role_id, permission_id) SELECT nextval('sec_role_permission_sequence'), "
                  "%s, %s WHERE NOT EXISTS (SELECT 1 FROM sec_role_permission WHERE role_id = %s AND permission_id = %s)",
                  (r[0], p[0], r[0], p[0]))
        n = c.execute("SELECT count(*) FROM sec_role_permission WHERE role_id = %s", (r[0],)).fetchone()[0]
    print(json.dumps({"role": role, "right": right, "rights_on_role": n}))


def role_add(tok, role, login):
    st, data = call("GET", "/WebAPI/role", tok)
    rid = next((r["id"] for r in json.loads(data) if r["role"] == role), None) if st == 200 else None
    st, data = call("GET", "/WebAPI/user", tok)
    uid = next((u["id"] for u in json.loads(data) if u["login"].lower() == login.lower()), None) if st == 200 else None
    if rid is None or uid is None:
        sys.exit(f"no such {'role' if rid is None else 'user (log in once first)'}")
    st, data = call("PUT", f"/WebAPI/role/{rid}/users/{uid}", tok)
    print(json.dumps({"role": role, "role_id": rid, "login": login, "status": st}))


def forged(tok):
    for label, h in (("forged email", {"X-Forwarded-Email": "attacker@example.com"}),
                     ("forged user+email", {"X-Forwarded-User": "attacker@example.com", "X-Forwarded-Email": "attacker@example.com"})):
        st, data = call("GET", "/WebAPI/user/me", tok, headers=h)
        login = json.loads(data).get("login") if st == 200 else None
        print(json.dumps({"case": label, "status": st, "login_seen_by_webapi": login}))


if __name__ == "__main__":
    args = ARGS
    cmd = args[0] if args else ""
    if cmd == "grant":
        grant(args[1], args[2])
    elif cmd == "role-perm":
        role_perm(args[1], args[2])
    elif cmd in ("me", "get", "source-add", "source-add-cdm", "forged", "role-add", "role-create"):
        t = token()
        {"me": lambda: me(t), "get": lambda: show(*call("GET", args[1], t)), "source-add": lambda: source_add(t),
         "source-add-cdm": lambda: source_add_cdm(t),
         "forged": lambda: forged(t), "role-add": lambda: role_add(t, args[1], args[2]),
         "role-create": lambda: role_create(t, args[1])}[cmd]()
    else:
        sys.exit(__doc__)
