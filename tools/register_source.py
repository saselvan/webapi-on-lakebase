"""Register one WebAPI source by SQL (WebAPI refuses REST source creation while security is disabled), with the username
and password stored already encrypted (ENC(...)), as WebAPI itself stores them, so the plaintext never lands in
<WEBAPI_SCHEMA>.source.

Encryption: tools/EncryptForWebApi.java (jasypt 1.9.2 + BouncyCastle, the jars inside the pinned WebAPI image), run
in a throwaway container with Java 11; key and values are passed as files, never on a command line. Needs Docker.
Insert: as you (the Lakebase project owner). WEBAPI_ROLE empty (the default) = no SET ROLE: in the app setup the schema
is owned by the app's service principal and the owner writes it directly. Idempotent on the source key.

Settings come from the environment (load config.env first: set -a; . ./config.env; set +a):
  DATABRICKS_PROFILE, LAKEBASE_ENDPOINT, WEBAPI_SCHEMA (default webapi), WEBAPI_ROLE (default empty).
Usage: python3 -I tools/register_source.py <key> <name> <dialect> <jdbc url> <username> <password file> <daimons json>
  daimons json: [["Vocabulary","<your vocabulary schema>",1], ...]
"""
import json, os, shutil, subprocess, sys, tempfile
import psycopg
from psycopg import sql

PROF = os.environ["DATABRICKS_PROFILE"]  # required; never guessed
EP = os.environ["LAKEBASE_ENDPOINT"]
SCHEMA = os.environ.get("WEBAPI_SCHEMA", "webapi")
ROLE = os.environ.get("WEBAPI_ROLE", "")  # "" = no SET ROLE (the owner writes the SP-owned schema directly)
WEBAPI_IMAGE = "ohdsi/webapi@sha256:bc5cffde0d6f29bccc994876bf3cb290e8c3f4e5c087ab28c7163343c0b67393"
JAVA_IMAGE = os.environ.get("JAVA_IMAGE", "ohdsi/broadsea-hades:1.19.0")  # any image with a JDK 11+ (single-file source launch)
KEY = os.path.expanduser("~/.webapi-on-lakebase/secrets/webapi_jasypt_key")  # made by tools/setup_and_deploy.sh
ALGO = "PBEWITHSHA256AND128BITAES-CBC-BC"
DAIMON = {"CDM": 0, "Vocabulary": 1, "Results": 2, "CEM": 3, "CEMResults": 4, "Temp": 5}
TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "EncryptForWebApi.java")


def cli(*a):
    return json.loads(subprocess.check_output(["databricks", *a, "--profile", PROF, "-o", "json"]))


def encrypt(values):
    """values: {name: plaintext}. Returns {name: 'ENC(...)'}; plaintext only ever in 0600 files in a 0700 temp dir."""
    d = tempfile.mkdtemp(prefix="webapi-enc.")
    try:
        cid = subprocess.check_output(["docker", "create", WEBAPI_IMAGE]).decode().strip()
        for j in ("jasypt-1.9.2.jar", "bcprov-jdk15on-1.69.jar"):
            subprocess.check_call(["docker", "cp", "-q", f"{cid}:/var/lib/ohdsi/webapi/WEB-INF/lib/{j}", d])
        subprocess.check_call(["docker", "rm", cid], stdout=subprocess.DEVNULL)
        shutil.copy(TOOL, d)
        shutil.copy(KEY, os.path.join(d, "key"))
        for n, v in values.items():
            with open(os.open(os.path.join(d, f"{n}.in"), os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
                f.write(v)
        script = " && ".join(f"java -cp /w/jasypt-1.9.2.jar:/w/bcprov-jdk15on-1.69.jar /w/EncryptForWebApi.java {ALGO} "
                             f"/w/key /w/{n}.in /w/{n}.out" for n in values)
        subprocess.check_call(["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", "-v", f"{d}:/w",
                               "--entrypoint", "sh", JAVA_IMAGE, "-c", script])
        return {n: open(os.path.join(d, f"{n}.out")).read() for n in values}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main(key, name, dialect, url, username, pw_file, daimons):
    owner = cli("current-user", "me")["userName"]
    enc = encrypt({"username": username, "password": open(pw_file).read().strip()})
    host = cli("postgres", "get-endpoint", EP)["status"]["hosts"]["host"]
    with psycopg.connect(host=host, user=owner, dbname="databricks_postgres", sslmode="require",
                         password=cli("postgres", "generate-database-credential", EP)["token"]) as c:
        if ROLE:
            c.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(ROLE)))
        S = sql.Identifier(SCHEMA)
        if c.execute(sql.SQL("SELECT 1 FROM {}.source WHERE source_key = %s").format(S), (key,)).fetchone():
            print(json.dumps({"source": key, "status": "exists, unchanged"}))
            return
        sid = c.execute(sql.SQL("SELECT nextval({})").format(sql.Literal(f"{SCHEMA}.source_sequence"))).fetchone()[0]
        c.execute(sql.SQL("INSERT INTO {}.source (source_id, source_name, source_key, source_connection, source_dialect, "
                          "username, password, is_cache_enabled, check_connection, created_date) "
                          "VALUES (%s, %s, %s, %s, %s, %s, %s, true, false, current_date)").format(S),
                  (sid, name, key, url, dialect, enc["username"], enc["password"]))
        for dt, q, prio in daimons:
            c.execute(sql.SQL("INSERT INTO {}.source_daimon (source_daimon_id, source_id, daimon_type, table_qualifier, priority) "
                              "VALUES (nextval({}), %s, %s, %s, %s)").format(S, sql.Literal(f"{SCHEMA}.source_daimon_sequence")),
                      (sid, DAIMON[dt], q, prio))
        stored = c.execute(sql.SQL("SELECT left(username, 4), left(password, 4) FROM {}.source WHERE source_id = %s").format(S),
                           (sid,)).fetchone()
        print(json.dumps({"source": key, "source_id": sid, "daimons": daimons, "stored_prefixes": stored}))


if __name__ == "__main__":
    a = sys.argv[1:]
    main(*a[:6], json.loads(a[6]))
