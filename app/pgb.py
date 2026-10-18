"""PgBouncer 1.26.1 and the token refresher inside the WebAPI app.

WebAPI -> 127.0.0.1:6432 PgBouncer (a fixed LOCAL password) -> Lakebase as the app's service principal (OAuth token).
Every refresh_s the refresher mints a new token, rewrites pgbouncer.ini and the userlist (0600, atomic swap) and sends
SIGHUP, which PgBouncer treats as RELOAD: open sessions stay open, and new server logins use the new token.

The token and the local password are never printed or logged. Events record time, kind, token length and a counter.
PgBouncer's own log goes to the app log; this module keeps only counters and redacted WARNING/ERROR lines.
"""
import collections, os, re, signal, socket, subprocess, threading, time

PORT = 6432
POOLS = ("webapi", "vocab")  # WebAPI's own database; the vocabulary source
AUTH_BAD = re.compile(r"login failed|password authentication failed|JWT", re.I)  # a pass rule counts these
FATAL = re.compile(r"FATAL")
CLOSE = re.compile(r"closing because: ([^(]+?)\s*(?:\(|$)")
HOSTLIKE = re.compile(r"[\w.-]+\.(?:com|net|io)\b|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


def _write_0600(path, text):
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)  # PgBouncer never reads a half-written file


def ca_file():
    for p in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"):
        if os.path.isfile(p):
            return p
    import certifi  # comes with requests in the app's Python
    return certifi.where()


class PgBouncer:
    def __init__(self, binary, workdir, host, user, local_pass, mint, refresh_s=900, log=print):
        if '"' in local_pass or not local_pass:
            raise ValueError("local password must be non-empty and hold no double quote")
        self.binary, self.dir, self.host, self.user = binary, workdir, host, user
        self.local_pass, self.mint, self.refresh_s, self.log = local_pass, mint, refresh_s, log
        self.ini, self.users = os.path.join(workdir, "pgbouncer.ini"), os.path.join(workdir, "userlist.txt")
        self.proc, self.token, self.lock = None, None, threading.Lock()
        self.events = []          # {t, kind, ...}; never a secret
        self.counts = collections.Counter()
        self.closes = collections.Counter()
        self.bad_lines = []       # redacted

    # --- config -------------------------------------------------------------------------------------------------
    def _config(self, token):
        dbs = "\n".join(f"{p} = host={self.host} port=5432 dbname=databricks_postgres user={self.user} "
                        f"password={token} application_name=pgb_{p}" for p in POOLS)
        return f"""[databases]
{dbs}

[pgbouncer]
listen_addr = 127.0.0.1
listen_port = {PORT}
unix_socket_dir =
auth_type = scram-sha-256
auth_file = {self.users}
pool_mode = session
max_client_conn = 400
default_pool_size = 60
server_tls_sslmode = verify-full
server_tls_ca_file = {ca_file()}
ignore_startup_parameters = extra_float_digits,options
log_connections = 1
log_disconnections = 1
stats_period = 60
"""

    def _mint_and_write(self, why):
        token = self.mint()
        with self.lock:
            _write_0600(self.users, f'"webapi" "{self.local_pass}"\n')
            _write_0600(self.ini, self._config(token))
            self.token = token
        self._event("token", why=why, length=len(token))
        return token

    # --- process ------------------------------------------------------------------------------------------------
    def _event(self, kind, **kw):
        e = {"t": round(time.time(), 3), "kind": kind, **kw}
        self.events.append(e)
        self.log({"pgb": kind, **{k: v for k, v in e.items() if k != "kind"}})

    def _read_log(self):
        for raw in self.proc.stdout:
            line = raw.rstrip("\n")
            print(f"[pgbouncer] {line}", flush=True)  # the app log; PgBouncer never logs passwords
            if "new connection to server" in line:
                self.counts["server_logins"] += 1
            if "login attempt" in line:
                self.counts["client_logins"] += 1
            m = CLOSE.search(line)
            if m:
                self.closes[m.group(1).strip()] += 1
            if AUTH_BAD.search(line):
                self.counts["auth_bad"] += 1
            if FATAL.search(line):
                self.counts["fatal"] += 1
            if AUTH_BAD.search(line) or FATAL.search(line) or " ERROR " in line or " WARNING " in line:
                self.counts["bad_lines"] += 1
                self.bad_lines.append(HOSTLIKE.sub("<redacted>", line)[-300:])
        self._event("pgbouncer_exit", rc=self.proc.wait())

    def version(self):
        out = subprocess.run([self.binary, "--version"], capture_output=True, text=True, timeout=10).stdout
        return out.splitlines()[0] if out else None

    def start(self, timeout=30):
        self._mint_and_write("start")
        self.proc = subprocess.Popen([self.binary, self.ini], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1)
        threading.Thread(target=self._read_log, daemon=True).start()
        t_end = time.time() + timeout
        while time.time() < t_end:
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
                self._event("listening", pid=self.proc.pid, version=self.version())
                threading.Thread(target=self._loop, daemon=True).start()
                return
            except OSError:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"PgBouncer exited at start, rc {self.proc.returncode}")
                time.sleep(0.2)
        raise RuntimeError("PgBouncer did not listen in time")

    def rotate(self, why):
        """Mint a new token, rewrite the config, SIGHUP (= RELOAD). Returns True on success."""
        try:
            self._mint_and_write(why)
            self.proc.send_signal(signal.SIGHUP)
            self._event("reload", why=why)
            return True
        except Exception as e:  # keep the old config; the timer retries
            self._event("refresh_error", why=why, error=type(e).__name__)
            return False

    def _loop(self):
        while self.proc.poll() is None:
            time.sleep(self.refresh_s)
            while not self.rotate("timer") and self.proc.poll() is None:
                time.sleep(30)

    def status(self):
        kinds = collections.Counter(e["kind"] for e in self.events)
        return {"pid": self.proc.pid if self.proc else None, "running": bool(self.proc and self.proc.poll() is None),
                "events": self.events, "event_counts": dict(kinds), "counts": dict(self.counts),
                "closes": dict(self.closes), "bad_lines": self.bad_lines[-20:]}
