"""Monitors inside the app: a ticker on WebAPI's REST layer and a sampler of Lakebase sessions.

ticker:  every 60 s, GET 2 paths on 127.0.0.1 (WebAPI's own database through PgBouncer), plus one concept on source
         SOURCE_KEY if TICK_CONCEPT_ID is set (the vocabulary source through PgBouncer).
sampler: every 60 s, a NEW direct login to Lakebase as the app's service principal (application_name ops-sampler),
         using the refresher's current token. Counts sessions in pg_stat_activity by role and keeps backend_start of
         the SP's sessions. No query text is read. A plain role sees other roles' usename, so sessions of the roles
         in NATIVE_ROLES (comma-separated, optional) are counted even though their details are hidden.
terminate(): the SP ends its own Lakebase sessions except the sampler's (a role may signal its own backends).
Results stay in memory; read them through /ops/conn. Nothing here holds or returns a secret.
"""
import http.client, os, re, threading, time

TICK_PATHS = {"info": "/WebAPI/info", "conceptset": "/WebAPI/conceptset/"}
if os.environ.get("TICK_CONCEPT_ID"):
    TICK_PATHS["concept"] = (f"/WebAPI/vocabulary/{os.environ.get('SOURCE_KEY', 'VOCAB')}/concept/"
                             f"{int(os.environ['TICK_CONCEPT_ID'])}")
NATIVE_ROLES = tuple(r for r in os.environ.get("NATIVE_ROLES", "").split(",") if r)
SAMPLER_APP = "ops-sampler"
APP_SCHEMA = os.environ.get("DATASOURCE_OHDSI_SCHEMA", "webapi")  # WebAPI's schema, where Flyway keeps schema_history
if not re.fullmatch(r"[a-z_][a-z0-9_]*", APP_SCHEMA):
    raise ValueError("DATASOURCE_OHDSI_SCHEMA must be a plain lowercase identifier")


class Monitors:
    def __init__(self, java_port, host, user, token_fn, period_s=60):
        self.java_port, self.host, self.user, self.token_fn, self.period = java_port, host, user, token_fn, period_s
        self.ticks, self.samples, self.terminations = [], [], []
        self.seen = {}  # SP session key (pid, backend_start) -> backend_start epoch

    # --- ticker -------------------------------------------------------------------------------------------------
    def _get(self, path):
        t0 = time.perf_counter()
        try:
            c = http.client.HTTPConnection("127.0.0.1", self.java_port, timeout=60)
            c.request("GET", path); r = c.getresponse(); body = r.read(); c.close()
            return r.status, round((time.perf_counter() - t0) * 1000, 1), len(body)
        except Exception as e:
            return f"{type(e).__name__}", round((time.perf_counter() - t0) * 1000, 1), 0

    def tick(self):
        t = time.time()
        row = {"t": round(t, 3)}
        for k, p in TICK_PATHS.items():
            row[k] = self._get(p)  # (status, ms, bytes)
        self.ticks.append(row)

    # --- sampler ------------------------------------------------------------------------------------------------
    def _connect(self):
        import psycopg
        return psycopg.connect(host=self.host, port=5432, dbname="databricks_postgres", user=self.user,
                               password=self.token_fn(), sslmode="require", application_name=SAMPLER_APP,
                               connect_timeout=20, autocommit=True)

    def sample(self):
        t = time.time(); row = {"t": round(t, 3)}
        t0 = time.perf_counter()
        try:
            with self._connect() as c:
                row["login_ms"] = round((time.perf_counter() - t0) * 1000, 1)
                rows = c.execute(
                    "SELECT usename = current_user, usename = ANY(%s), coalesce(application_name, ''), pid, "
                    "extract(epoch FROM backend_start)::float8 FROM pg_stat_activity "
                    "WHERE datname = current_database() AND pid <> pg_backend_pid()", (list(NATIVE_ROLES),)).fetchall()
                mine = [r for r in rows if r[0] and r[2] != SAMPLER_APP]
                row["sp_sessions"] = len(mine)
                row["native_sessions"] = sum(1 for r in rows if r[1])
                row["sp_oldest_age_s"] = round(t - min(r[4] for r in mine), 1) if mine else None
                row["sp_over_3600_s"] = sum(1 for r in mine if t - r[4] > 3600)
                new = [r for r in mine if (r[3], r[4]) not in self.seen]
                for r in new:
                    self.seen[(r[3], r[4])] = r[4]
                row["sp_new"] = len(new)
                row["sp_new_backend_starts"] = [round(r[4], 3) for r in new]
                try:
                    row["flyway"] = list(c.execute(
                        f"SELECT count(*), count(*) FILTER (WHERE success) FROM {APP_SCHEMA}.schema_history").fetchone())
                except Exception as e:
                    row["flyway"] = type(e).__name__
        except Exception as e:
            row["error"] = f"{type(e).__name__}"
        self.samples.append(row)

    def terminate(self):
        """End every SP session except the sampler's. Returns the number ended."""
        t = time.time()
        with self._connect() as c:
            n = c.execute("SELECT count(*) FILTER (WHERE pg_terminate_backend(pid)) FROM pg_stat_activity "
                          "WHERE usename = current_user AND pid <> pg_backend_pid() "
                          "AND coalesce(application_name, '') <> %s", (SAMPLER_APP,)).fetchone()[0]
        self.terminations.append({"t": round(t, 3), "ended": n})
        return n

    # --- loop ---------------------------------------------------------------------------------------------------
    def _loop(self):
        nxt = time.time()
        while True:
            self.tick()
            self.sample()
            nxt += self.period
            time.sleep(max(0.0, nxt - time.time()))

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()

    def status(self, full=False):
        out = {"n_ticks": len(self.ticks), "n_samples": len(self.samples), "terminations": self.terminations,
               "last_tick": self.ticks[-1] if self.ticks else None, "last_sample": self.samples[-1] if self.samples else None}
        if full:
            out["ticks"], out["samples"] = self.ticks, self.samples
        return out
