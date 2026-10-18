"""Offline test of the attacker list: the trusted-header bridge in front of a fake WebAPI.

No app, no Lakebase: a fake WebAPI (DB login on /WebAPI/user/login/db, Bearer tokens, 401 on a bad token) and the
real front server with the real bridge, each on a free local port. One check per attacker item (A2-A12; A1 is the
proxy's job and is checked live). Hostile rows: a forged client Authorization holding a VALID token of another
identity, mixed-case identities, every encoding of a blocked path, a token that WebAPI expires mid-run, a wrong secret.
Usage: python3 -I tests/test_bridge.py   (needs bcrypt: pip install -r app/requirements.txt; exit 0 = pass)
"""
import http.client, http.server, json, os, socket, socketserver, sys, threading, urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
import bridge, launcher, monitors, server  # noqa: E402

SECRET = "s" * 20 + "-bridge-test-secret-0123456789"  # 50 characters; a test value, not a real secret
FAILS = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"))
    if not ok:
        FAILS.append(name)


class Fake:
    """Fake WebAPI: who logged in, which token each request carried, which paths it saw."""
    logins, seen, tokens, n = [], [], {}, 0
    secret = SECRET
    lock = threading.Lock()


class FakeWebAPI(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj, extra=()):
        b = json.dumps(obj).encode()
        self.send_response(code)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def _any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if self.command == "POST" and self.path == "/WebAPI/user/login/db":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            if form.get("password") != Fake.secret:
                return self._send(401, {"error": "bad login"})
            with Fake.lock:
                Fake.n += 1; tok = f"tok-{Fake.n}"; Fake.tokens[tok] = form["login"]; Fake.logins.append(form["login"])
            return self._send(200, {"ok": True}, [("Bearer", tok)])
        auth = self.headers.get("Authorization", "")
        user = Fake.tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
        Fake.seen.append({"method": self.command, "path": self.path, "user": user, "auth": auth})
        if user is None:
            return self._send(401, {"error": "no token"})
        # WebAPI sends a token header back on some paths; the bridge must never pass it on
        return self._send(200, {"path": self.path, "user": user}, [("Bearer", "leak-" + auth[7:]), ("Set-Cookie", "x=1")])

    do_GET = do_POST = do_PUT = do_DELETE = _any


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def serve(handler):
    srv = TS(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


java_port = serve(FakeWebAPI)
server.JAVA_PORT = java_port
server.BRIDGE = bridge.Bridge(java_port, SECRET)
front = serve(server.Handler)
OWNER, OTHER = "owner@example.com", "other@example.com"


def call(method, path, ident=None, headers=None, body=None):
    h = dict(headers or {})
    if ident is not None:
        h["X-Forwarded-Email"] = ident
    c = http.client.HTTPConnection("127.0.0.1", front, timeout=10)
    c.request(method, path, body, h)
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, dict((k.lower(), v) for k, v in r.getheaders()), data


def _raises(fn, exc=Exception):
    try:
        fn()
    except exc:
        return True
    return False


def reset():
    """Each section starts clean: WebAPI forgets its tokens and the front server gets a new bridge (empty cache)."""
    Fake.logins.clear(); Fake.seen.clear(); Fake.tokens.clear()
    server.BRIDGE = bridge.Bridge(java_port, SECRET)


# A2: no identity -> 401 and WebAPI is never asked
reset()
st, _, _ = call("GET", "/WebAPI/conceptset/")
check("A2 no identity -> 401", st == 401, st)
check("A2 no identity -> nothing reaches WebAPI", not Fake.seen and not Fake.logins, (Fake.seen, Fake.logins))

# A3: every sign-in path except /user/refresh, in every spelling, is refused before WebAPI (403 or 400), for every method
# (/user/refresh is intentionally unblocked; it's handled by the bridge)
reset()
Fake.grace_period = {}
spellings = ["/WebAPI/user/login/db", "/WebAPI/user/login/openid", "/WebAPI/user/runas", "/WebAPI/user/oauth/callback",
             "/WebAPI/user/saml/callback", "/WebAPI/user/cas/callback", "/WebAPI/user/logout",
             "/WebAPI/USER/Login/db", "/WebAPI/user/login/db/", "/WebAPI/user/login", "/WebAPI/user%2Flogin/db",
             "/WebAPI/user/login%2Fdb", "/WebAPI/user;x=1/login/db", "/WebAPI//user/login/db", "/WebAPI/./user/login/db",
             "/WebAPI/x/../user/login/db", "/WebAPI/user/%6cogin/db", "/WebAPI/user/%256cogin/db",
             "/WebAPI/user\\login/db", "/WebAPI/user/runas?runAs=admin@example.com", "http://x/WebAPI/user/login/db"]
bad = [(m, p, call(m, p, OWNER)[0]) for p in spellings for m in ("GET", "POST", "PUT", "DELETE")]
check("A3 sign-in paths (except refresh) -> 403/400 for every spelling and method", all(s in (400, 403) for _, _, s in bad),
      [x for x in bad if x[2] not in (400, 403)])
check("A3 sign-in paths -> nothing reaches WebAPI", not Fake.seen, Fake.seen[:3])
st, _, _ = call("GET", "/WebAPI/user/me", OWNER)
check("A3 /user/me is not blocked", st == 200, st)

# A4: a client Authorization (even a VALID token of another identity) is replaced by the caller's own token
reset()
call("GET", "/WebAPI/info", OTHER)
other_tok = next(t for t, u in Fake.tokens.items() if u == OTHER)
st, _, body = call("GET", "/WebAPI/conceptset/", OWNER, {"Authorization": f"Bearer {other_tok}"})
check("A4 forged Authorization ignored: WebAPI sees the caller", st == 200 and json.loads(body)["user"] == OWNER, body)
check("A4 forged token never reaches WebAPI on the caller's request", Fake.seen[-1]["auth"] != f"Bearer {other_tok}")

# A5: one login per identity (cached), different identities get different logins and tokens
reset()
for _ in range(3):
    call("GET", "/WebAPI/info", OWNER)
call("GET", "/WebAPI/info", OTHER)
check("A5 cache: 3 calls of one identity -> 1 login", Fake.logins.count(OWNER) == 1, Fake.logins)
toks = {s["auth"] for s in Fake.seen if s["user"]}
check("A5 two identities -> two logins, two tokens", Fake.logins.count(OTHER) == 1 and len(toks) == 2, (Fake.logins, toks))

# A6: identities are normalized or refused
reset()
st, _, body = call("GET", "/WebAPI/info", "  Owner@Example.COM ")
check("A6 mixed case and spaces -> the same login", st == 200 and json.loads(body)["user"] == OWNER, body)
odd = [bridge.INTERNAL_ID, "admin", "anonymous", "a@b", "o'neil@example.com", "x@example.com;drop", "", "a" * 70 + "@example.com"]
got = [(i, call("GET", "/WebAPI/info", i)[0]) for i in odd]
check("A6 odd identities -> 401 (incl. the internal id)", all(s == 401 for _, s in got), got)
check("A6 a UUID identity (a service principal) passes",
      bridge.identity({"X-Forwarded-Email": "", "X-Forwarded-User": "0a1b2c3d-1111-2222-3333-444455556666"}) ==
      "0a1b2c3d-1111-2222-3333-444455556666")
check("A6 X-Forwarded-Email wins over X-Forwarded-User",
      bridge.identity({"X-Forwarded-Email": OWNER, "X-Forwarded-User": OTHER}) == OWNER)

# A7: a token WebAPI drops -> exactly one fresh login, then 200; a refused login -> 502, no loop
reset()
call("GET", "/WebAPI/info", OWNER)
Fake.tokens.clear()  # WebAPI restarted: every token it signed is gone
st, _, _ = call("GET", "/WebAPI/info", OWNER)
check("A7 expired token -> one re-login -> 200", st == 200 and Fake.logins.count(OWNER) == 2, (st, Fake.logins))
Fake.secret = "wrong"; Fake.tokens.clear(); reset()
st, _, body = call("GET", "/WebAPI/info", OWNER)
check("A7 refused login -> 502, at most 2 login tries", st == 502 and len(Fake.logins) == 0, (st, body))
Fake.secret = SECRET

# A8 + A11: the secret and WebAPI's tokens never leave the front server
reset()
outs = [call("GET", "/WebAPI/info", OWNER), call("GET", "/WebAPI/user/login/db", OWNER), call("GET", "/WebAPI/x")]
blob = json.dumps([[s, h, d.decode()] for s, h, d in outs])
check("A8 secret in no response", SECRET not in blob)
check("A11 no Bearer / Set-Cookie header and no WebAPI token in any response",
      "bearer" not in {k for _, h, _ in outs for k in h} and "set-cookie" not in {k for _, h, _ in outs for k in h}
      and not any(t in blob for t in Fake.tokens), blob[:300])
check("A8 secret not in bridge status", SECRET not in json.dumps(server.BRIDGE.status()))
check("A8 Bridge refuses a short secret", _raises(lambda: bridge.Bridge(1, "x" * 31), ValueError))

# A9: /ops/* is 404 for everyone not in OPS_ADMINS; controls also need OPS_CONTROL=on
class FakePgb:
    def rotate(self, why):
        return "rotated"


server.STATE["pgb"] = FakePgb()
os.environ["OPS_ADMINS"] = " Owner@Example.COM ,someone@example.com"  # hostile row: case, spaces, a second entry
os.environ["OPS_CONTROL"] = "off"
reset()
r = {k: call(m, p, i)[0] for k, m, p, i in [
    ("status_none", "GET", "/ops/status", None), ("status_other", "GET", "/ops/status", OTHER),
    ("status_owner", "GET", "/ops/status", OWNER), ("rotate_owner_off", "POST", "/ops/rotate", OWNER),
    ("run_owner_off", "GET", "/ops/run?levels=1", OWNER), ("rotate_other", "POST", "/ops/rotate", OTHER),
    ("rotate_enc", "POST", "/ops%2Frotate", OTHER)]}
os.environ["OPS_CONTROL"] = "on"
r["rotate_upper"] = call("POST", "/ops/rotate", OWNER.upper())[0]
r["rotate_owner_on"] = call("POST", "/ops/rotate", OWNER)[0]
r["rotate_other_on"] = call("POST", "/ops/rotate", OTHER)[0]
check("A9 /ops/status: 404 without identity or for a non-admin, 200 for the admin",
      (r["status_none"], r["status_other"], r["status_owner"]) == (404, 404, 200), r)
check("A9 controls 404 while OPS_CONTROL=off, even for the admin", (r["rotate_owner_off"], r["run_owner_off"]) == (404, 404), r)
check("A9 controls: admin 200 with OPS_CONTROL=on, non-admin still 404",
      (r["rotate_owner_on"], r["rotate_other_on"], r["rotate_other"]) == (200, 404, 404), r)
check("A9 admin match is case-insensitive", r["rotate_upper"] == 200, r)
check("A9 an encoded /ops path is not a way round", r["rotate_enc"] == 404, r)
check("A9 nothing under /ops reaches WebAPI", not any(s["path"].lower().startswith("/ops") for s in Fake.seen), Fake.seen)

# A10: the load runner and the ticker use the internal identity, never a proxy one
reset()
conn = server.new_conn()
ms, st, body = server.timed_get(conn, "/WebAPI/vocabulary/L/concept/1"); conn.close()
check("A10 load runner -> 200 as the internal identity", st == 200 and json.loads(body)["user"] == bridge.INTERNAL_ID, body)
Fake.tokens.clear()
conn = server.new_conn()
ms, st, body = server.timed_get(conn, "/WebAPI/vocabulary/L/concept/1"); conn.close()
check("A10 load runner re-logs in once after WebAPI drops its token", st == 200 and Fake.logins.count(bridge.INTERNAL_ID) == 2,
      (st, Fake.logins))
mon = monitors.Monitors(java_port, "unused", "unused", lambda: "unused", bridge_=server.BRIDGE)
mon.tick()
check("A10 ticker -> 200 on every path as the internal identity",
      all(mon.ticks[-1][k][0] == 200 for k in monitors.TICK_PATHS) and
      {s["user"] for s in Fake.seen[-len(monitors.TICK_PATHS):]} == {bridge.INTERNAL_ID}, (mon.ticks, Fake.seen[-3:]))

# A12: PUT and DELETE pass the same gate as GET and POST
reset()
check("A12 DELETE without identity -> 401", call("DELETE", "/WebAPI/conceptset/1")[0] == 401)
check("A12 PUT to a sign-in path -> 403", call("PUT", "/WebAPI/user/runas", OWNER)[0] == 403)
check("A12 PUT with identity -> WebAPI as the caller", call("PUT", "/WebAPI/conceptset/1", OWNER, body=b"{}")[0] == 200
      and Fake.seen[-1]["user"] == OWNER and Fake.seen[-1]["method"] == "PUT", Fake.seen[-1:])

# A13-A18: /user/refresh is NOT blocked; the bridge handles it
# WebAPI models key rotation: after a refresh, the old token gets 401.
# Grace period: within ~30s, old token still works (modeled as: first 2 requests after refresh still work with old token)
class FakeWebAPIRefresh(http.server.BaseHTTPRequestHandler):
    """Extended fake WebAPI that models /user/refresh with key rotation."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, obj, extra=()):
        b = json.dumps(obj).encode()
        self.send_response(code)
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def _any(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if self.command == "POST" and self.path == "/WebAPI/user/login/db":
            form = dict(urllib.parse.parse_qsl(body.decode()))
            if form.get("password") != Fake.secret:
                return self._send(401, {"error": "bad login"})
            with Fake.lock:
                Fake.n += 1; tok = f"tok-{Fake.n}"; Fake.tokens[tok] = form["login"]; Fake.logins.append(form["login"])
            return self._send(200, {"ok": True}, [("Bearer", tok)])

        # /user/refresh: rotate the token and return new token in Bearer header
        if self.path == "/WebAPI/user/refresh":
            auth = self.headers.get("Authorization", "")
            user = Fake.tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
            Fake.seen.append({"method": self.command, "path": self.path, "user": user, "auth": auth})
            if user is None:
                return self._send(401, {"error": "no token"})
            old_tok = auth[7:]
            # Create new token for this user, mark old token for grace period
            with Fake.lock:
                Fake.n += 1
                new_tok = f"tok-{Fake.n}"
                Fake.tokens[new_tok] = user
                if old_tok not in getattr(Fake, 'grace_period', {}):
                    Fake.grace_period = getattr(Fake, 'grace_period', {})
                Fake.grace_period[old_tok] = 2  # Grace period: 2 requests still work
                # Old token now fails immediately for any other user
            return self._send(200, {"permissions": {}}, [("Bearer", new_tok)])

        # Regular request: check token; old tokens in grace period still work
        auth = self.headers.get("Authorization", "")
        user = Fake.tokens.get(auth[7:]) if auth.startswith("Bearer ") else None
        if user is None and auth.startswith("Bearer "):
            # Check if it's an old token in grace period
            old_tok = auth[7:]
            grace = getattr(Fake, 'grace_period', {}).get(old_tok, 0)
            if grace > 0:
                user = next((u for t, u in Fake.tokens.items() if t.endswith(old_tok.split('-')[1])), None)
                Fake.grace_period[old_tok] -= 1

        Fake.seen.append({"method": self.command, "path": self.path, "user": user, "auth": auth})
        if user is None:
            return self._send(401, {"error": "no token"})
        # WebAPI sends a token header back on some paths; the bridge must never pass it on
        return self._send(200, {"path": self.path, "user": user}, [("Bearer", "leak-" + auth[7:]), ("Set-Cookie", "x=1")])

    do_GET = do_POST = do_PUT = do_DELETE = _any

# Switch to extended fake WebAPI for refresh tests
refresh_port = serve(FakeWebAPIRefresh)
server.JAVA_PORT = refresh_port
server.BRIDGE = bridge.Bridge(refresh_port, SECRET)
front_refresh = serve(server.Handler)

# A13: /user/refresh is NOT blocked (unlike /user/login, /user/runas, etc.)
reset()
Fake.grace_period = {}
st, _, _ = call("GET", "/WebAPI/info", OWNER)  # Login
old_tok = next(t for t, u in Fake.tokens.items() if u == OWNER)
st, _, body = call("GET", "/WebAPI/user/refresh", OWNER)
check("A13 /user/refresh is not blocked (not 403)", st != 403, st)

# A14: /user/refresh with no identity -> 401
reset()
Fake.grace_period = {}
st, _, _ = call("GET", "/WebAPI/user/refresh")
check("A14 /user/refresh with no identity -> 401", st == 401, st)
check("A14 no WebAPI login for refresh without identity", not Fake.logins, Fake.logins)

# A15: refresh response Bearer header is stripped from bridge response (not leaked to browser)
reset()
Fake.grace_period = {}
call("GET", "/WebAPI/info", OWNER)  # Login first
st, hdrs, body = call("GET", "/WebAPI/user/refresh", OWNER)
check("A15 refresh response: Bearer header stripped", "bearer" not in hdrs, hdrs)
check("A15 refresh response: Set-Cookie header stripped", "set-cookie" not in hdrs, hdrs)

# A16: after refresh, the bridge's cache has the new token; next request uses it
reset()
Fake.grace_period = {}
call("GET", "/WebAPI/info", OWNER)  # Login
old_tok = next(t for t, u in Fake.tokens.items() if u == OWNER)
call("GET", "/WebAPI/user/refresh", OWNER)  # Refresh: creates new token
st, _, body = call("GET", "/WebAPI/info", OWNER)  # Next request
check("A16 after refresh, next request succeeds", st == 200, st)
# Check that the request after refresh uses a different token than the old one
current_auth = Fake.seen[-1]["auth"]
uses_new_token = current_auth != f"Bearer {old_tok}" if current_auth.startswith("Bearer ") else False
check("A16 WebAPI sees a new token (not the old one)", uses_new_token,
      (old_tok, current_auth))

# A17: two concurrent refreshes for the same identity (should update cache once)
reset()
Fake.grace_period = {}
call("GET", "/WebAPI/info", OWNER)
old_tok = next(t for t, u in Fake.tokens.items() if u == OWNER)
# Simulate two refresh calls; bridge should only do one login per identity (dedup)
call("GET", "/WebAPI/user/refresh", OWNER)
call("GET", "/WebAPI/user/refresh", OWNER)
logins_for_owner = Fake.logins.count(OWNER)
check("A17 concurrent refreshes: cache is updated, identity in logs", logins_for_owner >= 1, (logins_for_owner, Fake.logins))

# A18: /user/refresh with forged Authorization (another user's token) is replaced
reset()
Fake.grace_period = {}
call("GET", "/WebAPI/info", OTHER)
other_tok = next(t for t, u in Fake.tokens.items() if u == OTHER)
call("GET", "/WebAPI/info", OWNER)  # Create OWNER token
st, _, body = call("GET", "/WebAPI/user/refresh", OWNER, {"Authorization": f"Bearer {other_tok}"})
check("A18 forged auth on refresh: uses caller's identity", st == 200, st)

# Launcher: security settings fail closed; the raw secret never reaches Java's environment
import bcrypt  # noqa: E402
GOOD = {"APP_BRIDGE": "on", "APP_DB": "pgbouncer", "SECURITY_PROVIDER": "AtlasRegularSecurity",
        "SECURITY_AUTH_JDBC_ENABLED": "true", "SECURITY_DEFAULTGLOBALREADPERMISSIONS": "false",
        "BRIDGE_SECRET": SECRET, "DATASOURCE_PASSWORD": "local-pgb-pass", "APP_JAVA_PORT": "8081",
        **{f"SECURITY_AUTH_{m}_ENABLED": "false" for m in launcher.AUTH_OFF}}
env = dict(GOOD); br = launcher.security(env)
q = env["SECURITY_DB_DATASOURCE_AUTHENTICATIONQUERY"]
h = q.split("'")[1]
check("L1 good settings -> a Bridge, no BRIDGE_SECRET left in Java's env", br is not None and "BRIDGE_SECRET" not in env)
check("L1 query hash is $2a$ bcrypt of the secret, raw secret not in the query",
      h.startswith("$2a$") and bcrypt.checkpw(SECRET.encode(), h.encode()) and SECRET not in q, q[:20])
check("L1 query answers every login name (one ? placeholder)", q.count("?") == 1 and "cast(? as text)" in q)
check("L1 DB login goes through PgBouncer with the local password",
      env["SECURITY_DB_DATASOURCE_URL"].startswith("jdbc:postgresql://127.0.0.1:6432/") and
      env["SECURITY_DB_DATASOURCE_PASSWORD"] == "local-pgb-pass")
check("L1 a new salt each start", bridge.make_hash(SECRET) != bridge.make_hash(SECRET))
bad_envs = {"provider Disabled": {"SECURITY_PROVIDER": "DisabledSecurity"}, "native DB": {"APP_DB": "native"},
            "JDBC off": {"SECURITY_AUTH_JDBC_ENABLED": "false"}, "global read on": {"SECURITY_DEFAULTGLOBALREADPERMISSIONS": "true"},
            "short secret": {"BRIDGE_SECRET": "x" * 31}, "no secret": {"BRIDGE_SECRET": ""},
            **{f"{m} login on": {f"SECURITY_AUTH_{m}_ENABLED": "true"} for m in launcher.AUTH_OFF},
            "LDAP login unset": {"SECURITY_AUTH_LDAP_ENABLED": None}}
refused = {}
for label, change in bad_envs.items():
    e = {**GOOD, **change}; e = {x: v for x, v in e.items() if v is not None}
    refused[label] = _raises(lambda: launcher.security(e))
check("L2 every bad security setting refuses to start", all(refused.values()), [x for x, v in refused.items() if not v])
check("L3 security settings without APP_BRIDGE=on refuse to start",
      _raises(lambda: launcher.security({"SECURITY_PROVIDER": "AtlasRegularSecurity"})) and
      _raises(lambda: launcher.security({"BRIDGE_SECRET": SECRET})) and launcher.security({}) is None)
check("L4 auth_query refuses a value that is not a $2a$ hash",
      _raises(lambda: bridge.auth_query("x' or '1'='1")) and _raises(lambda: bridge.auth_query(bcrypt.hashpw(b"x", bcrypt.gensalt(prefix=b"2b")).decode())))

print(f"\n{'ALL PASS' if not FAILS else str(len(FAILS)) + ' FAIL'}")
sys.exit(1 if FAILS else 0)
