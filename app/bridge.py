"""Trusted-header bridge: WebAPI security on, behind the Databricks Apps proxy.

The Apps proxy signs every user in with workspace SSO, sets X-Forwarded-Email, overwrites forged X-Forwarded-*
values and strips Authorization (checked live). The bridge maps that identity to a WebAPI login:
  identity  X-Forwarded-Email, else X-Forwarded-User; lowercased; only an email-like name or a UUID passes, else 401
  login     POST 127.0.0.1:JAVA_PORT/WebAPI/user/login/db with login=<identity>, password=<bridge secret>.
            WebAPI's DB realm checks the secret with bcrypt (its query returns one hash for every login), so only
            code that holds the secret can log in. WebAPI's own roles and per-source rights decide what a login sees.
  token     read from the 'Bearer' response header, cached per identity, sent as Authorization on every forwarded
            request (a client Authorization is always replaced); one fresh login after a 401
  blocked   WebAPI's own login, run-as, OAuth, SAML, CAS, and logout paths: 403 from outside
  refresh   GET /WebAPI/user/refresh as the identity; the new token from the Bearer header is cached,
            the header and body are stripped from the bridge's response so the token never leaves this process
  refused   a path that is ambiguous after one percent-decode (';', '\\', '%', '//', '.' or '..' segments): 400
Internal callers (ticker, load runner) use INTERNAL_ID, which no proxy identity can match (it holds ':').
The secret and the tokens stay in this process: never in a log line, a response body or a response header.
"""
import http.client, re, threading, urllib.parse

INTERNAL_ID = "svc:monitor"
LOGIN_PATH = "/WebAPI/user/login/db"
BLOCKED = ("/webapi/user/login", "/webapi/user/runas", "/webapi/user/oauth", "/webapi/user/saml",
           "/webapi/user/cas", "/webapi/user/logout")
REFRESH_PATH = "/webapi/user/refresh"
_EMAIL = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)+")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_HASH = re.compile(r"\$2a\$\d\d\$[./0-9A-Za-z]{53}")
STRIP_RESPONSE = {"bearer", "set-cookie"}


def identity(headers):
    """The caller's normalized identity from the proxy headers, or None."""
    raw = headers.get("X-Forwarded-Email") or headers.get("X-Forwarded-User") or ""
    name = raw.strip().lower()
    return name if _EMAIL.fullmatch(name) or _UUID.fullmatch(name) else None


def normalize_path(target):
    """The decoded path of a request target, or None when it is ambiguous (the caller answers 400)."""
    if not target.startswith("/"):
        return None
    path = urllib.parse.unquote(target.split("?", 1)[0])
    if any(c in path for c in ";\\%") or "//" in path:
        return None
    if any(seg in (".", "..") for seg in path.split("/")):
        return None
    return path


def blocked(path):
    """True for WebAPI's own sign-in paths (checked on the normalized path, case-insensitive)."""
    p = path.lower().rstrip("/")
    return any(p == b or p.startswith(b + "/") for b in BLOCKED)


def make_hash(secret):
    """bcrypt hash ($2a$, which Spring Security 4.2 accepts) of the bridge secret, new salt each start."""
    import bcrypt
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt(rounds=10, prefix=b"2a")).decode()


def auth_query(hash_):
    """WebAPI's DB-realm query: the same hash for every login name."""
    if not _HASH.fullmatch(hash_):
        raise ValueError("not a $2a$ bcrypt hash")
    return f"select '{hash_}' where cast(? as text) is not null"


class Bridge:
    def __init__(self, java_port, secret, timeout=120):
        if not secret or len(secret) < 32:
            raise ValueError("bridge secret missing or shorter than 32 characters")
        self.java_port, self._secret, self.timeout = java_port, secret, timeout
        self._tokens, self._locks, self._lock = {}, {}, threading.Lock()
        self.stats = {"logins": 0, "login_failures": 0, "relogins": 0, "refreshes": 0, "last_failure": None}

    def _conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.java_port, timeout=self.timeout)

    def _login(self, ident):
        body = urllib.parse.urlencode({"login": ident, "password": self._secret})
        c = self._conn()
        try:
            c.request("POST", LOGIN_PATH, body, {"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse(); r.read()
            tok = r.getheader("Bearer")
        finally:
            c.close()
        if r.status != 200 or not tok:
            self.stats["login_failures"] += 1
            self.stats["last_failure"] = f"HTTP {r.status}"
            raise PermissionError(f"WebAPI DB login refused: HTTP {r.status}")
        self.stats["logins"] += 1
        return tok

    def token(self, ident, fresh=False):
        with self._lock:
            lk = self._locks.setdefault(ident, threading.Lock())
        with lk:  # one login per identity at a time; the others wait and reuse it
            if fresh or ident not in self._tokens:
                self._tokens[ident] = self._login(ident)
            return self._tokens[ident]

    def drop(self, ident, tok):
        with self._lock:
            if self._tokens.get(ident) == tok:
                del self._tokens[ident]

    def _refresh(self, ident):
        """Refresh the token for ident by calling /user/refresh, cache the new token, return (status, hdrs, body).

        WebAPI's /user/refresh returns the user's permissions JSON in the body (only a Bearer header has the token).
        If WebAPI answers 401 (cached token expired or key rotated away), drop the token, do one fresh login,
        then try refresh once more. Never retry after a second 401.
        """
        tok = self.token(ident)  # Get current token; blocks on concurrent refresh for same identity
        for attempt in (0, 1):
            out = {"Authorization": f"Bearer {tok}"}
            c = self._conn()
            try:
                c.request("GET", "/WebAPI/user/refresh", b"", out)
                r = c.getresponse(); data = r.read()
                hdrs = [(k, v) for k, v in r.getheaders() if k.lower() not in STRIP_RESPONSE]
                new_tok = r.getheader("Bearer")
            finally:
                c.close()
            if r.status != 401 or attempt:  # On 401, only retry once
                if r.status == 200 and new_tok:
                    with self._lock:
                        self._tokens[ident] = new_tok
                    self.stats["refreshes"] += 1
                return r.status, hdrs, data
            # 401: drop cached token and get a fresh one for the retry
            self.drop(ident, tok)
            tok = self.token(ident, fresh=True)
        return r.status, hdrs, data

    def request(self, method, target, body, headers, ident):
        """Forward one request to WebAPI as ident. Returns (status, [(header, value)], body bytes).

        If target is /user/refresh, calls _refresh which updates the cache with the new token.
        Path matching is case-insensitive and ignores trailing slashes.
        """
        path = normalize_path(target) or target
        if path.lower().rstrip("/") == REFRESH_PATH:
            return self._refresh(ident)

        out = {k: v for k, v in headers.items() if k.lower() != "authorization"}
        for attempt in (0, 1):
            tok = self.token(ident)
            out["Authorization"] = f"Bearer {tok}"
            c = self._conn()
            try:
                c.request(method, target, body, out)
                r = c.getresponse(); data = r.read()
                hdrs = [(k, v) for k, v in r.getheaders() if k.lower() not in STRIP_RESPONSE]
            finally:
                c.close()
            if r.status != 401 or attempt:
                return r.status, hdrs, data
            self.drop(ident, tok); self.stats["relogins"] += 1
        return r.status, hdrs, data

    def status(self):
        return {"identities": len(self._tokens), **self.stats}
