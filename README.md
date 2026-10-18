# OHDSI WebAPI on Lakebase, as a Databricks App

This repo runs OHDSI WebAPI 2.15.2 as a Databricks App. WebAPI keeps its own tables and reads an OMOP vocabulary in
Lakebase, the managed Postgres in Databricks. It logs in as the app's service principal (the app's Databricks
identity), so no database password is stored. The only password is a local one between WebAPI and PgBouncer, inside
the app. Users sign in with workspace single sign-on through the Databricks Apps proxy, and WebAPI security is on:
each user gets only the WebAPI rights an admin granted.

How the database login works: WebAPI connects to PgBouncer 1.26.1, a connection pooler, on 127.0.0.1:6432 inside the
app. WebAPI knows only a local PgBouncer password. PgBouncer logs in to Lakebase with an OAuth token for the app's
service principal. A small refresher (`app/pgb.py`) mints a new token every 900 seconds, rewrites PgBouncer's config
and sends a reload. Open sessions stay open, and new logins use the new token. WebAPI itself is unchanged.

```mermaid
sequenceDiagram
    participant W as WebAPI
    participant P as PgBouncer (127.0.0.1:6432)
    participant R as Refresher
    participant L as Lakebase
    W->>P: log in with the local password
    P->>L: log in as the app's service principal (OAuth token)
    loop every 900 s
        R->>R: mint a new token
        R->>P: rewrite config, then SIGHUP (reload)
        Note over P,L: open sessions stay open, new logins use the new token
    end
    Note over R: a failed refresh keeps the old config and retries every 30 s
```

## Security

The Databricks Apps proxy signs every user in (workspace single sign-on, or an OAuth token for scripts) and refuses
anyone without CAN USE on the app. It passes the user's identity to the app in `X-Forwarded-Email`, replaces any value
a client sends in that header, and removes `Authorization`. So WebAPI's own token cannot travel from the browser.

`app/bridge.py` connects the two. For each request, the front server reads the user from `X-Forwarded-Email` (a
service principal arrives as its application id). The bridge logs that user in to WebAPI's database login
(`/WebAPI/user/login/db`) with a bridge secret that only the app holds, keeps WebAPI's token per user, and sends it to
WebAPI. WebAPI then applies its own roles and per-source rights to that user.

```mermaid
sequenceDiagram
    participant B as Browser or script
    participant X as Databricks Apps proxy
    participant S as server.py + bridge.py
    participant W as WebAPI
    B->>X: request (workspace sign-in or OAuth token)
    X->>S: request + X-Forwarded-Email (forged value replaced, Authorization removed)
    Note over S: no identity: 401. WebAPI sign-in paths: 403
    S->>W: first request of this user: POST /user/login/db (user, bridge secret)
    W-->>S: token for this user (kept in the app)
    S->>W: request + that user's token
    W-->>S: answer, by that user's WebAPI rights
    S-->>B: answer (token headers removed)
```

What the code enforces (each item has an offline test, see Tests):

- A request without a proxy identity gets 401 and never reaches WebAPI.
- WebAPI's own sign-in paths (`/user/login`, `/user/runas`, `/user/oauth`, `/user/saml`, `/user/cas`, `/user/refresh`,
  `/user/logout`) get 403 from outside, in every spelling the tests try (case, trailing `/`, `%2F`, double encoding,
  `;`, `//`, `/./`, `/../`). A path that is ambiguous after one decode gets 400.
- A client's `Authorization` header is always replaced. Each user has their own WebAPI token. After a WebAPI 401 the
  bridge logs in one more time, never in a loop.
- WebAPI's token and cookie headers are removed from every answer. The bridge secret is in no log line and no answer.
- `/ops/*` answers only the identities in `OPS_ADMINS` (404 for everyone else). The controls (`/ops/run`,
  `/ops/rotate`, `/ops/terminate`) also need `OPS_CONTROL=on`.
- The in-app ticker and load runner log in as `svc:monitor`, a name no proxy identity can have.
- The launcher refuses to start unless `SECURITY_PROVIDER=AtlasRegularSecurity`, only the database login is on, and
  global read rights for new users are off. At each start it makes a new bcrypt hash of the bridge secret (WebAPI's
  database-login query returns that hash for any user name) and keeps the raw secret out of Java's environment.

WebAPI rules you meet once (read from the pinned image's migrations, then checked live):

- The first admin is set by SQL. After that, admins grant roles by REST.
- An admin has no rights on a new source. WebAPI makes a role `Source user (<key>)` for each source; add users to it.
- An admin can create roles and add users to roles by REST (`PUT /WebAPI/role/{roleId}/users/{userId}`), but can add
  rights by REST only to the public role. So a narrow role gets its rights by SQL (`tools/webapi_admin.py role-perm`).
- Workspace groups are not mapped to WebAPI roles. A user appears in WebAPI after their first request.

## How the code is laid out

```text
webapi-on-lakebase/
├── app/                         # runs inside the Databricks App
│   ├── launcher.py              # entry point: gets Java and WebAPI, starts PgBouncer, checks security, starts WebAPI
│   ├── pgb.py                   # PgBouncer process and the token refresher
│   ├── bridge.py                # proxy identity -> WebAPI login, and the request gate
│   ├── server.py                # front server on the app port: /WebAPI/... (through the bridge) and /ops/...
│   ├── monitors.py              # every 60 s: checks WebAPI, counts Lakebase sessions
│   ├── app.yaml.template        # app settings, with __PLACEHOLDERS__
│   └── requirements.txt
├── pgbouncer/Dockerfile.static  # builds PgBouncer 1.26.1 as one static binary
├── tools/                       # runs on your laptop
│   ├── render.py                # checks config, security settings and binary hash, stages the app outside the repo
│   ├── setup_and_deploy.sh      # Postgres role and grants, 3 secrets, upload, deploy
│   ├── webapi_admin.py          # first admin, the vocabulary source, roles, checks
│   └── teardown.sh              # removes what setup made, then checks
├── tests/                       # offline: test_app.py, test_bridge.py, test_render.py
└── config.env.example           # your settings
```

What happens when the app starts (`app/launcher.py`, `main`):

```text
main
  fetch_jre                  # Temurin 8 JRE, SHA-256 checked
  fetch_webapi               # WebAPI 2.15.2 image from Docker Hub, manifest and every layer checked by digest
  start_pgbouncer            # APP_DB=pgbouncer
    check the binary's SHA-256 against PGB_SHA256   # refuses to start if unset or different
    PgBouncer.start
      mint a token, write pgbouncer.ini and the userlist (0600)
      run PgBouncer on 127.0.0.1:6432, wait until it listens
      start the refresher loop
  security                   # APP_BRIDGE=on: refuses any other security setting
    bridge_env               # new bcrypt hash of BRIDGE_SECRET -> WebAPI's database-login query; secret removed
  start WebAPI               # Java on 127.0.0.1:8081, local password, URL 127.0.0.1:6432/webapi
  Monitors.start             # ticker and session sampler, every 60 s, through the bridge
  server.serve               # app port: /WebAPI through the bridge, /ops for OPS_ADMINS
```

## What was tested, and what this copy is

The tested build ran in one Databricks workspace, on a Lakebase project with autoscaling 1-8 CU.

With WebAPI security off (the earlier runs):

- First start on an empty schema: Flyway created WebAPI's schema and ran its migrations (202 rows in
  `schema_history`, 0 failed). WebAPI was ready 58.0 s after the launcher started.
- Load: 1, 8 and 32 users, each with a 30 s warm-up and 180 s measured, and one forced token change per level.
  3,360 samples, every response HTTP 200, 0 client errors. A first run failed its pass rule with 1 client error:
  the first search on a vocabulary that no search had used before hit the load client's 120 s timeout.
- A simulated 3-day connection close: the service principal ended its own 57 Lakebase sessions at once. Every
  response stayed HTTP 200; the next full click path started 0.33 s later, with no restart. The real close at
  Lakebase's 3-day maximum connection life may look different.
- 6 hours with no load: 360 of 360 one-minute checks HTTP 200, 24 timer token changes, 0 refresh errors, and 0
  login-failed or JWT (token format) lines in PgBouncer's log.
- Stop and start of the app: token, then PgBouncer, then Java, in that order. Flyway added 0 rows, and WebAPI
  started in 23.956 s.
- The local PgBouncer password was in 0 of 259 saved logs and responses.

With WebAPI security on (this design, deployed again on an empty schema):

- Flyway: 202 rows, 202 succeeded. WebAPI was ready 53.8 s after the launcher started.
- Through the proxy, WebAPI saw the signed-in user's email. Forged `X-Forwarded-Email` and `X-Forwarded-User` headers
  from the client changed nothing.
- A second identity (a service principal given CAN USE on the app) arrived as its application id. It got 403 on the
  vocabulary source until an admin added it to the source's role, then 200.
- 8 WebAPI sign-in paths, among them `/user/Login/db` and `/user%2Flogin/db`, got 403 through the app. 4 `/ops`
  paths got 404 for an identity that is not in `OPS_ADMINS`.
- Stop and start: the next requests got 200 with no manual step. Roles and the source were kept, Flyway added 0
  rows, and WebAPI was ready after 148.0 s.
- 34 one-minute checks over 33.0 minutes, through the bridge as `svc:monitor`: all HTTP 200, 3 timer token changes,
  0 refresh errors.
- 0 tokens, 0 copies of the local password and 0 bridge secret values in 476 saved files and in the app log.
- Offline: 39 checks against a fake WebAPI pass, and 37 of 37 deliberate code breaks each made a check fail. WebAPI's
  own BCrypt (spring-security-crypto 4.2.3) accepts the launcher's `$2a$` hash and refuses a `$2b$` hash.

The tested build used the test project's own names. This copy replaces them with settings in `config.env`, renames
the operations path to `/ops`, and drops a search plug-in that is not part of this repo. It also drops the SQL tools
for adding a source: with security on, `tools/webapi_admin.py source-add` uses WebAPI's REST path, which also makes
the source's role. The load runner's third step is `ancestorAndDescendant`, because WebAPI's per-source role has no
right for `/descendants`. That was checked live once, for a service principal in the source's role:
`ancestorAndDescendant` 200, `descendants` 403.

This copy, deployed as committed to a new app on the same Lakebase project (autoscaling 1-8 CU), with
`config.env` filled in and no code changed:

- `render.py` and `setup_and_deploy.sh` worked as written. Flyway: 202 rows, 202 succeeded.
- The 8 calls of step 5 below worked in that order, plus `role-add "Source user (<SOURCE_KEY>)" svc:monitor`.
  `forged` printed the signed-in user's login twice. 8 WebAPI sign-in paths got 403 through the app.
- Load with security on: 1, 8 and 32 users, each with a 30 s warm-up and 180 s measured, one forced token change per
  level, click path search, concept, `ancestorAndDescendant`, all through the bridge. 2,898 samples, every response
  HTTP 200, 0 client errors, 0 bridge login failures, 0 PgBouncer login-failed or JWT lines. Click paths per second:
  2.26 at 8 users and 2.19 at 32 users (security off: 2.24 and 2.14). At 1 user: 0.36 (security off: 1.16),
  because some first searches were still cold (slowest 33.2 s). Before that run, one 60 s warm-up at 1 user
  (not measured) had 1 client timeout on the first search of a cold vocabulary.
- 0 tokens and 0 copies of the local password in the saved results and in the app log (468 lines).

## What was not tested

- The ATLAS web app in a browser. The tested requests were REST calls through the proxy and from inside the app.
- A long run (hours) with security on, a simulated connection close with security on, and more than 32 users.
- Changing the bridge secret while users are signed in.
- A real close at the 3-day maximum connection life (only simulated, above).
- Rotation of the app service principal's own credentials.
- Downloads staged in a Unity Catalog volume. The launcher fetches the JRE and the WebAPI image from the internet.

## Why PgBouncer 1.26.1 or later

PgBouncer 1.25 caps passwords at 2,048 characters and cuts longer ones. A Lakebase OAuth token is about 2,250
characters, so the cut token is no longer valid and the login fails. PgBouncer 1.26.0 raised the cap. 1.26.1 also
fixes CVE-2026-107350: versions 1.17.0 through 1.26.0 processed a second StartupMessage sent during SCRAM login,
and this setup uses `auth_type = scram-sha-256`.

## What you need

- A Databricks workspace with Databricks Apps, a Lakebase project, and the Databricks CLI logged in to a profile.
- Your OMOP vocabulary tables or views in one schema on that Lakebase project.
- You are the Lakebase project owner. The scripts log in as you to create the app's role and grants, and to set the
  first WebAPI admin.
- `psql`, Python 3 with `psycopg[binary]` (for `webapi_admin.py grant` and `role-perm`), and Docker (to build
  PgBouncer).

## Steps

```mermaid
flowchart LR
    A[build PgBouncer<br/>Dockerfile.static] --> B[create the app<br/>fill config.env]
    B --> C[render.py<br/>checks and stage]
    C --> D[setup_and_deploy.sh<br/>role, secrets, deploy]
    D --> E[webapi_admin.py<br/>admin, source, roles]
    E --> F[GET /ops/status]
```

1. Build PgBouncer as one static linux/amd64 binary. The build checks the source tarball's published SHA-256.

   ```
   docker buildx build --platform linux/amd64 -f pgbouncer/Dockerfile.static --output type=local,dest=build pgbouncer
   shasum -a 256 build/pgbouncer-1.26.1-linux-amd64-static
   ```

2. Create the app: `databricks apps create <app name> --profile <profile>`. This starts the app compute, which is
   billable, and can take more than 2 minutes.

3. Copy `config.env.example` to `config.env` and fill it in. `PGB_SHA256` is the hash of the binary you built in
   step 1. `APP_URL` is the app's URL (`databricks apps get <app name> -o json`). Put your email in `OPS_ADMINS`.
   git ignores `config.env`.

4. Render and deploy. `tools/render.py` stages the app in `~/.webapi-on-lakebase/stage`, checks the binary's hash,
   and refuses a template where security is not on. `tools/setup_and_deploy.sh` creates the service principal's
   Postgres role and grants and the three app secrets, then deploys. It makes a new bridge secret on each run, and no
   copy stays on your machine. Read it first.

   ```
   python3 -I tools/render.py
   bash tools/setup_and_deploy.sh
   ```

5. Set up WebAPI's rights, in this order. Each line is one call. Your WebAPI user appears with your first request.

   ```
   python3 -I tools/webapi_admin.py me                                   # your login; makes your WebAPI user
   python3 -I tools/webapi_admin.py grant <your email> admin             # the first admin (SQL)
   python3 -I tools/webapi_admin.py source-add                           # source SOURCE_KEY on VOCAB_SCHEMA
   python3 -I tools/webapi_admin.py role-add "Source user (<SOURCE_KEY>)" <your email>
   python3 -I tools/webapi_admin.py role-create Monitor                  # a narrow role for the in-app ticker
   python3 -I tools/webapi_admin.py role-perm Monitor conceptset:get
   python3 -I tools/webapi_admin.py role-add Monitor svc:monitor
   python3 -I tools/webapi_admin.py forged                               # must print your login, not the forged one
   ```

   If you set `TICK_CONCEPT_ID` or use the load runner, also add `svc:monitor` to the source's role:
   `role-add "Source user (<SOURCE_KEY>)" svc:monitor`. For each other user: they open the app once, then you add
   them to the roles they need, for example `role-add "Source user (<SOURCE_KEY>)" <their email>`.

6. Check `GET <app url>/ops/status`: the launcher events (token, PgBouncer listening, bridge, Java start),
   `cold_done` and the bridge's login counts. `GET <app url>/ops/conn` shows the refresher, the in-app checks every
   60 s, and the Lakebase session counts. The in-app load runner needs your own `queries.json` (set `QUERIES_JSON`)
   and `OPS_CONTROL=on`; without them `/ops/run` answers 404.

## Tests

```
pip install -r app/requirements.txt
python3 -I tests/test_app.py
python3 -I tests/test_bridge.py
python3 -I tests/test_render.py
```

All three run offline, with no Databricks, Lakebase or Java. `tests/test_bridge.py` runs the real front server and
bridge against a fake WebAPI, with checks for each item of the security list above.

## Teardown

Stop the app, then run `bash tools/teardown.sh`. It removes WebAPI's schema, the service principal's Postgres role,
the app and its service principal, the secret scope (with the bridge secret), the app's workspace folder and the
local PgBouncer password file, then checks each one.

## License

Apache License 2.0. See `LICENSE`.

I work at Databricks. All opinions are my own.
