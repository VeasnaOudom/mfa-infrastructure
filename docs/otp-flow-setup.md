# OTP flow pre-configuration

Everything the PrivacyIDEA OTP flow needs, in the order it has to be done, on both sides. Values shown
are the ones this stack actually uses; substitute the host and realm names per environment.

Assumes the stack is already running (`mise run start`). For *why* any of this is necessary rather
than incidental, see `AGENTS.md`.

---

## 0. Order of operations

The two systems point at each other, so the shared secret and the resolver client have to exist before
either side can be finished.

1. Keycloak — realm, SMTP, client for the resolver
2. privacyIDEA — resolver pointing at that client
3. Generate the shared webhook secret and put it in **three** places
4. Keycloak — authentication flow and both authenticator configs
5. privacyIDEA — event handler posting to `/ipn`
6. Per user — enroll a token

---

## 1. The shared secret

One value, three locations. All three must be byte-identical.

| # | Where | Why |
| --- | --- | --- |
| 1 | `webhookSecret` on the **EDC MFA Channels** authenticator config | what Keycloak expects |
| 2 | `PRIVACYIDEA_WEBHOOK_SECRET` in `.env` | fallback source, also used by the compose env |
| 3 | the `URL` option of the **privacyIDEA** event handler | what privacyIDEA sends |

Generate one:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Resolution order in `PrivacyIdeaSettings` is **admin config first, then environment variable**, so
location 1 wins if they disagree. A mismatch is not silent — `/ipn` answers `401` and logs
`method=secretValid status=REJECTED`.

> An empty secret used to mean "skip the check". It now fails closed: with no secret configured every
> `/ipn` request is rejected. If you add `PRIVACYIDEA_WEBHOOK_SECRET` to `.env.j2` and regenerate
> before seeding Vault, expect `401` until the Vault key exists.

---

## 2. Keycloak

### 2.1 Realm

* Realm name: **`EDC`** (renamed from `mfa`).
* Users come from **LDAP / Active Directory** federation, not from local accounts.
  * `editMode` is `Writable` and `syncRegistrations` is `true`, so **user writes reach AD**. Do not
    create throwaway users in this realm to test.

### 2.2 SMTP

**Realm settings → Email**

| Field | Value |
| --- | --- |
| Host | `smtp4dev` |
| Port | `25` |
| From | `mfa-service@crosswired.me` |
| SSL / STARTTLS | off |
| Auth | none |

`smtp4dev` is the container-network name, not a public host. The web inbox is at
`https://mfa-mail.crosswired.me`.

### 2.3 Client for the privacyIDEA resolver

privacyIDEA reads users from Keycloak over the admin REST API, so it needs a confidential client.

**Clients → Create client**

| Field | Value |
| --- | --- |
| Client ID | `privacyidea-resolver` |
| Client authentication | **on** (confidential) |
| Service accounts | on |
| Standard flow | **off** |

Copy the generated **client secret** — it becomes the resolver's password in step 3.1.

### 2.4 Authentication flow

Realm **Settings → User profile** is not involved. The flow is:

**Authentication → Flows**, top-level flow **`PrivacyIDEA`** (`dbc80027`), containing subflow
**`PrivacyIDEA forms`** with exactly three executions in this order:

| Order | Execution | Provider ID | Role |
| --- | --- | --- | --- |
| 1 | `Username Password Form` | `auth-username-password-form` | first factor (AD credentials) |
| 2 | `EDC MFA Channels` | `edc-mfa-channels` | detects available channels, issues the challenge cookie |
| 3 | `privacyIDEA` | `privacyidea-authenticator` | renders the OTP page and validates the code |

**Set this once for the whole realm:** Realm settings → *User Defined Browser Flow* = **`PrivacyIDEA`**.
No per-client binding is needed — clients that do not override it inherit this.

### 2.5 `EDC MFA Channels` config

**Authentication → Flows → PrivacyIDEA forms → EDC MFA Channels → ⚙ → Config**

| Field | Value | Notes |
| --- | --- | --- |
| `piBaseUrl` | `http://mfa-privacyidea:8080` | internal, for server-to-server calls |
| `piAdminUsername` | `admin` | privacyIDEA superuser |
| `piAdminPassword` | the PI admin password | see §3.0 |
| `webhookSecret` | see §1 | |
| `publicBaseUrl` | `https://keycloak-mfa.crosswired.me` | logo/asset origin in OTP mail |
| `spassExpiryMinutes` | `5` | code validity **and** the page countdown |

`challengeTtlMinutes` defaults to `30` when absent. It governs how long the browser's challenge proof
lives and **must outlive the code**, otherwise "Send a new code" breaks at exactly the moment it is
needed.

`PrivacyIdeaSettings` is the single source of truth: the webhook resource and the channel detector both
resolve from it, so they cannot drift.

### 2.6 `privacyIDEA` authenticator config

Same screen path, third execution. Vendor defaults mostly apply; these are the ones that matter:

| Field | Value |
| --- | --- |
| `piserver` | `http://mfa-privacyidea:8080` |
| `pirealm` | **`EDC`** |
| `piservicerealm` | **`EDC`** |
| `piserviceaccount` / `piservicepass` | privacyIDEA service credentials |
| `pidotriggerchallenge` | `true` |
| `pidisablepasswordcheck` | `false` |

> **Currently wrong on this deployment.** `pirealm` and `piservicerealm` are still `mfa` from before
> the rename. It has not broken the flow — the resolver path does not consult them — but it is stale
> and should be corrected to `EDC`.

---

## 3. PrivacyIDEA

Web UI: `https://pi-mfa.crosswired.me`

### 3.0 Admin account

The channel detector authenticates to privacyIDEA with `piAdminUsername` / `piAdminPassword`. That is
currently the **superuser** (`admin`), which is far more privilege than the detector needs. It should
become a least-privilege service account with rights limited to token init, token list and validate.

### 3.1 Resolver

**Config → Realms → `edc` → Resolver → Create resolver**

| Field | Value |
| --- | --- |
| Resolver name | `keycloak-resolver` |
| Type | `Keycloak/OpenID` (`keycloakresolver`) |
| Base URL | `http://mfa-keycloak:8080` |
| Realm | `edc` |
| Username | `privacyidea-resolver` |
| Password | the client secret from §2.3 |
| Editable | off (read-only users) |

Attribute mapping used here:

| privacyIDEA | Keycloak |
| --- | --- |
| `username` | `username` |
| `userid` | `id` |
| `givenname` | `email` |
| `surname` | `lastName` |

After saving, the privacyIDEA realm must have this resolver assigned, or no user will be found and the
channel detector will report no channels.

### 3.2 Event handler

**Config → Event Handlers → Create event handler**

| Field | Value |
| --- | --- |
| Name | `validate_triggerchallenge` |
| Event | `validate_triggerchallenge` |
| Handled module | `WebHook` |
| Position | `post` |
| Active | yes |

Options:

| Option | Value |
| --- | --- |
| `URL` | `http://mfa-keycloak:8080/realms/EDC/privacyidea/ipn?secret=<shared secret>` |
| `content_type` | `application/json` |
| `data` | `{"username": "{logged_in_user}", "client_ip": "{client_ip}"}` |
| `replace` | `True` |

The realm name in that URL must be **`EDC`**, not `mfa`. privacyIDEA runs inside the Docker network, so
it uses the internal `mfa-keycloak:8080` address here and the public hostname from a browser or from an
external host.

privacyIDEA cannot send custom headers, which is why the secret travels as a query parameter rather than
in an `Authorization` header.

### 3.3 Tokens per user

Each user needs at least one enrolled token, or no channel is offered.

**Users & Containers → *user* → Tokens → Generate token**

| Channel | Token type | Serial prefix | Notes |
| --- | --- | --- | --- |
| Email / SMS (SPASS) | `spass` | `PISP…` | one-time code pushed by the webhook |
| Authenticator app | `totp` | `TOTP…` | user scans the QR code |

Enrolled serials look like `PISP000106D7` and `TOTP0000C201`. The serial is what the OTP page submits,
and what the webhook is told to trigger.

TOTP parameters in use: `timeStep=30`, `timeWindow=180`, hash `sha1`.

---

## 4. What the flow does

```
browser ──AD credentials──▶ Username Password Form
                          ──▶ EDC MFA Channels
                                │  GET  /realms/EDC/privacyidea/channels
                                │       → which channels this user has
                                └──▶ issues a short-lived signed challenge cookie
                          ──▶ privacyIDEA authenticator renders the OTP page
                                │
                                └──▶ on validate, privacyIDEA fires validate_triggerchallenge
                                          │
                                          └──▶ WebHook ──▶ POST /ipn?secret=…
                                                        → triggers the token
                                                        → emails / sends the code
user submits code ──────────▶ privacyidea-authenticator ──▶ privacyIDEA /validate/check
```

`GET /channels` and `POST /resend` are served by the same realm resource provider at
`/realms/EDC/privacyidea/`. They authorise from the signed cookie, not from a Keycloak session — a plain
REST request cannot see one.

---

## 5. Verification

### 5.1 Without any user credentials

The webhook secret can be checked on its own. `mfa-keycloak:8080` only resolves inside the Docker
network, so either run these through `docker exec` or use the public hostname.

```bash
set -a; source .env; set +a
BASE="https://${KEYCLOAK_HOST}/realms/EDC/privacyidea/ipn"
BODY='{"username":"<existing user>","serial":"x"}'

# 401 — secret did not match
curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$BASE?secret=wrong" \
  -H 'Content-Type: application/json' -d "$BODY"

# 401 — no secret supplied
curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$BASE" \
  -H 'Content-Type: application/json' -d "$BODY"

# 200 — secret matched and the user resolved
curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$BASE?secret=$PRIVACYIDEA_WEBHOOK_SECRET" \
  -H 'Content-Type: application/json' -d "$BODY"
```

Or from inside the stack network, where the internal name resolves:

```bash
docker exec mfa-privacyidea curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST "http://mfa-keycloak:8080/realms/EDC/privacyidea/ipn?secret=$PRIVACYIDEA_WEBHOOK_SECRET" \
  -H 'Content-Type: application/json' -d '{"username":"<existing user>","serial":"x"}'
```

Status codes mean what you would expect, and the distinction matters when reading them:

| Request | Status | Means |
| --- | --- | --- |
| wrong or missing secret | `401` | secret rejected, nothing else attempted |
| correct secret, unknown user | `404` | secret is fine; the user did not resolve |
| correct secret, no `username` | `400` | malformed call |
| correct secret, existing user | `200` | secret **and** user both resolved |

A `404` on the third call means the secret matched but the username is wrong — a common false alarm when
copying this. It is still not proof that delivery works, because a bogus serial then fails in business
logic.

Trigger a real code and read the mail:

```bash
curl -sk -o /dev/null -X POST "$BASE?secret=$PRIVACYIDEA_WEBHOOK_SECRET" \
  -H 'Content-Type: application/json' \
  -d '{"username":"<user>","serial":"<PISP serial>"}'

# then read https://mfa-mail.crosswired.me
```

Check the generated theme file carries the right public origin:

```bash
grep '^emailBaseUrl=' themes/khalibre/email/theme.properties
```

### 5.2 What needs a real user

The OTP page is only reachable after valid AD credentials, so it cannot be exercised without one.
Drive the forgot-password flow instead, which needs no password: create a temporary public client with
`redirectUris: ["*"]`, follow the reset link out of the mail, then delete the client. Temporary clients
are safe; temporary **users** are not, because they reach AD.

### 5.3 Logs

```bash
mise run logs:keycloak      # look for method=processIpn status=UNAUTHORIZED
mise run logs:privacyidea   # look for webhookeventhandler lines naming /ipn
```

---

## 6. Open items

* `pirealm` / `piservicerealm` on the `privacyidea-authenticator` are still `mfa` — should be `EDC`.
* `piAdminPassword` is the privacyIDEA superuser; move to a least-privilege service account.
* `PRIVACYIDEA_WEBHOOK_SECRET` is in `.env` but not in `.env.j2`, so `mise run start` regenerates it
  empty and the webhook rejects everything until the Vault key
  (`vault_privacyidea_webhook_secret`) exists.
* Admin-config values live in the Keycloak database, so a database restored from another environment
  carries that environment's `webhookSecret` and `publicBaseUrl` with no warning.
