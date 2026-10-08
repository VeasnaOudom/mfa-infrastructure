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
3. Generate the shared secret and put it in **two** places
4. Keycloak — authentication flow and both authenticator configs
5. Per user — enroll a token

There is **no privacyIDEA event handler to configure.** Delivery happens inside
`edc-mfa-channels`, which writes the PIN and sends it before the OTP step; there was once a WebHook
handler posting to `/ipn` beside it, and it is gone. See `AGENTS.md` → *Codes were deliverable exactly
once per token*.

---

## 1. The shared secret

One value, two locations. Both must be byte-identical.

| # | Where | Why |
| --- | --- | --- |
| 1 | `webhookSecret` on the **EDC MFA Channels** authenticator config | what Keycloak expects |
| 2 | `PRIVACYIDEA_WEBHOOK_SECRET` in `.env` | fallback source, also used by the compose env |

Generate one:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

The field is still called `webhookSecret` even though the webhook is gone. What it signs now is the
`EdcChallengeToken` browser cookie, which is what authorises `GET /channels`,
`POST /enrolment/telegram-link` and `POST /resend` — remove it and the whole MFA flow stops.

Resolution order in `PrivacyIdeaSettings` is **admin config first, then environment variable**, so
location 1 wins if they disagree. A mismatch is not silent: `POST /resend?secret=` answers `401` and
logs `method=secretValid status=REJECTED`.

> An empty secret used to mean "skip the check". It now fails closed: with no secret configured every
> `POST /resend?secret=` is rejected **and** no challenge cookie can be verified, so `/channels`
> answers `401` too. Seed it before you start the stack.

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
**`PrivacyIDEA forms`**:

| Order | Execution | Provider ID | Role |
| --- | --- | --- | --- |
| 10 | `Username Password Form` | `auth-username-password-form` | first factor (AD credentials) |
| 11 | `EDC MFA Channels` | `edc-mfa-channels` | detects channels, issues the challenge cookie, and puts MFA enrolment on the user when they have no working channel |
| 12 | `Second factor` | *(subflow, requirement **CONDITIONAL**)* | the challenge itself |
| └ 0 | `Conditional - EDC MFA Enrolled` | `edc-mfa-enrolled` | runs the subflow only for users who have finished enrolment |
| └ 1 | `privacyIDEA` | `privacyidea-authenticator` | renders the OTP page and validates the code |

The subflow's requirement must be **`CONDITIONAL`**, not `REQUIRED`. That requirement is what makes
the flow engine consult its conditional authenticator at all; with `REQUIRED` the subflow always runs
and the gate is decorative.

**Why the challenge is behind a gate.** A user with no privacyIDEA token and no linked Telegram
account cannot produce a code, so an unconditional challenge would meet them with six empty boxes and
no way forward. Gating it means they are sent to enrolment instead, and the enrolment wizard is what
actually stops them — Keycloak will not finish signing someone in while a required action is
outstanding.

**Set this once for the whole realm:** Realm settings → *User Defined Browser Flow* = **`PrivacyIDEA`**.
No per-client binding is needed — clients that do not override it inherit this.

### 2.4a `EDC MFA Enrolment` required action

The action is **not** to be added to the realm's *Default required actions*. `edc-mfa-channels` puts
it on individual users, and only for as long as they have no working channel. Adding it to the
defaults sends everyone through the wizard on every sign-in.

**It still has to be registered in the realm**, which is a separate step from deploying the JAR and
not an obvious one. Deploying only publishes the provider to
`GET /authentication/unregistered-required-actions`; Keycloak resolves a user's required actions
against the realm's *registered* set, so until it is registered there, `edc-mfa-channels` happily
puts the action on the user, Keycloak logs

```
Could not find configuration for Required Action edc-mfa-enrolment, did you forget to register it?
```

and **signs the user straight in**. No error is shown and no screen is rendered, so it looks exactly
like the feature not existing.

In the admin console: **Authentication → Required actions**, and add *EDC MFA Enrolment* from the
provider-supplied list. Over the API:

```bash
POST /admin/realms/EDC/authentication/register-required-action
{"providerId": "edc-mfa-enrolment", "name": "EDC MFA Enrolment"}
```

Note the path is `register-required-action` — not under `required-actions`, and not a PUT on the
action itself. `PUT …/required-actions/{alias}` answers `Failed to find required action`, because
that endpoint only updates an existing registration.

Confirm it registered:

```bash
curl -sk -H "Authorization: Bearer $AT" \
  "https://$KEYCLOAK_HOST/admin/realms/EDC/authentication/unregistered-required-actions"
# => []   (empty means it is now registered)
curl -sk -H "Authorization: Bearer $AT" \
  "https://$KEYCLOAK_HOST/admin/realms/EDC/authentication/required-actions" | grep edc-mfa
```

After registering, restart is not needed, but existing users keep the action only if their login
re-evaluates it: `edc-mfa-channels` adds it on each sign-in, so a user with no channel gets it on
their next attempt.

### The enrolled-users group

Finishing enrolment adds the user to a group (`MFA` by default, editable as **Enrolled Users Group**
on the EDC MFA Channels execution). Resetting someone's MFA - see *Resetting a user's MFA* below -
takes them out of it again.

It is the operator-facing answer to "who has a second step set up", and it is a reliable one: group
membership is stored locally in Keycloak, and no LDAP group mapper is attached to this realm, so
unlike the `edc-mfa-*` attributes nothing rewrites it during sync. Nothing in the sign-in flow reads
it - the OTP gate is the `edc-mfa-enrolled` condition, which uses the enrolment marker - so it can be
read, exported or repurposed without affecting who is let in.

### 2.5 `EDC MFA Channels` config

**Authentication → Flows → PrivacyIDEA forms → EDC MFA Channels → ⚙ → Config**

| Field | Value | Notes |
| --- | --- | --- |
| `piBaseUrl` | `http://mfa-privacyidea:8080` | internal, for server-to-server calls |
| `piAdminUsername` | `admin` | privacyIDEA superuser |
| `piAdminPassword` | the PI admin password | see §3.0 |
| `webhookSecret` | see §1 | names the browser challenge cookie signing key |
| `publicBaseUrl` | `https://keycloak-mfa.crosswired.me` | logo/asset origin in OTP mail |
| `spassExpiryMinutes` | `5` | code validity **and** the page countdown |
| `backupCodeCount` | `10` | codes per set, issued automatically at the end of enrolment |
| `backupCodeLength` | `6` | digits per code; the code field is six boxes wide |

`challengeTtlMinutes` defaults to `30` when absent. It governs how long the browser's challenge proof
lives and **must outlive the code**, otherwise "Send a new code" breaks at exactly the moment it is
needed.

`PrivacyIdeaSettings` is the single source of truth: the `privacyidea` resource provider and the
channel detector both resolve from it, so they cannot drift.

### 2.6 `privacyIDEA` authenticator config

Same screen path, `privacyIDEA` execution inside `Second factor`. Vendor defaults mostly apply;
these are the ones that matter:

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

### 3.2 Tokens per user

Each user needs at least one enrolled token, or no channel is offered.

**Users & Containers → *user* → Tokens → Generate token**

| Channel | Token type | Serial prefix | Notes |
| --- | --- | --- | --- |
| Email / SMS (SPASS) | `spass` | `PISP…` | one-time code pushed by `edc-mfa-channels` |
| Authenticator app | `totp` | `TOTP…` | user scans the QR code |
| Backup codes | `tan` | `PITN…` | 100 pre-generated single-use 6-digit codes |

Enrolled serials look like `PISP000106D7`, `TOTP0000C201` and `PITN00005935`. The serial is what the OTP
page submits, and what `edc-mfa-channels` looks up when it issues a code.

TOTP parameters in use: `timeStep=30`, `timeWindow=180`, hash `sha1`.

**Backup codes** are a TAN token. They are typed into the same six-box field, and privacyIDEA validates
them on the ordinary check call, so there is no second validation path. The codes are shown **once**, at
enrolment — privacyIDEA returns them in `detail.otps` from `/token/init` and stores them hashed, so
they cannot be listed again. Losing the list means enrolling a new TAN token.

---

## 4. What the flow does

### An enrolled user

```
browser ──AD credentials──▶ Username Password Form
                          ──▶ EDC MFA Channels
                                │  GET  /realms/EDC/privacyidea/channels
                                │       → which channels this user has
                                ├──▶ no enrolment required → note 0
                                ├──▶ issues a short-lived signed challenge cookie
                                └──▶ issueSignInCode → /token/setpin, then email / Telegram
                          ──▶ Second factor (CONDITIONAL → matches)
                                └──▶ privacyIDEA authenticator renders the OTP page
user submits code ──────────▶ privacyidea-authenticator ──▶ privacyIDEA /validate/check
```

### A user being stopped for enrolment

```
                          ──▶ EDC MFA Channels
                                ├──▶ no channel at all → note 1
                                └──▶ puts EDC MFA Enrolment on the user
                          ──▶ Second factor (CONDITIONAL → does not match, skipped)
                          ──▶ required actions
                                └──▶ EDC MFA Enrolment
                                       ├ choose      ──▶ Telegram / Authenticator app / Email
                                       ├ telegram    ──▶ QR, bot confirms the scan
                                       ├ totp        ──▶ QR, user types the code, /validate/check
                                       ├ email       ──▶ code mailed, user types it, /validate/check
                                       └ backup codes──▶ TAN token issued, codes shown once
                                                          → marker written, action removed
```

`GET /channels`, `POST /resend` and `POST /enrolment/telegram-link` are served by the same realm
resource provider at `/realms/EDC/privacyidea/`. The browser authorises from the signed challenge
cookie, because a plain REST request cannot see a Keycloak authentication session. `/resend` also
accepts `?secret=` for a trusted server-side caller.

### Backup codes

Backup codes are a privacyIDEA **TAN token** (`PITN…`, `tokentype=tan`) and nothing else. They are
issued automatically once a channel is set up; there is no screen on which a user can decline them.

* privacyIDEA keeps them **hashed** and reports them exactly once, in `detail.otps` from
  `/token/init`. The wizard holds them in an authentication-session note for the length of one
  required-action visit and drops it when the user leaves. There is no way to show them again —
  re-enrolment is the replacement mechanism.
* They are typed into the same six-box field as a channel code, and privacyIDEA validates them on the
  ordinary `/validate/check` call, so there is no second validation path.
* Issuing a set **deletes every existing TAN token first**, so "generate a new set" stops the old
  codes working instead of silently doubling what an attacker could try.
* Count comes from `backupCodeCount` on the EDC MFA Channels execution.

### Re-enrolling someone

`EdcEnrolmentState` requires *both* a completion marker **and** a live channel, so deleting a user's
privacyIDEA tokens sends them through the wizard again on their next sign-in without any second flag
to remember.

**Do not try to clear the marker or the `telegram-*` attributes through the admin console or the
admin REST API.** On this realm it reports success, reads back as gone, and the rows are still
there — checked against `USER_ATTRIBUTE` in the database, which is the only reliable read. What
works is an in-process write, which is what the endpoint below does.

Note that deleting a privacyIDEA token is enough on its own: with no `spass` token the bot has
nothing to send, so the Telegram channel is withdrawn even though the link survives, and enrolment
is owed again. That is deliberate, because a bare `telegram-user-id` is an address, not a channel.

### Managing your own channels (account console)

The **Signing in** page of the account console lets a user turn each channel on and off themselves.
It is backed by a separate provider mounted at `/realms/EDC/edc-mfa-settings/`, which acts **only on
the caller's own account** — the user comes from a verified `account`-client bearer token and is never
read from a parameter, so unlike the ICT endpoint above it cannot be pointed at another account.

The caller is authenticated by `AccountConsoleCaller`, shared with the account-activities endpoint so
the two cannot drift on who is allowed in:

* The token must be issued for the `account` client.
* **Service accounts are refused.** Worth knowing when testing: a `client_credentials` token in this
  realm carries `aud: account` anyway, so the audience check passes and the service-account check is
  the only thing standing between it and a user's MFA setup. A master-realm token is refused too —
  a provider mounted on `EDC` validates against `EDC`'s keys.

| Call | Does |
| --- | --- |
| `GET  /edc-mfa-settings/channels` | State of all four channels, what could be added, whether privacyIDEA is reachable |
| `POST /edc-mfa-settings/channels/{id}/start` | Begins one: returns an `otpauth://` URI, sends an email code, or mints a Telegram deeplink |
| `POST /edc-mfa-settings/channels/{id}/verify` | `{"code":"…"}` finishes it; Telegram takes none |
| `GET  /edc-mfa-settings/channels/telegram/scan` | Polls a Telegram scan and asks the bot for a phone number |
| `POST /edc-mfa-settings/channels/{id}/remove` | Turns one off |
| `POST /edc-mfa-settings/channels/backupCode/regenerate` | Issues a fresh set of backup codes, returning them once |

Three things about it that are not obvious:

* **Telegram linking here cannot reuse `telegram-auth`.** Those endpoints file their `AuthState`
  under the root authentication session, which is `null` on a plain REST request, so the account
  console has to key its scan on the user id instead. That is equally unforgeable — the id comes from
  the verified token — but it is a different key, so a scan started in one flow is invisible to the
  other.
* **Email and Telegram share one `spass` token.** Email reads as on whenever a `spass` token exists,
  so turning Email off deletes the only thing the bot can send a code through and Telegram goes quiet
  too. The response reports `willNeedEnrolment` and the page confirms it, but the coupling is real
  and fixing it means giving each channel its own token.
* **Backup codes cannot be re-read.** `regenerate` deletes the old `tan` token before creating the new
  one — creating first would leave the previous set working — and returns the codes in that response
  and nowhere else.

### Resetting a user's MFA (ICT)

```
POST /realms/EDC/edc-mfa-admin/reset?username=<name>&deleteTokens=true
Authorization: Bearer <token>
```

Clears the `telegram-*` attributes, the Telegram federated identity and the `edc-mfa-enrolled-*`
markers in one in-process write, and queues `edc-mfa-enrolment` again so the next sign-in starts the
wizard. `deleteTokens=true` also deletes their privacyIDEA tokens. The response is a report of what
was removed, so check it rather than assuming.

The token must be **issued by `EDC`** and carry `manage-realm`:

* The master admin's `admin-cli` token will not work. Keycloak validates a bearer against the realm
  the provider is mounted on, and this admin has no user record in `EDC` at all. It also emits no
  role claims whatsoever, not even with `scope=roles`.
* `manage-realm` arrives under `resource_access["realm-management"]` on a service-account token, so
  the working setup is a **confidential client with a service account** and `realm-management` added
  in the client's **Role mapping** tab. An end-user token is rejected with 401.
* Granting it over REST is awkward on KC 26.1.3: `POST .../clients/{id}/default-roles` and
  `POST .../clients/{id}/default-roles/{realm-management-id}` both 404. The Role mapping tab works.

To exempt a non-human account entirely, set `edc-mfa-enrolment-exempt` = `true`. `ldap-svc` has no
tokens and no Telegram account, so without this it would be stopped at a wizard it can never get
past.

**Clearing the marker on its own is not a re-enrol tool**, on this realm or any other: it is a local
attribute on a federated user and the admin REST API cannot remove it. Clearing a *channel* is what
works, because enrolment is owed whenever there is no working channel regardless of the marker. That
is the reasoning behind `deleteTokens` above, and it is why the marker is kept as a courtesy write
rather than relied on.

### Telegram linking during enrolment

The bot's token lives in the `telegram` identity provider's `clientSecret`. Note that the admin API
masks it in `GET …/identity-provider/instances`, so `**********` there does not mean the bot is
unconfigured — read the real value from `IDENTITY_PROVIDER_CONFIG` if you need to test it. A realm
whose token is genuinely a placeholder fails `EdcChannelDetector.isTelegramConfigured`, and Telegram
is then not offered in the chooser rather than dead-ending the user at a QR code that cannot work.

Enrolment reuses the identity provider's existing QR and polling endpoints unchanged — they read the
root authentication session the wizard is already running inside. What it cannot do is hand the
result to the IdP callback, because that only runs for a broker round trip and enrolment is not one.
So `POST /privacyidea/enrolment/telegram-link` writes the federated identity and the same user
attributes the broker would have written, from the `AuthState` the scan produced. It refuses a chat
id already linked to a different user.

### Telegram account already linked

The bot token identifies a Telegram account, and a Telegram account belongs to one person. Three
places enforce that, because getting it wrong means two staff accounts receive their codes at the
same phone:

| Place | What it refuses |
|---|---|
| `POST /privacyidea/enrolment/telegram-link` | linking a chat another account already holds |
| `TelegramIdentityProvider` broker callback | the same, when linking through the Telegram login page |
| `EdcChannelDetector.detectTelegram` | *reporting* the channel when two accounts claim one chat |

Ownership is decided from **both** the `telegram-user-id` user attribute and the federated-identity
row. On this realm only the attribute reliably persists for LDAP-backed users, so a check built on
the row alone finds nothing and lets a second account link the same phone.

If two accounts end up claiming one chat - as happened during testing - the channel is withdrawn
from both and this appears in the log:

```
ERROR method=detectTelegram user=<a> chat=<id> alsoHeldBy=<b>
  message=Two accounts claim one Telegram account; refusing the channel for both
```

Repair it by hand: decide which account owns the Telegram account, remove the `telegram-user-id`,
`telegram-username`, `telegram-first-name` and `telegram-last-name` attributes from the other, and
let that person enrol again. There is deliberately no automated repair, because guessing the
rightful owner means deciding who receives someone else's verification codes.

---

## 5. Verification

### 5.1 Without any user credentials

There is no longer a credential-free probe for the shared secret, because the endpoint that used to
provide one (`POST /ipn`) is gone. What can still be checked without an AD account:

**The provider is registered.** A real path answers `401` (no challenge cookie) while an unknown one
answers `404`. That `401` is the registration check — it proves the `privacyidea` resource provider is
mounted and reachable, which a `404` would not.

```bash
set -a; source .env; set +a
BASE="https://${KEYCLOAK_HOST}/realms/EDC/privacyidea"

# 401 — provider is mounted, caller has no challenge cookie
curl -sk -o /dev/null -w '%{http_code}\n' "$BASE/channels"

# 404 — no such endpoint, so the 401 above really was the provider answering
curl -sk -o /dev/null -w '%{http_code}\n' "$BASE/nosuchpath"

# 404 — /ipn was deleted; this must NOT come back 401 or 200
curl -sk -o /dev/null -w '%{http_code}\n' -X POST "$BASE/ipn?secret=$PRIVACYIDEA_WEBHOOK_SECRET"
```

`mfa-keycloak:8080` only resolves inside the Docker network, so either run these through `docker exec`
or use the public hostname as above.

**The secret is only observable through a real challenge.** It signs the cookie that `/channels`
verifies, so the honest check is a sign-in that renders the chooser. A misconfigured secret shows up as
`401` on `/channels` plus this line in the Keycloak log:

```
WARN  method=channels status=UNAUTHORIZED message=No valid challenge cookie
```

There is no `?secret=` probe worth running: `POST /resend?secret=<wrong>` answers `401` whether the
secret is wrong *or* correct-and-you-simply-also-lack the cookie, and `?secret=<correct>` with a
resolved user **actually issues and delivers a real code**. Do not use it as a probe.

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
mise run logs:keycloak      # look for method=channels status=UNAUTHORIZED, or method=resend status=*
```

There is no `method=processIpn` line to look for any more. If you still see `webhookeventhandler`
output from privacyIDEA naming `/ipn`, a WebHook event handler is still configured there and needs
deleting.

---

## 6. Admin API notes

Setting this flow up by hand in the console is fine. Doing it over the admin API is not, and KC 26
gets in the way in ways worth writing down:

* **Address flows by alias, never by id.** `POST …/flows/{flowId}/executions/flow` answers
  `Parent flow doesn't exist` for a perfectly valid subflow id. `…/flows/PrivacyIDEA%20forms/…`
  works. Subflow ids are not listed by `GET …/authentication/flows` either — that endpoint returns
  top-level flows only.
* **Executions cannot be addressed by id at all.** `GET`, `PUT` and `DELETE`
  `…/flows/{alias}/executions/{executionId}` all answer `404`. Update an execution through the
  *collection* endpoint, `PUT …/flows/{alias}/executions`, with a body carrying the `id` plus the
  fields to change. That is the only way to change an execution's requirement or priority.
* **A collection PUT drops `authenticationConfig`.** Setting it changes the requirement and nothing
  else. To attach an authenticator config, use
  `POST …/authentication/executions/{executionId}/config` with `{"alias": …, "config": {…}}` — it
  creates the config and binds it in one call. The alias must be unique across the realm, so a
  second `privacyIDEA` execution needs a different one.
* **`POST …/execution` reads `provider`, not `authenticator`.** Sending `authenticator` answers
  `No authentication provider found for id: null`; sending `provider` creates the execution but
  ignores `requirement` and any config you include.
* **A leftover disabled execution.** Moving the OTP challenge into the new subflow could not delete
  the original (`DELETE …/executions/{id}` 404s), so it sits at priority 0 with requirement
  `DISABLED`. It never runs. Delete it in the admin console when convenient.
* **Registering a provider-supplied required action lives at `POST
  …/authentication/register-required-action`** with `{"providerId": …, "name": …}`, not under
  `…/required-actions`. The list at `…/unregistered-required-actions` is the check: empty means every
  provider-supplied action is registered, non-empty means one is published but not usable yet.

## 7. Open items

* `pirealm` / `piservicerealm` on the `privacyidea-authenticator` are still `mfa` — should be `EDC`.
* `piAdminPassword` is the privacyIDEA superuser; move to a least-privilege service account.
* `PRIVACYIDEA_WEBHOOK_SECRET` **is** rendered — `.env.j2` has it, and `privacyidea_webhook_secret`
  in `ansible/group_vars/all/vars.yml` falls back to a hardcoded literal when
  `vault_privacyidea_webhook_secret` is unset. So the secret is non-empty in every environment, but it
  is the *same* non-empty value everywhere until the Vault key is seeded. Seed it, then regenerate.
* Admin-config values live in the Keycloak database, so a database restored from another environment
  carries that environment's `webhookSecret` and `publicBaseUrl` with no warning.
* The account console **Signing in** page now manages channels (see above), so a lost backup-code set
  can be replaced without ICT. What it does **not** do is require a password re-check first: a stolen
  console session can still strip MFA and mint a new set of backup codes. Adding one is the next thing
  this page needs.
* Email and Telegram share a single `spass` token, so the two channels cannot be switched on and off
  independently. Turning Email off also stops Telegram codes arriving.
* MFA enrolment has been driven end to end for the `extuser` AD account (chooser → authenticator app
  → wrong code → correct code → backup codes → completion marker). The **Telegram** and **email**
  branches have not: Telegram needs a real bot chat, and the email branch needs a mailbox at
  smtp4dev.
* The account console has been verified only as far as **authentication**: a service-account token and
  a master-realm token are both refused, and the provider is registered. The page itself needs a real
  user's browser session to confirm, because every account on this realm is LDAP-federated and
  creating one is not safe.
