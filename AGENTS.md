# AGENTS.md

Working notes for coding agents on this repository. Read before changing Keycloak, PrivacyIDEA or
the `khalibre` theme.

For setup, tasks and architecture see `README.md`. This file records the things that are **not
obvious from the code** and that cost real debugging time.

## Ground rules

* **Verify against the running stack, not against assumptions.** Most bugs found here were
  "valid-looking" code that failed only at runtime.
* **Assert on scripted edits.** Several silent no-op `str.replace()` calls left broken code behind
  because the anchor had drifted. Wrap replacements and check.
* **Do not create test users in realm `EDC`.** The realm federates to LDAP with
  `editMode=Writable` and `syncRegistrations=true`, so user writes propagate to Active Directory.
  Creating a user once wrote `cn=Otp Test` into AD and failed halfway. Temporary *clients* are
  safe. If a user must be created, delete it and confirm with a full LDAP sync.

## Keycloak platform constraints

These are Keycloak/PrivacyIDEA behaviours, not project choices.

* **Authentication-session notes are unreachable from FreeMarker.** Keycloak binds
  `authenticationSession` to an `AuthenticationSessionBean` carrying only the parent session id and
  tab id (`FreeMarkerLoginFormsProvider`), never `AuthenticationSessionModel`. `getAuthNote()`
  cannot be called from a template.
* **A plain REST request sees no authentication session.** `getContext().getAuthenticationSession()`
  is only populated for login-action requests, so a realm resource provider endpoint cannot
  identify the caller. `AUTH_SESSION_ID` is signed/encoded and `decodeAuthSessionId` is
  package-private, so it cannot be decoded from a provider. Hence `EdcChallengeToken`: the
  authenticator issues a short-lived HMAC-signed cookie and the endpoints verify it themselves.
* **An `Authenticator` must always resolve its context.** `DefaultAuthenticationFlow` does
  `switch (result.getStatus())` on the result of both `authenticate()` and `action()`. Returning
  without `context.success()` is an NPE. Use `finally { context.success(); }` on a pass-through.
* **`@Context` must be a method parameter on a factory-created resource, not a field.**
  `RealmResourceProvider.getResource()` returns the instance the factory built, and RESTEasy never
  runs field injection on it, so a `@Context` field stays null and NPEs on first use - as
  `headers` did in `EdcMfaAdminResource`. `AccountActivitiesResource` does both, and its two
  `@Context` fields are dead weight; the method parameter at its `getEvents` is what actually works.
* **A realm resource provider can only validate a bearer token that realm minted.** Keycloak verifies
  the signature against the *current* realm's keys, so the master admin's own `admin-cli` token gets
  a 401 from a provider mounted on `EDC`. Consequence for any admin-only endpoint here: the caller
  needs an **EDC** account holding realm-management, and the master admin - who has no user record
  in `EDC` at all - cannot be the caller.
* **`manage-realm` arrives in two different places, and both must be read.** It is a *client* role of
  `realm-management`, so on a user token it is under `resource_access["realm-management"]`, while a
  service-account token carries the same authority in `realm_access`. Checking only one rejects half
  the legitimate callers. Note the master admin here emits **no** role claims at all - not even with
  `scope=roles` - so `isUserInRole` is never a usable gate on its own.
* **Several role-scoping and required-action admin paths 404 on KC 26.1.3.** Confirmed 404:
  `PUT`/`DELETE .../users/{id}/required-actions` (and `.../required-actions/{alias}`), and both
  `POST .../clients/{id}/default-roles` and `POST .../clients/{id}/default-roles/{realm-management-id}`.
  So an ICT role cannot be granted over REST - it has to come from the admin console. Granting a
  realm-management role *to a user* does work:
  `POST .../users/{id}/role-mappings/clients/{realm-management-id}`.
  `DELETE` on that same collection, with the role in the body, removes it again.
* **A pending required action blocks direct grant.** `grant_type=password` for an account with
  `edc-mfa-enrolment` queued answers `invalid_grant: Account is not fully set up`, which makes it
  impossible to mint that user's token for testing while enrolment is pending - and the endpoint that
  would clear it needs a token in the first place.
* **`Config.Scope` is only populated for realm resource providers.** `AuthenticatorFactory.init()`
  is called at startup, so values read there are frozen until restart. Resolve per request in
  `create()` instead if changes must apply live.
* **`updateAuthenticatorConfig()` does not re-`init()` the factory.** Editing an authenticator
  config in the console persists to the database but does not affect cached factory state.
* **FreeMarker `?no_esc` is Keycloak-registered, not standard.** It breaks offline parsing/rendering
  unless stubbed or textually swapped.
* **`display: flex` beats the `hidden` attribute.** Any rule setting `display` silently defeats
  `element.hidden = true`. `custom.css` has a global `[hidden] { display: none !important; }`
  because the OTP page relies on this.
* **Anchors in a `<#if>` chain are not interchangeable with `<#endif>`.** Keycloak's own templates
  use the legacy `</#if>` closing form; be careful which one you write.
* **KC 26 admin API shapes are asymmetric.** Reads return `providerId`/`authenticationConfig`, while
  writes need `authenticator`/`authenticatorConfig`. Flow listings are **flattened** — subflow
  executions appear under the parent flow. Addressing endpoints by alias works where a UUID 404s,
  and `AuthenticatorConfigRepresentation` takes a `config` map rather than `name`/`value` pairs.
  Verify field names against `javap` on the `keycloak-core` jar rather than guessing.
* **Sub-resource providers need `META-INF/services` registration** in
  `keycloak-provider/src/main/resources/META-INF/services/`:
  `...Authentication.AuthenticatorFactory`, `...Authentication.RequiredActionFactory`,
  `...services.resource.RealmResourceProviderFactory`, and `...broker.provider.IdentityProviderFactory`.
  The path is `authentication/`, not `services/`, for authenticators and required actions.
* **The KC 26 admin API cannot address an execution by id.** `GET`, `PUT` and `DELETE`
  `.../flows/{alias}/executions/{executionId}` all return 404. Change an execution through the
  *collection* endpoint `PUT .../flows/{alias}/executions` with the `id` in the body - and note that
  this drops `authenticationConfig`, so a config has to be attached separately with
  `POST .../authentication/executions/{executionId}/config`. Flows, by contrast, are addressed by
  alias rather than by flow id, or `POST .../flows/{flowId}/executions/flow` answers
  "Parent flow doesn't exist". `POST .../execution` reads `provider`, not `authenticator`.
* **`/token/` resolution goes through the Keycloak admin API**, so every privacyIDEA call that names
  a user (`/token/init`, `/validate/check`) inherits that API's availability. An LDAP-backed
  `GET /admin/realms/EDC/users?username=...` was observed hanging past 60s intermittently while other
  admin endpoints answered in milliseconds. It surfaces as a privacyIDEA 500 whose only clue is a
  `ReadTimeout` from `KeycloakResolver.getUserId`. Check the Keycloak admin API before concluding
  privacyIDEA is at fault.
* **Custom SPI registration proved unreliable here.** A hand-built `Provider`/`Spi` pair registered
  correctly in the JAR yet `session.getProvider()` returned null at runtime. The MFA channel
  detector deliberately avoids a custom SPI and builds its `PrivacyIdeaService` directly in its
  factory, mirroring the webhook resource provider.
* **`realm.baseUrl` does not exist in KC 26.** No `getBaseUrl()` on `RealmModel`, no `base_url`
  column. Nor does `UrlBean` expose a bare origin — `resourcesUrl`/`loginUrl` are built from the
  server's own request base URI and therefore contain the **internal** host and port
  (`http://keycloak-mfa.crosswired.me:8080`), which is unusable in a public email.
* **Email templates get `realmName`, not a `realm` bean.** `realm.displayName` fails with a 500 in
  an email template and takes the whole send down, including the plain-text part.
* **Editing a theme file requires a Keycloak restart to take effect** — templates and messages are
  cached. Theme and message edits alone will not show up in a running container.

## This realm's specifics

* **Realm is `EDC`** (renamed from `mfa`). Update anything referencing the old name: privacyIDEA's
  event handler URL, the privacyIDEA resolver, and `pirealm`/`piservicerealm` on the
  `privacyidea-authenticator` config.
* **Do not generalise from one admin-API test.** Writing `telegram-user-id` through
  `PUT /admin/realms/<realm>/users/{id}` returned HTTP 204 and stored nothing, which looked like
  proof that LDAP federation discards unmapped attributes. It does not: attributes written
  in-process by the Telegram brokered-identity flow (`telegram-user-id`, `telegram-username`,
  `telegram-first-name`) are present and survive. The observed difference is the code path —
  admin REST updates on a federated user versus in-process `setSingleAttribute`. Revalidate before
  asserting either.
* **Telegram detection prefers the user attribute and falls back to the federated identity.** Both
  are consulted, because only one of them is guaranteed for a given user. A `FEDERATED_USER_ID`
  must be a numeric Telegram chat id, not a UUID; if you see a UUID, the link did not complete
  properly and the row needs redoing rather than trusting.
* **`PI_ADMIN_PASSWORD` is the privacyIDEA superuser** and is what the channel detector
  authenticates with. It should become a least-privilege service account.
* **Creating local test clients is safe; creating local test users is not** (see Ground rules).

## MFA flow

`PrivacyIDEA` (top level) binds the `PrivacyIDEA forms` subflow, whose executions are:

| Priority | Execution | Role |
| --- | --- | --- |
| 10 | `auth-username-password-form` | first factor |
| 11 | `edc-mfa-channels` | detects available channels, issues the challenge cookie |
| 12 | `privacyidea-authenticator` | renders the OTP page |

Channel availability lives in authentication-session notes written by `edc-mfa-channels` and is
read back through `GET /realms/<realm>/privacyidea/channels`, which renders the chooser rows in
`pi-form.js`.

`PrivacyIdeaSettings` is the single source of truth for the privacyIDEA connection settings and
the webhook secret. Both the webhook resource and the channel detector resolve from it, so they
cannot drift. It is edited in one place only:

```
Authentication → Flows → PrivacyIDEA forms → EDC MFA Channels → ⚙ → Config
```

Two distinct lifetimes, deliberately not tied together:

* `spassExpiryMinutes` (default 5) — validity of a generated code, and what the page countdown
  counts down.
* `challengeTtlMinutes` (default 30) — how long the browser's challenge proof stays valid. Must
  **outlive** the code, otherwise "Send a new code" breaks at exactly the moment it is needed.

## Backup codes

Backup codes are a privacyIDEA **TAN token** (`PITN…` serials, `tokentype=tan`), not a separate
mechanism. A TAN token holds 100 pre-generated 6-digit codes (`tan.count`, `otplen=6`), which is exactly
what backup codes are, and it is already single-use.

* **No extra validation path exists or is needed.** A backup code is typed into the same `#otp` field,
  and privacyIDEA accepts it on the ordinary `/validate/check` call the authenticator already makes.
  Verified against privacyIDEA 3.12: first use `ACCEPT`, second use of the same code `REJECT`, and it
  validates with `user`+`pass` alone, no serial required.
* `EdcChannelDetector` therefore only adds `tan` to the token types it queries and sets
  `NOTE_BACKUP_CODE`; `PrivacyIdeaWebhookResource.channels()` exposes it as `backupCode`, and
  `pi-form.js` renders the row plus the "enter one of your backup codes" hint.
* The codes are only ever shown by privacyIDEA at enrolment (`/token/init` returns them in
  `detail.otps`); the token stores them hashed, so they cannot be displayed again later. Re-enrolment
  is how a lost list is replaced.
* **The upstream `privacyidea-authenticator` JAR knows nothing about TAN or backup codes.** It has
  `enrollViaMultichallenge` / `enrollViaMultichallengeOptional` enrolment and will happily `/token/init`
  whatever type the user picks, but there is no "backup" or "tan" string anywhere in it. So auto-issuing
  backup codes on enrolment is ours to build; only the channel setup itself can reuse the JAR.
  `piotplength` on that execution is the knob for code length.

## MFA enrolment

* **A provider-supplied required action must be registered in the realm, not just published by the
  JAR.** `META-INF/services/...RequiredActionFactory` makes it appear at
  `GET …/unregistered-required-actions`; Keycloak still resolves a user's required actions against
  the realm's registered set. Forget the second half and `edc-mfa-channels` puts the action on the
  user, Keycloak logs `Could not find configuration for Required Action edc-mfa-enrolment`, and
  **signs the user straight in** - no error, no screen, indistinguishable from the feature not
  existing. Register with `POST …/authentication/register-required-action`; that odd path is the
  only one that works (`PUT …/required-actions/{alias}` answers "Failed to find required action",
  and so does everything under `…/required-actions`). The console equivalent is adding it from the
  provider-supplied list.
* **Keycloak 26 removed the `ConditionFactory` SPI.** There is no `org.keycloak.authentication.ConditionFactory`
  in 26.x. A conditional subflow is now an ordinary subflow whose first execution is a
  `ConditionalAuthenticator`, and the subflow execution's requirement must be **`CONDITIONAL`** -
  that requirement is what makes `DefaultAuthenticationFlow` consult the condition at all. With
  `REQUIRED` the subflow always runs and the gate is decorative. `conditionalNotMatched()` only ever
  sets the *conditional execution's* own status to `DISABLED`, so as a plain sibling execution the
  gate would silently do nothing.
* **`AuthenticatorFactory.getSingleton()` + `ConditionalAuthenticatorFactory`** is the whole
  registration story, in the ordinary `META-INF/services/org.keycloak.authentication.AuthenticatorFactory`
  file. No new services file is needed for the condition.
* **The gate must not repeat the work of the execution before it.** `edc-mfa-enrolled` reads the
  auth note `edc-mfa-channels` already wrote. At this scale a second privacyIDEA round trip on every
  sign-in, for six thousand people, to learn something the previous execution just learned, is not
  an acceptable price for one boolean. Where the note is absent (a required action driven from
  outside the flow) it falls back to the user record.
* **Required actions run *after* the browser flow, not during it.** That is why the OTP challenge has
  to be gated rather than simply preceded: the challenge is inside the browser flow, so it would be
  met before any required action could intervene.
* **`user.addRequiredAction` on an LDAP-federated user is not a Keycloak-side no-op**, but the
  attribute writes that go with the completion marker are the fragile part - see Ground rules. Both
  were written in-process, which is the code path that survives.
* **Local attributes on a federated user cannot be cleared through the admin REST API.** This affects
  `edc-mfa-enrolled-at` *and* the `telegram-*` attributes. Tried, in order: omitting the key,
  sending an explicit `null`, and restarting Keycloak first to flush the user cache. Each time the
  attribute reads back as gone for two to three minutes - across four 30-second syncs - and then
  returns with its **original** value and timestamp, which means something is rewriting the
  `USER_ATTRIBUTE` rows rather than the delete never happening. It is not AD: `FED_USER_ATTRIBUTE`
  and `FEDERATION_USER` hold nothing for these users. What does work is an **in-process** write,
  which is how the Telegram link and the enrolment marker got there in the first place. So there is
  currently **no way to undo a bad Telegram link** on this realm - which makes the missing
  "ICT resets a user's MFA" endpoint a correctness problem, not a nicety.
* **`FreeMarker cannot read auth notes**, so the enrolment wizard's private material (an
  otpauth:// URI, a set of backup codes) is passed to templates through
  `LoginFormsProvider.setAttribute`, never through the notes. The notes hold it; the form attributes
  hand over only what this step is allowed to show.
* **Wizard position has to survive a GET.** A "choose a different method" button is a POST with a
  back flag, not a link: a GET re-reads the step note unchanged and puts the user straight back.
* **A screen can render `#edc-qr` and still show no QR.** `initTotpQr()` returns silently when
  `QRCodeStyling` is undefined, and `edc-mfa-enrol-code.ftl` - the screen behind both "Authenticator
  app" and "Email" - did not load the library at all, so the authenticator step showed an empty
  frame with no error anywhere. Only the Telegram templates included it, and nothing in the build
  checks that pairing. **After touching any enrolment template, confirm by hand that every one
  carrying `id="edc-qr"` also loads `qr-code-styling-1.9.2.js`** - that grep is the whole check. The
  JS branch that swallows this now opens the setup-key panel instead, so a repeat is visible to the
  user even if the library goes missing again.
* **A missing `var` in the enrolment script is invisible, not loud.** The file is strict mode, so an
  undeclared assignment throws a `ReferenceError` inside a promise chain, and its own `.catch` turns
  that into a small note at the bottom of the page. The symptom was "no QR code appears" with
  nothing in the console. Nothing in the build runs it any more, so **after editing
  `edc-enrol.js`, load it in a browser console** (or a strict-mode VM) and confirm it parses with no
  `ReferenceError`. A `node --check` will not do: it does not run the file.
* **`context.failure()` is unusable in a `RequiredActionProvider`.** After `processAction`,
  `LoginActionsService.processRequireAction` reads back whatever `context.challenge(...)` was
  handed and returns it for *both* CHALLENGE and FAILURE. A `failure()` therefore answers with a
  null challenge, and the equivalent call in
  `AuthenticationManager.actionRequired` sends `LoginProtocol.Error.CONSENT_DENIED`. To show a step
  again with an error, render the template yourself from `processAction` - which is what
  `UpdateProfile`, and every other stock action, does.
* **Backups codes are one-shot by construction, not by a flag.** A TAN token is a list of
  pre-generated codes stored hashed; presenting it is `detail.otps` from `/token/init` and there is
  no read path afterwards. "Generate a new set" therefore means delete-then-create, and it has to
  delete *first* or the old codes keep working.

## The Telegram bot

* **A Telegram long poll costs more wall-clock than its `timeout`.** `getUpdates?timeout=30` holds
  the request for 30s *after* connecting, and the connect on this deployment varies from 0.3s to 10s.
  Measured end to end: 30.3s, 31.1s, 32.2s, 39.6s. A client budget of `timeout + 5` therefore threw
  away roughly half of every poll, and each discarded poll had already cost the user 30s of waiting -
  which presents as "I scanned the code and nothing happened". The budget is now
  `timeout + LONG_POLL_HEADROOM_SECONDS` (20), the connect has its own timeout so the two are
  distinguishable, and a transport failure is retried once. Before: a `Polling error` every ~30s.
  After: none.
* **One Telegram account must belong to exactly one Keycloak user, and the user attribute is the
  record that survives - not the federated identity.** Observed on this realm: a
  `federated-identity` row written for an LDAP-backed user did not persist, while
  `telegram-user-id` written in process by the very same request did. So a uniqueness check built
  on `getUserByFederatedIdentity` finds nothing and lets the *same phone* be linked to a second
  account; both then receive codes at one chat. `EdcChannelDetector.anotherUserHolding` checks both
  signals, and it guards all three doors: enrolment's `/enrolment/telegram-link`, the identity
  provider's broker callback, and `detectTelegram` itself.
* **`detectTelegram` fails closed on a shared chat.** If two accounts claim the same `telegram-user-id`
  it reports the channel as unavailable for *both* and logs an ERROR naming them, rather than
  promising delivery to a chat that belongs to someone else. That state can only be produced by
  hand - see "Telegram account already linked" in `docs/otp-flow-setup.md`.
* **Do not retry a Telegram 4xx.** `sendMessage` throws on any non-2xx and that must not be retried,
  because a rejected message (unknown chat, bad `parse_mode`) will be rejected identically forever.
  Only `IOException` is retried.
* **The admin API masks IdP secrets in `identity-provider/instances`.** The telegram
  `clientSecret` reads back as `**********`, which is not what is stored and not what the bot uses -
  the real value is in `IDENTITY_PROVIDER_CONFIG`. Testing the bot with the masked value gets a 404
  from `getMe` and looks exactly like "the bot does not exist". Read the real token from the database,
  or observe the bot's own logs.

## The telegram package is now sub-packaged

Upstream moved it, and the tree no longer matches what older notes describe:

| class | package |
| --- | --- |
| `TelegramBotClient`, `TelegramBotManager`, `TelegramBotMode`, `TelegramPollingService`, `TelegramUpdateHandler`, `TelegramWebhookPayload` | `telegram.bot` |
| `TelegramIdentityProvider(Factory)` | `telegram.idp` |
| `TelegramAuthResource(Factory)` | `telegram.rest` |
| `AuthState`, `AuthStateCache`, `AuthStateSession` | `telegram.state` |

* **A rebase across that move leaves the tree not compiling, and only the `edc` and `privacyIdea`
  files are affected** - those are the ones holding imports into `telegram`. After pulling, expect
  `cannot find symbol` in `EdcOtpDelivery` (wants `telegram.bot.TelegramBotClient`) and in
  `PrivacyIdeaWebhookResource` (wants `telegram.state.AuthState` and `AuthStateSession`). `edc` and
  `privacyIdea` did not move, so nothing warns you; the `telegram` files themselves resolve fine.
* **The `META-INF/services` files *were* resolved correctly**, so the SPI registrations are not the
  thing to check - the providers all register. Run `build:keycloak-provider` before anything else.
* **Restarting while the bind-mounted JAR is being replaced logs `Failed to read zip entry ...` from
  the outgoing container.** That is the previous generation trying to load a class the new JAR has
  already moved, not a live fault. Ignore it unless it appears *after* the newest
  `started in ... Listening on` line.

## Codes were deliverable exactly once per token

**Email and Telegram codes stopped arriving after the first successful sign-in, while the OTP page
still rendered normally.** The privacyIDEA execution creates the challenge and calls
`/validate/triggerchallenge`, expecting privacyIDEA to fire the `validate_triggerchallenge` event our
webhook listens for. privacyIDEA only re-triggers that event while the token's *current* challenge is
still live, so once a code is used the challenge is answered and every later call answers `0`: no
event, no PIN written, no mail, no bot message. The page still renders, so it presents a code field
that can never be completed.

```
09:42:22  triggerchallenge -> webhook fired -> setpin -> mail captured
09:42:35  validate/check   -> success, PIN consumed
09:43:51  triggerchallenge -> no webhook, no setpin, no mail
```

`EdcMfaChannelsAuthenticator.issueSignInCode` now writes the PIN and sends it itself, before the OTP
step, using `EdcOtpDelivery.issue` - the path enrolment and `/resend` already used. Two consequences
worth knowing:

* **`triggerchallenge` is still a no-op** after a code is used. Nothing relies on it now, but do not
  read its `0` as a broken integration.
* **It fires on every sign-in for a user with a SPASS-backed channel** - email *or* Telegram, since
  both ride the same `spass` token - and never while enrolment is owed, because then the wizard runs
  instead of the OTP page and a code would arrive with nowhere to enter it. TOTP is skipped: the
  authenticator app generates its own code.

## Two things that survive nothing but a running stack

* **`themes/khalibre/email/theme.properties` is generated and gitignored, and a rebase can take it
  with it.** When it goes, *every* email fails with
  `TemplateNotFoundException: Template not found for name "html/template.ftl"`, which surfaces as
  `EmailException: Failed to template html email` from `EdcOtpDelivery.sendEmail` and takes the
  plain-text part with it. The symptom is "the email code is not sent", with nothing in the Keycloak
  log above the stack trace. Regenerate it with the role, not by hand:
  ```
  docker compose -f setup-docker-compose.yml run --rm ansible-ee \
    ansible-playbook ansible/playbook.yml --tags env
  ```
  That tag is safe - it only renders `.env`, the MariaDB config, the encfile and this file, with no
  vault or cert work. Check `emailBaseUrl` came out as `https://<KEYCLOAK_HOST>`.
* **The Telegram bot has to be re-armed after every Keycloak restart.** `postInit` is deliberately a
  no-op, so nothing starts it; the symptom is a silent one - the bot simply is not polling, and the
  first code "not arriving" looks like a delivery bug rather than a bot that never started. No log
  line says so. Call `POST /realms/EDC/telegram-auth/telegram/init` after any restart and expect
  `[TelegramBotManager] Started polling for bot: telegram`. This is worth automating into the
  compose healthcheck or the restart task; it is not currently.
* **`GET /telegram-auth/status` used to 500 on a plain REST call.** `AuthStateSession.getAuthStateId`
  passed a null session id into `singleUseObjects().get()`, which throws rather than returning
  nothing. A request with no root authentication session has no session id, so this was the normal
  case, and `telegram-qr-link.ftl` calls the endpoint. Guarded; it now answers `404 {"EXPIRED"}`,
  which is what the endpoint already meant by that.

## No automated coverage of the enrolment rules

The JUnit suite that used to pin `hasNoUsableChannel`, `withdrawUndeliverableTelegram`, the challenge
token and the bot-token check has been deleted, and nothing in the build now exercises these rules.
That is a deliberate choice, not an oversight - do not assume a passing build means the enrolment
rules are correct. Two of them have already shipped broken:

* **A Telegram link without a privacyIDEA token read as a usable channel**, and a marker plus any
  channel read as "enrolled", so the user was signed straight in with no second factor.
* **A missing `var` in `edc-enrol.js`** rendered a TOTP screen with an empty QR frame and no error.

The cheap manual substitute is a sign-in for each of the three channels plus the checks named on the
individual rules above. `hasNoUsableChannel` and `withdrawUndeliverableTelegram` are static methods
over a plain `Map`, so they can be exercised from a scratch main class in seconds if that is wanted.

## The account console

The account console is a separate Maven/npm module (`khalibre-account-ui`) building a theme JAR, not
the login theme. It has its own PatternFly version, its own translations, and its own class of
mistakes.

* **`@patternfly/react-core` here is v5, while the login theme renders on PatternFly v4 and v3.** So
  the modal parts are `ModalBoxHeader`/`ModalBoxBody`/`ModalBoxFooter` and there is no `ModalBody`.
  `NumberInput` exists but is a *quantity stepper*, not a segmented code field — use `TextInput` with
  `inputMode="numeric"` for a fixed-length code. `ClipboardCopyButton` has no `value`: it copies from
  the element whose id you pass as `textId`, so the text has to be rendered as its own element.
* **`Page` comes from `@keycloak/keycloak-account-ui`, not from PatternFly.** The PatternFly one has
  no `description` prop, and the account one is what `AccountActivities.tsx` uses.
* **`parent=keycloak.v3` does not exist in the server image.** No `keycloak.v3` directory and no jar
  containing one, so nothing is inherited: `signingIn` and `signingInDescription` resolved to their
  raw keys, and any key not written into this module's `messages_en.properties` renders as the key
  itself. Define messages locally rather than assuming the parent supplies them.
* **Translations live in `maven-resources/theme/khalibre-account/account/messages/`.** A message
  containing markup needs `<Trans components={{ strong: <strong /> }} />`, **not** `t()`. This was
  got wrong here before: `i18n.ts` sets `escapeValue: false`, and that looks like it should make
  `<strong>` in a message render as markup. It does not. That flag governs how i18next escapes
  *interpolated variables*, not the returned string — `t()` returns a plain string, React escapes it,
  and the tag reaches the page as visible text. `<Trans>` is what maps the tag to an element, and it
  is what upstream's own `SigningIn.tsx` used.
* **Beware i18next plural keys.** Passing an option named `count` makes i18next look for
  `_one`/`_other` variants and fall back to the base key; `{{count}}` alone will not interpolate.
  The backup-code count therefore uses `{{n}}`.
* **The QR library is `qrcode`, dynamically imported** so it lands in the page's own lazy chunk
  rather than the main bundle. It is not vendored from the login theme's
  `qr-code-styling-1.9.2.js`, which is a separate copy for the FreeMarker pages.

### Authenticating an account-console endpoint

`AccountConsoleCaller.resolve` is the single gate, shared by the account-activities endpoint and the
MFA settings one. Two checks, and **the service-account check is not redundant**:

* **A `client_credentials` token in this realm already carries `aud: account`.** That was measured,
  not assumed. So the audience check passes for it and only
  `getServiceAccountClientLink() != null` rejects it. Removing that line would hand every service
  account in the realm a user's MFA settings.
* **The user is always the token's subject, never a request parameter.** An admin endpoint takes
  `?username=`; these cannot, or one user could read another's channels.

A **master-realm token is refused**, as everywhere: a provider mounted on `EDC` validates against
`EDC`'s keys. So these endpoints cannot be tested with the master admin, and — since every account
here is LDAP-federated and creating one is not safe — the happy path needs a real user's browser
session. What can be checked without credentials: the provider is registered (`401` on a real path
against `404` on an unknown one), and a temporary client with a service account is enough to confirm
both rejection branches. Temporary *clients* are safe to create and delete.

### A Telegram scan cannot be keyed the same way in both places

`TelegramAuthResource` files its `AuthState` under the root authentication session id. **A plain REST
request has none** — see the platform notes above — so that key is `null` there and
`singleUseObjects().get(null)` throws. The account console therefore keys its scan on
`"edc-mfa-settings:scan:" + user.getId()`, which is equally unforgeable because the id comes from the
verified token. The two flows do not see each other's scans.

`EdcTelegramLink` holds the write and the one-account-one-chat rule, so the enrolment wizard and the
account console cannot disagree about it. `AuthStateSession`'s `singleUseObjects().put` takes a
`Map<String, String>`, not a map of objects.

### The Email/Telegram coupling

Email and Telegram share one `spass` token. `EdcChannelDetector` reports Email as on whenever a
`spass` token exists, and the bot can only send a PIN for a token that exists — so:

* Removing Email deletes the `spass` token, which silently also withdraws Telegram
  (`withdrawUndeliverableTelegram`). The account console confirms this and reports
  `willNeedEnrolment`.
* Email cannot be offered to someone who already has Telegram, because there is nothing to switch on.
* Giving each channel its own token is the only real fix, and privacyIDEA does allow several tokens
  per user. Not done.

## The enrolled-users group

`EdcEnrolmentState.markComplete()` adds the user to the realm's MFA group, and `clear()` takes them
out of it. Both are driven from `EdcEnrolmentState` rather than from each channel's step, because
that is the one place Telegram, an authenticator app and email converge, so the group cannot drift
from the marker.

* **Group membership is the durable record of enrolment.** It lives in `USER_GROUP_MEMBERSHIP`, and
  with no LDAP group mapper attached on this realm nothing rewrites it on sync. That is the opposite
  of the `edc-mfa-*` attributes, which an admin REST delete does not survive.
* **`RealmModel` has no `getGroupByName` in KC 26.** The lookup is
  `session.groups().searchForGroupByNameStream(realm, name, true, 0, 1).findFirst()`.
* **A missing group must not fail enrolment.** `markComplete` writes the marker and removes the
  required action regardless, and the group step logs a warning naming the group it could not find.
  A blank `enrolmentGroup` falls back to `MFA` rather than joining nothing and reporting success.
* **Only service-account tokens carry role claims on this realm.** A password-grant token from
  `admin-cli` - master *or* EDC - arrives with no `realm_access` and no `resource_access`, whatever
  roles the user holds. That is why the reset endpoint cannot be exercised with a user token, and
  why granting `manage-realm` to a user and expecting it in the token wastes time.

## Unenrolled users

* **A user with no privacyIDEA token used to reach a normal-looking OTP page that could never
  succeed.** `EdcMfaChannelsAuthenticator` passed through unconditionally and `pi-form.js` only hid the
  chooser, so the six boxes, countdown and resend button all rendered. That is the population this
  deployment most needs to serve: most staff have no email address, so they have no channel at all.
* `EdcChannelDetector.hasNoUsableChannel` now derives `NOTE_ENROLMENT_REQUIRED` from the same flags,
  `/channels` exposes it as `enrolmentRequired`, and `pi-form.js` swaps the whole entry UI for an
  explanation. Verified against all nine realm users: six come back `enrolmentRequired=true`.
* **The check deliberately includes backup codes.** A user holding only unused TANs can still get in,
  so they must not be pushed back into enrolment.
* **Sign-in *is* blocked now, by the wizard rather than by this gate.** `edc-mfa-enrolment` is a
  registered required action that `edc-mfa-channels` puts on the user, and a pending required action
  stops Keycloak finishing the sign-in, so the OTP gate no longer has to. What is still only
  presentation is the OTP *page's* own behaviour - it explains rather than redirects, because the
  action runs after the browser flow, not during it. `isUserSetupAllowed()` still returns `false`; that
  governs whether an *authenticator* can be set up from the admin console and is unrelated to the
  wizard, which is a `RequiredActionProvider`.
* **Service identities are caught too.** `ldap-svc` has no tokens and comes back
  `enrolmentRequired=true`. Any non-human account that signs in through this flow will be stopped until
  someone gives it a channel, so exempt them deliberately rather than discovering it in PROD.
* **A Telegram link is not a channel - the privacyIDEA token is.** Enrolment creates a `spass`
  token for both Telegram and email, and the bot sends the PIN for that token. Delete the token -
  which privacyIDEA's own web UI does in one click - and the `telegram-user-id` attribute survives
  while the delivery path does not. Treating the attribute alone as a channel is a hole, not just a
  wrong label: a marker plus any channel reads as "enrolled", so `requiresEnrolment` returns false and
  the user is signed straight in with **no second factor at all**. Observed exactly this way -
  `extuser` reached the account page. `EdcChannelDetector.withdrawUndeliverableTelegram` now turns
  the channel off unless a `spass` token exists, and fails closed when privacyIDEA cannot be asked,
  because the cost of being wrong in that direction is a user re-enrolling rather than a user
  walking in. It has no automated test: see *No automated coverage of the enrolment rules*.
* **`EdcChannelDetector.detect()` writes to the `channels` map for the Telegram note *before*
  privacyIDEA has been asked.** Order matters now: `withdrawUndeliverableTelegram` must run after
  `detectPrivacyIdeaTokens`, or it has no `spass` signal to check.
* **Trust `USER_ATTRIBUTE` in the database, not the admin REST read.** The admin API reported
  `telegram-user-id` as present and absent for the same user within one minute, so a
  "cleaned up" attribute read back through `GET /users/{id}` means nothing. Query the table. This is
  also the real explanation for the attributes that appeared to be restored by the sync with their
  original timestamps: the delete had not happened, and the reads were flapping.
* **The enrolment state is derived, not just flagged.** `EdcEnrolmentState.requiresEnrolment` needs
  the completion marker *and* a live channel. Marker alone would let a user whose channels ICT has
  cleared walk straight through, because nothing clears the marker when the tokens go.
* **privacyIDEA realms are still `mfa`** even though the Keycloak realm is `EDC` — tokens report
  `realms: ["mfa"]` and `user_realm: "mfa"`. Queries that omit a realm parameter are unaffected, which
  is why this has never broken anything, but it is inconsistent and worth fixing deliberately.

## privacyIDEA API gotchas

* **Never send `Content-Type: application/json` on a bodyless GET.** `/token/` calls `get_json()`
  internally, so the header makes Flask raise `JSONDecodeError`, and privacyIDEA then answers **500**
  from its own error handler. It looks intermittent and server-side but is entirely the caller's
  fault. Symptom: hundreds of `Exception on /token/ [GET]` tracebacks, no useful application error.
* **`Authorization` is the raw JWT with no `PI ` prefix.** `PI <jwt>` and `Bearer <jwt>` both give
  `401` (error 4304). `PrivacyIdeaService` already does this correctly; copy it rather than guessing.
* **Deleting a token is `DELETE /token/?serial=…`, with no `Content-Type` header.** `/token/delete`
  answers `405` for both GET and POST, and `DELETE /token/` with a JSON body answers `405` too.
* **Token *type* filters are case-insensitive** (`type=tan`, `TAN` and `Tan` all match) — the
  awkwardness is that the filter accepts them, not that it is case-sensitive.
* **Audit `client` column is the reverse-proxy address, not the real caller.** A browser action
  through Traefik is recorded as `10.100.100.10` (the Traefik container), which makes it look like
  some mystery server-side process did it. Cross-check the Keycloak log before blaming the provider.

* **A greyed-out channel row was still clickable, because `disabled` was keyed on the wrong
  variable.** `edc-mfa-enrol-choose.ftl` gated the email radio's `disabled` attribute on
  `!telegramAvailable` while the `edc-option-off` class that greys the row was correctly gated on
  `!emailAvailable`. So the appearance and the behaviour disagreed: Email looked unavailable and was
  not, and — had it been read the other way — a user with a perfectly good address would have had
  Email disabled whenever Telegram was configured. A label wrapping a radio toggles it on click, so
  only the attribute stops it; `opacity` and a class do not.
* **Every unavailable channel needs a server-side guard, not just a disabled input.** The email
  branch already had one (`hasEmailAddress`, with a comment saying a crafted POST could reach it) and
  the Telegram branch did not, so `channel=telegram` on a realm with no bot token would have opened a
  QR the bot can never answer. Both are now checked in `choose()`.

## This login theme's CSS

* **The theme chain is `khalibre` → `keycloak` → `base`, so the page loads PatternFly v4 and v3.**
  `pf-v5-c-button` and friends match no stylesheet at all. Always take button classes from the
  properties instead - `${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}
  ${properties.kcButtonBlockClass!}` - which is what every stock Keycloak template does and what
  keeps a new screen consistent with the rest of sign-in.
* **`custom.css` has `.login-pf-page label { display: inline-block; ... }` at specificity (0,1,1).**
  A bare `.edc-option` at (0,1,0) silently loses to it, so a `<label>` styled as a flex row stacks
  its contents instead. Scope anything that competes with that rule under a second class, or match
  its specificity.
* **The navy button on the sign-in screens comes from an `#kc-login` rule**, not from a shared
  button style, so a new screen has no navy unless it adds `.edc-primary`. That rule is written as
  `.login-pf-page button.edc-primary` because PatternFly's `.pf-c-button.pf-m-primary` is two
  classes and would otherwise win.
* **To review a login screen, screenshot the real HTML.** Sign in, save the rendered page, rewrite
  its `/resources/...` hrefs to absolute URLs, and screenshot with `google-chrome --headless
  --screenshot`. A hand-built DOM gives false results - `properties.*` resolve to different class
  names than you would guess. The only thing an offline capture cannot show is the QR code, whose
  fetch is same-origin.

## Per-environment vs per-locale configuration

* **`themes/khalibre/email/theme.properties` is generated and gitignored.** It is rendered from
  `email-theme.properties.j2` by the `generate_creds` role, with `emailBaseUrl` coming from
  `keycloak_public_base_url` in `vars.yml` - which derives from `keycloak_host`, the same variable
  `.env` takes `KEYCLOAK_HOST` from, so the two cannot disagree for a given host. Themes arrive by
  bind mount (`./themes/khalibre:/opt/keycloak/themes/khalibre`), so each host reads its own copy and
  no environment hostname is ever committed.
* **`parent=base` in that file is load-bearing, not decorative.** `password-reset.ftl` and
  `privacyidea-otp.ftl` both wrap their body in `<@layout.emailLayout>` from the base email theme's
  `template.ftl`, so deleting the file breaks every email, not just branding. It is produced by the
  same playbook task list as `.env`, and the stack cannot start without `.env` anyway.
* **Keycloak-generated mail needs that file because admin config cannot reach it.**
  `FreeMarkerEmailTemplateProvider` binds a fixed model - `properties`, `url`, `msg`, `locale`, `user`,
  `realmName`, `link` - with no realm bean and no authenticator configuration, and a FreeMarker
  template cannot read environment variables. A theme property is the only per-environment value such
  a template can reach. The OTP mail, which our own provider renders, does not use the file: it gets
  the value injected as `otpEmailBaseUrl` from the `publicBaseUrl` field on the EDC MFA Channels
  execution.
* **Overriding `EmailTemplateProvider` to inject the value instead breaks password reset. Do not
  retry it.** The SPI is internal (Keycloak logs it as `KC-SERVICES0047 ... internal SPI
  emailTemplateProvider`). Registering a replacement factory makes
  `session.getProvider(EmailTemplateProvider.class)` return `null`, and `ResetCredentialEmail.authenticate`
  then dies on `provider.setRealm(...)` with a `NullPointerException`, so the reset mail is never
  sent. This happens under a distinct id *and* under the built-in id `"email"` - overriding the id
  does not help.
* **Admin-config values live in the Keycloak database, so they travel with a DB restore.** A PROD
  database restored from a dev backup carries dev's `webhookSecret` and `publicBaseUrl`, and nothing
  warns you. Host-local generated files cannot have that problem.
* **Locale files** (`messages_*.properties`) are shared across environments - never put a host or
  a path in them.
* **Per-environment values** belong in `.env`/`docker-compose.yml`, in a generated file, or in admin
  config for the authenticator. Never hand-edit a generated file, and never commit one.

## Verification notes

* **Nothing in the build runs the enrolment rules any more.** The JUnit suite and the strict-mode JS
  check are both gone, so `build:keycloak-provider` is compile-only. The four
  `edc-mfa-enrol-*.ftl` templates were verified once, by parsing and rendering them against a stub
  model with a real FreeMarker jar - that is what caught them being structurally fine, and it is not
  a repeatable harness. The vendor `privacyIDEA.ftl` and the base `template.ftl` were never covered,
  so a template change there still fails only at request time. To re-check the templates, either walk
  the wizard in a browser or rebuild that harness.
* **Getting that harness to render needs the base login theme.** `template.ftl` imports `footer.ftl`,
  which lives in the `parent=keycloak` theme inside
  `/opt/keycloak/lib/lib/main/org.keycloak.keycloak-themes-26.1.3.jar`. Extract it to a scratch
  directory and register it as a second `FileTemplateLoader`, or every render dies on the import.
  Also stub `?no_esc` and set `HTMLOutputFormat`, or `template.ftl` fails to parse for reasons that
  have nothing to do with your change.
* **Theme edits need a restart.** Templates and messages are cached by the running server, so a
  change under `themes/khalibre/` is not visible until Keycloak restarts. Provider JAR changes also
  need one, though the JAR is bind-mounted.
* When verifying a template offline, render it against a stub data model to catch both syntax
  errors and runtime dereferences of variables Keycloak never binds. Keep the stub's bean shapes
  aligned with the real ones — an over-permissive stub (for example one inventing `url.realmUrl`,
  which does not exist) validates a template that fails in production.
* **A FreeMarker range needs a number.** `<#list 1..codeLength>` compiles and then throws when
  `codeLength` arrived as a string from `setAttribute`. Pass the `int` and render it with `?c`.
* Web templates render against `authenticationForm`, a bean; email templates render against
  attributes injected by the sender, and only receive `realmName`, not a `realm` bean. Different
  models, different failure modes.
* `pi-form.js` can be exercised headlessly in Node with a minimal DOM stub in a `vm` context. Two
  bugs this caught: intervals stacking on every resend, and duplicate submissions. Note that
  `formResult` is declared by an inline `<script>` in `privacyIDEA.ftl`, not in the JS file, so a
  stub must supply it.
* The OTP page is only reachable after valid AD credentials, so browser verification of it needs a
  real user. Automated checks cannot replace it. Driving the forgot-password flow end to end does
  not need credentials: create a temporary public client with `redirectUris: ["*"]`, bind it to the
  `PrivacyIDEA` flow, and follow the reset link. Delete the client afterwards.