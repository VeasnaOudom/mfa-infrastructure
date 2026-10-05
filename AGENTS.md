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
  `...Authentication.AuthenticatorFactory`, `...services.resource.RealmResourceProviderFactory`,
  and `...broker.provider.IdentityProviderFactory`. The path is `authentication/`, not
  `services/`, for authenticators.
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

* **There is no automated template or token check in this repo.** `mise run deploy:keycloak-provider`
  only builds the JAR, copies it into `keycloak-providers/`, and restarts Keycloak. A
  FreeMarker parse/render harness and a challenge-token test suite existed earlier and were
  deliberately removed, so a template that cannot parse will only fail at request time. Rebuild
  them if this becomes a recurring problem.
* **Theme edits need a restart.** Templates and messages are cached by the running server, so a
  change under `themes/khalibre/` is not visible until Keycloak restarts. Provider JAR changes also
  need one, though the JAR is bind-mounted.
* When verifying a template offline, render it against a stub data model to catch both syntax
  errors and runtime dereferences of variables Keycloak never binds. Keep the stub's bean shapes
  aligned with the real ones — an over-permissive stub (for example one inventing `url.realmUrl`,
  which does not exist) validates a template that fails in production.
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