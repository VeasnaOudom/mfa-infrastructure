# MFA Infrastructure

This project provisions and runs a Multi-Factor Authentication (MFA) stack using Keycloak and PrivacyIDEA.

Docker Compose runs the services. Mise runs the commands. Ansible generates the local runtime files from Vault-backed variables.

## Architecture

* **Traefik**: Reverse proxy handling HTTP/HTTPS routing.
* **Keycloak**: Identity and Access Management (IAM) server (version 26+).
* **PrivacyIDEA**: Two Factor Authentication system.
* **MariaDB**: Centralized database backend for both Keycloak and PrivacyIDEA.
* **smtp4dev**: Internal SMTP catcher and web inbox for test mail.

## Prerequisites

1. [Docker](https://docs.docker.com/engine/install/) and Docker Compose
2. [Mise](https://mise.jdx.dev/getting-started.html) installed on the host
3. Access to HashiCorp Vault for fetching credentials

## Deploy

Generate runtime files and start the stack:

```bash
mise run start
```

This generates `.env`, certificates, PrivacyIDEA encfile, MariaDB config, renders the Keycloak Dockerfile, builds the custom Keycloak image, creates `keycloak-providers/`, builds provider/theme JARs into it, and then starts Docker Compose. If Ansible downloads a database backup, the task prints the restore command.

### Access URLs

* **Keycloak**: `https://keycloak-mfa.crosswired.me`
* **PrivacyIDEA**: `https://pi-mfa.crosswired.me`
* **Mail Inbox**: `https://mfa-mail.crosswired.me`
* **Traefik Dashboard**: `http://localhost:8080`

Internal SMTP endpoint for containers on the stack network: `smtp4dev:25`.

Generated MariaDB config is written to `config/mariadb/conf.d/`. The generated root `Dockerfile` and MariaDB config are ignored by git.

## Configuration

`mise run start` brings the stack up, but the PrivacyIDEA OTP flow needs one-off configuration on both
Keycloak and privacyIDEA before it will authenticate anyone: an authentication flow with two custom
authenticators, a privacyIDEA resolver, and a shared secret that has to match in two places. There is
no privacyIDEA event handler to configure — code delivery happens inside Keycloak.

**[docs/otp-flow-setup.md](docs/otp-flow-setup.md)** — step-by-step setup for both systems, plus how to
verify it without needing a real user's credentials.

## Tasks

Run tasks with `mise run <task>`.

| Task | Description |
|---|---|
| `start` | Generate runtime files, build Keycloak/provider assets, and start the stack |
| `start:services` | Start Compose services without Ansible |
| `stop` / `restart` / `down` | Stop, restart, or remove containers |
| `start:keycloak` / `stop:keycloak` / `logs:keycloak` | Manage Keycloak |
| `start:mariadb` / `stop:mariadb` / `logs:mariadb` | Manage MariaDB |
| `start:pi` / `stop:pi` / `logs:privacyidea` | Manage PrivacyIDEA |
| `start:mail` / `stop:mail` / `logs:mail` | Manage smtp4dev |
| `build:keycloak` | Render Dockerfile and build custom Keycloak image |
| `build:keycloak-providers` | Create `keycloak-providers/`, then build the provider JAR and the khalibre-account-ui theme JAR into it |
| `build:keycloak-provider` | Build the Keycloak provider JAR (runs tests) |
| `build:khalibre-account-ui` | Build the khalibre-account-ui theme JAR and copy it to `keycloak-providers/` |
| `deploy:khalibre-account-ui` | Build the khalibre-account-ui theme JAR and restart Keycloak to load it |
| `build:khalibre-admin-ui` | Build the khalibre-admin-ui theme JAR (downloads the pinned Keycloak console source on first run) and copy it to `keycloak-providers/` |
| `deploy:admin-ui` | Build the khalibre-admin-ui theme and restart Keycloak to load it |
| `deploy:keycloak-provider` | Build and deploy the provider JAR into the running Keycloak container |
| `ps` / `pull` | Show containers or pull images |
| `db:export` | Create a full MariaDB physical backup in `databases/export/` |
| `db:restore [file]` | Restore the newest backup, or a specific `.tar.gz` file |
| `clean` | Remove containers, volumes, generated files, and DB backups |

## Keycloak Provider

The `keycloak-provider/` module contains custom Keycloak identity providers. After making changes:

```bash
# Build only
mise run build:keycloak-provider

# Build and deploy to the running Keycloak container (auto-restarts Keycloak)
mise run deploy:keycloak-provider
```

The provider JAR is copied into `keycloak-providers/`, which is mounted into the Keycloak container at
`/opt/keycloak/providers` so it's available on container start.

## Keycloak Providers

`keycloak-providers/` is the folder bind-mounted at `/opt/keycloak/providers`. It is gitignored (only
`.gitkeep` is tracked), so it is created and populated automatically before Keycloak starts:

```bash
# Create keycloak-providers/ and build every JAR into it
mise run build:keycloak-providers
```

This runs on every `mise run start` and `mise run start:keycloak`, and produces:

| JAR | Source |
|---|---|
| `keycloak-provider-1.0.0.jar` | `keycloak-provider/` (Gradle `assemble`, tests skipped) |
| `khalibre-account-ui-26.1.3.jar` | `khalibre-account-ui/` (npm + Maven) |
| `khalibre-admin-ui-26.1.3.jar` | `khalibre-admin-ui/` (built on demand, see below) |

The admin console theme is **not** part of `build:keycloak-providers`: it needs a checkout of Keycloak's
own JS sources the first time it runs, which takes several minutes. Build it when you want the EDC MFA
page in the console.

## Khalibre Admin UI

`khalibre-admin-ui/` is the administration console plus one page: **EDC MFA** under Configure, where
ICT switches the four channels (Email, Telegram, Authenticator app, Backup codes) on and off for the
realm. The page talks to `GET/POST /realms/EDC/edc-mfa-admin/channels` in `keycloak-provider/`.
`POST /realms/EDC/edc-mfa-admin/reset` — resetting one user's MFA — stays curl-only for now; it is
moving to a per-user screen under Users.

```bash
# Build the theme JAR and copy it to keycloak-providers/
mise run build:khalibre-admin-ui

# Build and restart Keycloak so it serves the new console
mise run deploy:admin-ui
```

The admin console is a React app with no plugin hook, so this is a **scripted patch of a pinned
checkout** rather than a fork. On first use the task downloads `keycloak-26.1.3` into `build/`
(gitignored), installs its dependencies with the pnpm version it pins, copies `khalibre-admin-ui/src/mfa/`
into the checkout, and patches three files: `src/routes.tsx`, `src/PageNav.tsx` and `vite.config.ts`.
Each edit replaces an exact anchor and fails loudly if the anchor has moved, so an upstream upgrade that
moved something stops the build instead of producing a console with no EDC page in it. The Vite build
that follows also type-checks the page, under `strict: true`.

| Path | What it is |
|---|---|
| `src/mfa/` | The page: `MfaChannels.tsx`, its route object, and the API calls |
| `scripts/patch-admin-ui.mjs` | Copies the page into the checkout and applies the three edits (idempotent) |
| `maven-resources/` | `keycloak-themes.json`, the theme's `theme.properties`, and its messages |
| `pom.xml` | Packages the built console into `khalibre-admin-ui-26.1.3.jar` |

Set `KEYCLOAK_JS_DIR` to point at a checkout you already have; otherwise the task fetches it.

**Activating it.** A realm's console runs the theme named in that realm's `adminTheme` setting - there
is no `--spi-theme-default-admin` in KC 26. `EDC` is set to `khalibre-admin`, so its console serves the
page; `master` is left on the stock console. It lives in the database (`REALM.ADMIN_THEME`), so a
restored backup carries it and an older backup does not:

```bash
# what the realm is set to
docker exec mfa-mariadb mariadb -uroot -p"$MYSQL_ROOT_PASSWORD" -N -B \
  -e "SELECT name, ADMIN_THEME FROM keycloak.REALM;"

# back to the stock console
docker exec mfa-mariadb mariadb -uroot -p"$MYSQL_ROOT_PASSWORD" -e \
  "UPDATE keycloak.REALM SET ADMIN_THEME=NULL WHERE NAME='EDC';"
docker restart mfa-keycloak
```

## Khalibre Account UI

`khalibre-account-ui/` is the Vite/React account UI theme, built on the official
`@keycloak/keycloak-account-ui` package (pinned to the server version, `26.1.3`).

```bash
# Build the theme JAR and copy it to keycloak-providers/
mise run build:khalibre-account-ui

# Build and restart Keycloak so it serves the new bundle
mise run deploy:khalibre-account-ui
```

The build runs `npm install` → `vite build` → `mvn package`, which bundles `dist/` and
`maven-resources/` into `target/khalibre-account-ui-26.1.3.jar`. The JAR is then copied to
`keycloak-providers/`, so `mise run start` picks it up automatically.

### Local development (HMR)

For quick iteration, run the Vite dev server and let Keycloak serve the account console from it —
no JAR rebuild, no redeploy:

```bash
mise run dev:account-ui          # Vite on 0.0.0.0:5173 + Keycloak with KC_ACCOUNT_VITE_URL
mise run dev:account-ui:stop     # back to the bundled theme JAR
```

Then open `https://<KEYCLOAK_HOST>/realms/<realm>/account` — the task prints the exact URL.
Do **not** open `http://localhost:5173` in the browser: it returns 404 by design, because
Keycloak injects the dev-server scripts into the account page rather than serving the app itself.

How it works: in dev mode (`start-dev`) Keycloak exposes `KC_ACCOUNT_VITE_URL` to the account
theme as the `devServerUrl` template variable, and `index.ftl` then loads `/@vite/client`,
`/@react-refresh`, `/@vite-plugin-checker-runtime` and `/src/main.tsx` from that URL. No
requests are proxied through Keycloak, so the URL has to be reachable from the browser:
`http://localhost:5173` (not `host.docker.internal`, which only resolves inside Docker), and Vite
must listen on `0.0.0.0` as the task does. The HMR websocket also connects directly to
`http://localhost:5173`.

This uses `docker-compose.dev-account-ui.yml` as a compose overlay, which sets
`KC_ACCOUNT_VITE_URL` on the `keycloak` service. Dependencies are installed on first run; if `npm`
is not found, the task loads nvm.

Use `mise run deploy:khalibre-account-ui` when you want the change baked into the theme JAR.

## Backup and Restore

**Export Database**:

```bash
mise run db:export
```

This dumps only the application databases (Keycloak and PrivacyIDEA — not MariaDB's internal system tables) and compresses them into `databases/mariadb_backup_<timestamp>.tar.gz`.

**Restore Database**:

```bash
mise run db:restore                                              # restores the most recent backup in databases/
mise run db:restore databases/mariadb_backup_20260914_123456.tar.gz   # restores a specific backup
```

After restoring, the task automatically resyncs MariaDB's internal healthcheck credentials and waits for the container to report `healthy` before exiting.
