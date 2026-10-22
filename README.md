# gopasszk

A zero-knowledge password manager for the terminal. It runs on Linux and Windows.

Your master password never leaves your machine. Every username and password is encrypted on your computer before it is sent, so the server only ever stores data it cannot read. If the database leaks, the attacker gets opaque blobs.

```
$ gopass add
Master password:
Site: github.com
Username: alice
Password to store (Enter to generate):
Generate a random password? [Y/n]: y
Length [20]:
Generated a 20-character password.
Added: 12
```

## Contents

**Using gopass**
- [Install](#install)
- [Getting started](#getting-started)
- [Commands](#commands)
- [Update and uninstall](#update-and-uninstall)
- [Troubleshooting](#troubleshooting)
- [How your data is protected](#how-your-data-is-protected)

**Developing gopass**
- [Architecture](#architecture)
- [Crypto and auth flow](#crypto-and-auth-flow)
- [Database](#database)
- [Project structure](#project-structure)
- [Local development](#local-development)
- [Configuration](#configuration)
- [API reference](#api-reference)
- [Testing](#testing)
- [Releasing and deploying](#releasing-and-deploying)

---

## Install

Pick your platform and paste the block into a terminal. The released app already points at the hosted server, so there is nothing to configure.

### Linux

```sh
arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
mkdir -p ~/.local/bin
curl -fsSL "https://github.com/madhavv-xd/gopasszk/releases/latest/download/gopass-linux-$arch" -o ~/.local/bin/gopass
chmod +x ~/.local/bin/gopass
gopass help
```

If `gopass: command not found`, add `~/.local/bin` to your PATH and open a new terminal:

```sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

For `gopass copy`, install a clipboard tool: `xclip`, `xsel`, or `wl-clipboard` on Wayland. For example, `sudo apt install xclip`.

### Windows (PowerShell)

```powershell
$dir = "$env:LOCALAPPDATA\gopass"
New-Item -ItemType Directory -Force $dir | Out-Null
Invoke-WebRequest https://github.com/madhavv-xd/gopasszk/releases/latest/download/gopass-windows-amd64.exe -OutFile "$dir\gopass.exe"
```

On your **first install only**, add it to your PATH:

```powershell
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:LOCALAPPDATA\gopass", "User")
```

Close the terminal, open a new one, and run `gopass help`.

### From source

This needs [Go](https://go.dev/dl/) 1.26 or newer:

```sh
go install github.com/madhavv-xd/gopasszk/cmd/gopass@latest
```

Source builds default to `http://localhost:8080`. To use the hosted server, set `GOPASS_SERVER=https://gopasszk.onrender.com` (see [Configuration](#configuration)).

---

## Getting started

1. **Create an account:**

   ```sh
   gopass register
   ```

   Pick a strong master password. You will then see a **24-word recovery phrase, shown only once**. Write it down and keep it somewhere safe. It is the only way back in if you forget your master password.

2. **Log in:**

   ```sh
   gopass login
   ```

3. **Save your first password:**

   ```sh
   gopass add
   ```

   gopass can generate a strong random password for you.

4. **Get it back when you need it:**

   ```sh
   gopass list          # see your sites and their IDs
   gopass copy 12       # copy the password for ID 12 (clipboard clears after 30s)
   ```

Prefer menus to commands? Run `gopass` with no arguments to open the full-screen terminal UI.

> **Forgot your master password?** Run `gopass recover` and enter your recovery phrase.
> If you lose **both** the password and the phrase, your data cannot be recovered by anyone. This is by design.

---

## Commands

| Command | What it does |
|---|---|
| `gopass` | Open the full-screen terminal UI |
| **Account** | |
| `gopass register` | Create an account. Shows your recovery phrase once |
| `gopass login` | Log in and remember your session |
| `gopass logout` | Forget the saved session on this machine |
| `gopass passwd` | Change your master password |
| `gopass recover` | Reset a forgotten master password using your recovery phrase |
| **Credentials** | |
| `gopass add` | Add a credential (can generate a password) |
| `gopass list` | List your sites and IDs (nothing decrypted) |
| `gopass search <term>` | Find credentials by site name |
| `gopass show <id>` | Show one credential, decrypted |
| `gopass copy <id>` | Copy a password to the clipboard. It is cleared after 30 seconds |
| `gopass edit <id>` | Change a credential |
| `gopass delete <id>` | Delete a credential |
| **Tools** | |
| `gopass generate [len]` | Print a random password (default length 20) |
| `gopass audit` | Find weak, reused, and breached passwords |
| `gopass help` | Show help |

Commands that read your vault ask for your master password each time. The decryption key is never saved to disk.

`audit` checks for breaches with [Have I Been Pwned](https://haveibeenpwned.com/Passwords) using k-anonymity. Only the first 5 characters of each password's SHA-1 hash are sent, never the password.

---

## Update and uninstall

**Update:** run the same download command from [Install](#install) again. It always fetches the latest release. On Windows, skip the PATH step.

**Uninstall on Linux:**

```sh
rm ~/.local/bin/gopass
rm -rf ~/.config/gopass        # saved session
```

**Uninstall on Windows (PowerShell):**

```powershell
Remove-Item -Recurse "$env:LOCALAPPDATA\gopass"   # the app
Remove-Item -Recurse "$env:APPDATA\gopass"        # saved session
```

Uninstalling does not delete your account or vault. They stay on the server, encrypted.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| First command after a while takes ~30 seconds | The hosted server sleeps when idle and is waking up. Later commands are fast. |
| `gopass: command not found` / `not recognized` | The install folder is not on your PATH. See the PATH step in [Install](#install), then open a **new** terminal. |
| `GOPASS_SERVER must use https` | `GOPASS_SERVER` is set to a plain `http://` address. Use `https://`, or unset it to use the built-in server. |
| `copy` fails on Linux | Install `xclip`, `xsel`, or `wl-clipboard`. |
| `unauthorized` | Your saved session is older than 24 hours. Run `gopass login`. |

---

## How your data is protected

- Your master password is turned into two separate keys on your machine. One proves who you are to the server. The other unlocks your vault and **never leaves your computer**.
- Usernames and passwords are encrypted with AES-256-GCM before they are sent. The server cannot decrypt them.
- The server hashes your login proof again with Argon2id before storing it.
- The server doesn't reveal whether an email has an account: unknown emails get the same responses as real ones.

The technical details are in [Crypto and auth flow](#crypto-and-auth-flow).

---

# Developing gopass

## Architecture

```
┌──────────────────────────┐   HTTPS / JSON    ┌──────────────────────────┐      ┌────────────┐
│  gopass CLI  (client)    │ ────────────────► │  API server (Gin)        │ ───► │ PostgreSQL │
│                          │                   │                          │      │            │
│  master password         │                   │  handlers                │      │ users      │
│   ├─ Argon2id(salt|auth) ┼─► auth hash ────► │   └─ middleware (JWT)    │      │ credentials│
│   └─ Argon2id(salt|enc)  │   (sent)          │       └─ repository      │      │            │
│        └─ AES-256-GCM    ┼─► ciphertext ───► │  re-hashes auth hash     │      │ hash + blob│
│  vault key: local only   │   (opaque)        │  never sees the key      │      │ only       │
└──────────────────────────┘                   └──────────────────────────┘      └────────────┘
```

| Layer | Package | Responsibility |
|---|---|---|
| CLI | `cmd/gopass`, `internal/tui`, `internal/vault`, `internal/client`, `internal/crypto` | Prompts and full-screen UI, key derivation, encrypt/decrypt, session file, HTTP calls |
| Routing | `cmd/server` | Wires routes, Swagger UI |
| Handlers | `internal/handlers` | Request validation, response mapping (methods on `Handler`) |
| Middleware | `internal/middleware` | `RequireAuth`: validates Bearer JWT, sets `userID` |
| Auth | `internal/auth` | Server-side Argon2id hash/verify, JWT, deterministic fake salts |
| Repository | `internal/repository` | Plain functions taking `*gorm.DB`, no interfaces |
| Models | `internal/models` | `User`, `Credential` |

## Crypto and auth flow

The client never uses the master password directly as the vault key. Instead, a random **vault key** encrypts all credentials. The server stores that key *wrapped* (encrypted) in two ways:

| Value | Derived from | Used for | Leaves the client? |
|---|---|---|---|
| Auth hash | Argon2id(`salt ‖ "auth"`) | Proving identity at login | Yes (server hashes it again) |
| Password key | Argon2id(`salt ‖ "enc"`) | Wraps/unwraps the vault key | **Never** |
| Vault key | Random 32 bytes | AES-256-GCM encrypt/decrypt of credentials | **Never** (only wrapped) |
| Recovery wrap key + recovery auth hash | HKDF of the 24-word recovery phrase | Wraps the vault key a second way; proves you hold the phrase | Auth hash only |

**Register:** the client generates a salt, a vault key and a 24-word BIP-39 recovery phrase. It sends `{email, salt, auth_hash, wrapped_vault_key, recovery_wrapped_key, recovery_auth_hash}`. The phrase is shown once and never sent. The server hashes the auth hashes again with Argon2id (PHC string) and stores them.

**Login:** the client calls `GET /salt?email=...`, derives the auth hash again and calls `POST /login`. The server verifies it and returns an HS256 JWT (24h, `user_id` claim) plus the wrapped vault key. The client unwraps the vault key with the password key.

**Change password (`passwd`):** the vault key is re-wrapped under a new password key with a new salt. Credentials are untouched.

**Forgot password (`recover`):** the recovery phrase proves identity (`POST /recover/key`). The client unwraps the vault key with it, then re-wraps it under a new password (`POST /recover/reset`). The existing recovery phrase keeps working.

**Vault entries:** username and password are encrypted client-side. The wire format is `base64(nonce[12] ‖ ciphertext+tag)`. The server only checks the decoded length (28-4096 bytes).

**Anti-enumeration:**
- `GET /salt` for an unknown email returns a deterministic fake salt, `HMAC-SHA256(SALT_HMAC_SECRET, email)[:16]`.
- `POST /login` for an unknown email still runs an Argon2 verify against a dummy hash and returns the same 401.

**Ownership:** the credential owner always comes from the JWT, never from the request body. Every credential query is scoped by `id AND user_id`, so another user's row looks the same as a missing one (404).

## Database

PostgreSQL 16. Locally it runs from `docker-compose.yml` (service `db`, port 5432, named volume `pgdata`). Any hosted Postgres also works through the `DB_*` variables. The schema is created by `go run ./cmd/migrate` (GORM AutoMigrate, the only schema mechanism).

| Table | Columns of note |
|---|---|
| `users` | `id` (uuid), `email` (unique), `salt`, `auth_hash`, `wrapped_vault_key`, `recovery_wrapped_key`, `recovery_auth_hash` |
| `credentials` | `id`, `user_id`, `site_name`, `username_ciphertext`, `password_ciphertext` |

Everything sensitive is a hash or ciphertext. There is no `ON DELETE CASCADE` on `credentials.user_id`.

## Project structure

```
cmd/
  server/      API server
  gopass/      terminal client
  migrate/     GORM AutoMigrate (User, Credential)
  dbtest/      DB connectivity check
  cryptotest/  crypto sanity check
internal/
  audit/       weak / reused / breached password checks
  auth/        argon2 hash, JWT, salt
  client/      HTTP client used by the CLI
  config/      .env + env var loading
  crypto/      key derivation, AES-GCM, recovery phrase
  database/    Postgres connection
  handlers/    HTTP handlers
  middleware/  JWT auth middleware
  models/      GORM models
  pwgn/        random password generator
  repository/  DB queries
  tui/         full-screen terminal UI
  vault/       client-side vault operations shared by CLI and TUI
docs/          Swagger (generated by swag, do not hand-edit)
.github/workflows/release.yml   builds and publishes CLI binaries on tag push
Dockerfile                      server image (runs migrate, then server)
docker-compose.yml              local Postgres
```

## Local development

**Prerequisites:** Go 1.26+, Docker (for Postgres), and optionally [`swag`](https://github.com/swaggo/swag) to regenerate the API docs.

1. Create a `.env` at the repo root. It is gitignored:

   ```env
   POSTGRES_USER=gopass
   POSTGRES_PASSWORD=change-me
   POSTGRES_DB=gopass
   SALT_HMAC_SECRET=<long random string>
   JWT_SECRET=<long random string>
   ```

   Generate the secrets with `openssl rand -hex 32`.

2. Start Postgres and create the schema:

   ```sh
   docker compose up -d
   go run ./cmd/migrate        # the only schema mechanism
   go run ./cmd/dbtest         # optional: connectivity check
   ```

3. Run the server and the CLI:

   ```sh
   go run ./cmd/server         # API on :8080
   go run ./cmd/gopass         # in another terminal, talks to localhost:8080
   ```

   Health check: `http://localhost:8080/health`. Swagger UI: `http://localhost:8080/swagger/index.html`.

## Configuration

**Server:** the server reads these from `.env` (found by walking up from the cwd) or from the process environment. It refuses to start if a required variable is missing.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `POSTGRES_USER` | yes | | DB user |
| `POSTGRES_PASSWORD` | yes | | DB password |
| `POSTGRES_DB` | yes | | DB name |
| `SALT_HMAC_SECRET` | yes | | Key for fake-salt HMAC |
| `JWT_SECRET` | yes | | HS256 signing key |
| `DB_HOST` | no | `localhost` | Postgres host |
| `DB_PORT` | no | `5432` | Postgres port |
| `DB_SSLMODE` | no | `disable` | Postgres sslmode (`require` for hosted DBs) |
| `PORT` | no | `8080` | Server listen port |

**CLI:**

| Variable | Default | Purpose |
|---|---|---|
| `GOPASS_SERVER` | release builds: `https://gopasszk.onrender.com`, source builds: `http://localhost:8080` | API base URL. No trailing slash. Plain `http` is allowed only for `localhost` / `127.0.0.1`. |

```sh
GOPASS_SERVER=https://vault.example.com gopass login            # Linux
$env:GOPASS_SERVER = "https://vault.example.com"; gopass login  # PowerShell
```

The CLI stores `{email, token}` at `os.UserConfigDir()/gopass/session.json`.

## API reference

Interactive docs live at `/swagger/index.html`.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | no | Liveness check |
| POST | `/register` | no | Email, salt, auth hash, wrapped keys, recovery auth hash; 409 if the email exists |
| GET | `/salt?email=` | no | Real or deterministic fake salt |
| POST | `/login` | no | `{email, auth_hash}`; returns JWT and wrapped vault key |
| POST | `/recover/key` | no | `{email, recovery_auth_hash}`; returns recovery-wrapped vault key |
| POST | `/recover/reset` | no | Set a new salt, auth hash and wrapped key using the recovery proof |
| PUT | `/me/password` | Bearer | Change master password (old auth hash + new salt/hash/wrapped key) |
| GET | `/me` | Bearer | Current user |
| POST | `/credentials` | Bearer | `{site_name, username_ciphertext, password_ciphertext}` |
| GET | `/credentials` | Bearer | List your credentials |
| PUT | `/credentials/:id` | Bearer | Update a credential |
| DELETE | `/credentials/:id` | Bearer | Delete a credential |

Authenticated requests send `Authorization: Bearer <token>`.

## Testing

```sh
go test ./...                                              # full suite
go test ./internal/crypto -run TestEncryptDecryptRoundTrip # single test
go vet ./...
swag init -g cmd/server/main.go                            # regenerate docs/ after changing @ annotations
```

Tests in `internal/handlers`, `internal/repository` and `internal/auth` (`salt_test.go`) hit the real Postgres, which must be up and migrated. They create and delete rows with fixed emails. The `internal/crypto` tests, `jwt_test.go` and `hash_test.go` are pure.

There is no `ON DELETE CASCADE` on `credentials.user_id`, so delete a user's credentials before deleting the user. New models must be added to the `AutoMigrate` call in `cmd/migrate/main.go`.

## Releasing and deploying

### Deploy the server

The server runs on [Render](https://render.com) as a native Go service:

| Render setting | Value |
|---|---|
| Build command | `go build -tags netgo -ldflags '-s -w' -o app ./cmd/server && go build -tags netgo -ldflags '-s -w' -o migrate ./cmd/migrate` |
| Start command | `./migrate && ./app` |
| Health check path | `/health` |
| Environment | The [server variables](#configuration) (Render sets `PORT` itself) |

Any Docker host works too (Railway, Fly.io, a VPS). The `Dockerfile` builds the server and runs `migrate` on every start. AutoMigrate is idempotent, so this is safe.

```sh
docker build -t gopasszk-server .
docker run --env-file .env -p 8080:8080 gopasszk-server
```

The host must serve HTTPS, because the CLI refuses plain `http` for anything except localhost.

### Release the CLI

1. Make sure the **repository** variable `GOPASS_SERVER_URL` is set to the deployed API, for example `https://gopasszk.onrender.com`. Find it under Settings > Secrets and variables > Actions > Variables > *Repository variables*. An *environment* variable will not work.
2. Push a new version tag:

   ```sh
   git tag v0.1.3
   git push origin v0.1.3
   ```

`.github/workflows/release.yml` builds `gopass-linux-amd64`, `gopass-linux-arm64` and `gopass-windows-amd64.exe` with that URL baked in, then publishes them as a GitHub release. The install commands always download from the latest release.
