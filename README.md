# gopasszk

A zero-knowledge password manager in Go: a Gin + GORM/PostgreSQL API server and a terminal client (`gopass`).

Your master password never leaves your machine. The server stores only an Argon2id hash of a derived key plus AES-256-GCM ciphertext it cannot decrypt. If the database leaks, the attacker gets opaque blobs.

## Contents

- [Architecture](#architecture)
- [Crypto and auth flow](#crypto-and-auth-flow)
- [Database](#database)
- [Project structure](#project-structure)
- [Quick start](#quick-start)
- [Install the CLI](#install-the-cli)
- [Using the CLI](#using-the-cli)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Testing](#testing)

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
| CLI | `cmd/gopass`, `internal/client`, `internal/crypto` | Key derivation, encrypt/decrypt, session file, HTTP calls |
| Routing | `cmd/server` | Wires routes, Swagger UI |
| Handlers | `internal/handlers` | Request validation, response mapping (methods on `Handler`) |
| Middleware | `internal/middleware` | `RequireAuth`: validates Bearer JWT, sets `userID` |
| Auth | `internal/auth` | Server-side Argon2id hash/verify, JWT, deterministic fake salts |
| Repository | `internal/repository` | Plain functions taking `*gorm.DB`, no interfaces |
| Models | `internal/models` | `User`, `Credential` |

## Crypto and auth flow

The client never uses the master password directly as the vault key. Instead there is a random **vault key** that encrypts all credentials, and that key is stored on the server *wrapped* (encrypted) two ways:

| Value | Derived from | Used for | Leaves the client? |
|---|---|---|---|
| Auth hash | Argon2id(`salt ‖ "auth"`) | Proving identity at login | Yes (server hashes it again) |
| Password key | Argon2id(`salt ‖ "enc"`) | Wraps/unwraps the vault key | **Never** |
| Vault key | Random 32 bytes | AES-256-GCM encrypt/decrypt of credentials | **Never** (only wrapped) |
| Recovery wrap key + recovery auth hash | HKDF of the 24-word recovery phrase | Wraps the vault key a second way; proves you hold the phrase | Auth hash only |

**Register:** client generates a salt, vault key and 24-word BIP-39 recovery phrase. It sends `{email, salt, auth_hash, wrapped_vault_key, recovery_wrapped_key, recovery_auth_hash}`. The phrase is shown once and never sent. The server re-hashes the auth hashes with Argon2id (PHC string) and stores them.

**Login:** client `GET /salt?email=...`, re-derives the auth hash, `POST /login`. The server verifies and returns an HS256 JWT (24h, `user_id` claim) plus the wrapped vault key, which the client unwraps with the password key.

**Change password (`passwd`):** vault key is re-wrapped under a new password key with a new salt. Credentials are untouched.

**Forgot password (`recover`):** the recovery phrase proves identity (`POST /recover/key`), the client unwraps the vault key with it, then re-wraps under a new password (`POST /recover/reset`). Your existing recovery phrase keeps working. **Lose both the password and the phrase and the data is unrecoverable by design.**

**Vault entries:** username and password are encrypted client-side. Wire format is `base64(nonce[12] ‖ ciphertext+tag)`. The server only checks the decoded length (28-4096 bytes).

**Anti-enumeration:**
- `GET /salt` for an unknown email returns a deterministic fake salt, `HMAC-SHA256(SALT_HMAC_SECRET, email)[:16]`.
- `POST /login` for an unknown email still runs an Argon2 verify against a dummy hash and returns the same 401.

**Ownership:** the credential owner always comes from the JWT, never the request body. Every credential query is scoped by `id AND user_id`; another user's row looks the same as a missing one (404).

## Database

PostgreSQL 16, run locally by `docker-compose.yml` (service `db`, port 5432, named volume `pgdata` so data survives restarts). Credentials come from the same `.env`. Schema is created by `go run ./cmd/migrate` (GORM AutoMigrate, the only schema mechanism).

| Table | Columns of note |
|---|---|
| `users` | `id` (uuid), `email` (unique), `salt`, `auth_hash`, `wrapped_vault_key`, `recovery_wrapped_key`, `recovery_auth_hash` |
| `credentials` | `id`, `user_id`, `site_name`, `username_ciphertext`, `password_ciphertext` |

Everything sensitive is a hash or ciphertext. There is no `ON DELETE CASCADE` on `credentials.user_id`.

## Project structure

```
cmd/
  server/      API server (:8080)
  gopass/      terminal client
  migrate/     GORM AutoMigrate (User, Credential)
  dbtest/      DB connectivity check
  cryptotest/  crypto sanity check
internal/
  auth/        argon2 hash, JWT, salt
  client/      HTTP client used by the CLI
  config/      .env + env var loading
  crypto/      key derivation, AES-GCM
  database/    Postgres connection
  handlers/    HTTP handlers
  middleware/  JWT auth middleware
  models/      GORM models
  pwgn/        random password generator
  repository/  DB queries
docs/          Swagger (generated by swag, do not hand-edit)
docker-compose.yml
```

## Quick start

**Prerequisites:** Go 1.26+, Docker (for Postgres), and optionally [`swag`](https://github.com/swaggo/swag) to regenerate docs.

1. Create a `.env` at the repo root (gitignored):

   ```env
   POSTGRES_USER=gopass
   POSTGRES_PASSWORD=change-me
   POSTGRES_DB=gopass
   SALT_HMAC_SECRET=<long random string>
   JWT_SECRET=<long random string>
   ```

   Generate secrets with `openssl rand -hex 32`.

2. Start Postgres and create the schema:

   ```sh
   docker compose up -d
   go run ./cmd/migrate        # the only schema mechanism
   go run ./cmd/dbtest         # optional: connectivity check
   ```

3. Run the server:

   ```sh
   go run ./cmd/server         # API on :8080
   ```

   Health: `http://localhost:8080/health`. Swagger UI: `http://localhost:8080/swagger/index.html`.

## Install the CLI

```sh
go install ./cmd/gopass
```

This puts `gopass` in `$(go env GOPATH)/bin` (or `$GOBIN`). Make sure that directory is on your `PATH`.

Or build a local binary instead:

```sh
go build -o gopass.exe ./cmd/gopass
```

Point the CLI at a different server with `GOPASS_SERVER` (default `http://localhost:8080`). Plain `http` is accepted only for `localhost` / `127.0.0.1`; anything else must be `https`.

```sh
GOPASS_SERVER=https://vault.example.com gopass login
```

## Using the CLI

```sh
# account
gopass register        # create an account; shows your 24-word recovery phrase ONCE
gopass login           # authenticate, saves a session token
gopass logout          # clear the saved session
gopass passwd          # change your master password
gopass recover         # reset a forgotten master password with the recovery phrase

# credentials
gopass add             # add a credential (can generate a password for you)
gopass list            # list site names and IDs
gopass search <term>   # find credentials by site name
gopass show <id>       # show one credential, decrypted
gopass copy <id>       # copy password to clipboard, cleared after 30s
gopass edit <id>       # update a credential
gopass delete <id>     # delete a credential

# tools
gopass generate [len]  # random password (default 20)
gopass audit           # flag weak, reused and breached passwords
gopass help
```

Typical first run: `gopass register` -> write down the phrase -> `gopass login` -> `gopass add`.

`audit` checks breaches via haveibeenpwned using k-anonymity: only the first 5 characters of each password's SHA-1 are sent.

- The session is stored at `os.UserConfigDir()/gopass/session.json` as `{email, token}`.
- Every vault command except `delete` re-prompts for the master password, re-logs in for a fresh token, and derives the encryption key locally. The key is never persisted.

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

## Configuration

Loaded from `.env` (found by walking up from the cwd) or the process environment.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `POSTGRES_USER` | yes | | DB user |
| `POSTGRES_PASSWORD` | yes | | DB password |
| `POSTGRES_DB` | yes | | DB name |
| `SALT_HMAC_SECRET` | yes | | Key for fake-salt HMAC |
| `JWT_SECRET` | yes | | HS256 signing key |
| `DB_HOST` | no | `localhost` | Postgres host |
| `DB_PORT` | no | `5432` | Postgres port |
| `DB_SSLMODE` | no | `disable` | Postgres sslmode |
| `GOPASS_SERVER` | no | `http://localhost:8080` | CLI only: API base URL |

The server refuses to start if a required variable is missing.

## Testing

```sh
go test ./...                                              # full suite
go test ./internal/crypto -run TestEncryptDecryptRoundTrip # single test
go vet ./...
swag init -g cmd/server/main.go                            # regenerate docs/ after changing @ annotations
```

Tests in `internal/handlers`, `internal/repository`, and `internal/auth` (`salt_test.go`) hit the real Postgres (up and migrated) and create and delete rows with fixed emails. The `internal/crypto` tests, `jwt_test.go`, and `hash_test.go` are pure.

There is no `ON DELETE CASCADE` on `credentials.user_id`, so delete a user's credentials before the user. New models must be added to the `AutoMigrate` call in `cmd/migrate/main.go`.
