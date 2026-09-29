# gopasszk

A zero-knowledge password manager written in Go: a REST API server backed by PostgreSQL, and a terminal client (`gopass`).

Your master password never leaves your machine. The server only stores an Argon2id hash of a key derived from it, plus AES-256-GCM ciphertext it has no way to decrypt. If the database leaks, the attacker gets opaque blobs.

---

## Contents

- [How it works](#how-it-works)
- [Security design](#security-design)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Running locally](#running-locally)
- [Testing locally](#testing-locally)
- [Using the CLI](#using-the-cli)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Known limitations](#known-limitations)

---

## How it works

Everything secret happens on the client. From your master password and a per-account random salt, the client derives **two independent keys**:

| Key | Derived from | Used for | Leaves the client? |
|---|---|---|---|
| **Auth hash** | `Argon2id(password, salt ‖ "auth")` | Proving who you are at login | Yes, sent to the server |
| **Encryption key** | `Argon2id(password, salt ‖ "enc")` | Encrypting and decrypting vault entries | **Never** |

Different labels are appended to the salt, so the two keys are unrelated. Knowing the auth hash tells you nothing about the encryption key.

### Register

```
client                                              server
──────                                              ──────
salt     = random 16 bytes
authHash = Argon2id(pw, salt‖"auth")
                 ── POST /register {email, salt, auth_hash} ──▶
                                                    phc = Argon2id(authHash)   (hashed again)
                                                    store {email, salt, phc}
```

### Login

```
client                                              server
──────                                              ──────
                 ── GET /salt?email=… ──────────────▶
                 ◀── {salt} ─────────────────────────
authHash = Argon2id(pw, salt‖"auth")
                 ── POST /login {email, auth_hash} ─▶
                                                    verify authHash against phc
                 ◀── {token} (JWT, 24h) ─────────────
```

### Store and read a credential

```
client                                              server
──────                                              ──────
encKey = Argon2id(pw, salt‖"enc")
ct     = base64(nonce ‖ AES-GCM(encKey, value))
                 ── POST /credentials {site_name, username_ciphertext, password_ciphertext} ─▶
                                                    store ciphertext as-is
                 ── GET /credentials ───────────────▶
                 ◀── [{…ciphertext…}] ───────────────
plaintext = AES-GCM-Open(encKey, nonce, ct)
```

---

## Security design

### Key derivation (client)

- **Algorithm:** Argon2id (`golang.org/x/crypto/argon2`)
- **Parameters:** time = 1, memory = 64 MiB, threads = 4, key length = 32 bytes
- **Salt:** 16 random bytes from `crypto/rand`, generated once at registration and stored on the server

### Encryption (client)

- **Cipher:** AES-256-GCM (authenticated encryption, so tampering is detected on decrypt)
- **Nonce:** a fresh 12-byte random nonce for every encryption
- **Wire format:** `base64( nonce[12] ‖ ciphertext ‖ tag[16] )`

The username and the password of each entry are encrypted separately.

### Auth hash storage (server)

The server doesn't store the auth hash directly. It hashes it again with Argon2id (memory = 19 MiB, iterations = 2, parallelism = 1, random 16-byte salt) and stores the result as a PHC string. A stolen database row can't be replayed to log in.

### Anti-enumeration

The API is built so it doesn't reveal which emails have accounts:

- `GET /salt` for an unknown email returns a **deterministic fake salt**, computed as `HMAC-SHA256(SALT_HMAC_SECRET, email)[:16]`. It looks like a real salt and stays the same across requests.
- `POST /login` for an unknown email still runs a full Argon2id verification against a dummy hash, so the response time matches. The response is the same `401 invalid credentials`.
- A duplicate registration returns a generic `409 unable to register`.

### Authorization

- Every `/credentials` route requires a `Bearer` JWT (HS256, signed with `JWT_SECRET`, valid for 24 hours).
- The owner of a credential is **always** taken from the token, never from the request body.
- Every query is scoped by `id AND user_id`. Trying to read, update or delete another user's credential returns `404`, exactly like a credential that doesn't exist.

### Input validation

- Registration requires the salt to decode to exactly 16 bytes and the auth hash to exactly 32 bytes.
- Ciphertext fields must be valid base64 and decode to between 28 bytes (nonce plus tag) and 4096 bytes.
- `site_name` is limited to 255 characters. Credential IDs must be valid UUIDs.

### What the server knows

| The server stores | The server never sees |
|---|---|
| Email | Master password |
| Salt | Encryption key |
| Argon2id(auth hash) | Plaintext usernames and passwords |
| Site name (plaintext) | |
| Encrypted username and password | |

---

## Tech stack

| Area | Library |
|---|---|
| HTTP framework | [Gin](https://github.com/gin-gonic/gin) |
| ORM / database | [GORM](https://gorm.io) + PostgreSQL 16 |
| Password hashing | `golang.org/x/crypto/argon2`, [alexedwards/argon2id](https://github.com/alexedwards/argon2id) |
| Tokens | [golang-jwt/jwt v5](https://github.com/golang-jwt/jwt) |
| API docs | [swaggo/swag](https://github.com/swaggo/swag) + gin-swagger |
| Config | [godotenv](https://github.com/joho/godotenv) |
| CLI password input | `golang.org/x/term` |

---

## Project structure

```
.
├── cmd/
│   ├── server/        API server entrypoint and route wiring
│   ├── gopass/        Terminal client (register, login, add, list, edit, delete)
│   ├── migrate/       Creates or updates the database schema (GORM AutoMigrate)
│   ├── dbtest/        Checks the database connection
│   └── cryptotest/    Demo of an encrypt/decrypt round trip
├── internal/
│   ├── crypto/        Client-side key derivation and AES-GCM
│   ├── auth/          Server-side hashing, JWT issuing, salt lookup and fake salts
│   ├── handlers/      HTTP handlers (with Swagger annotations)
│   ├── middleware/    JWT auth middleware
│   ├── repository/    Database queries, all scoped by user
│   ├── models/        GORM models: User, Credential
│   ├── client/        Typed HTTP client used by the CLI
│   ├── database/      Postgres connection
│   └── config/        .env loading
├── docs/              Generated Swagger spec (don't edit by hand)
└── docker-compose.yml Postgres 16
```

---

## Running locally

### Prerequisites

- Go 1.26+
- Docker (for Postgres)
- Optional: the [swag CLI](https://github.com/swaggo/swag), to regenerate API docs

### 1. Create a `.env` file in the repo root

```env
POSTGRES_USER=gopass
POSTGRES_PASSWORD=change-me
POSTGRES_DB=gopass

# Key for the HMAC that produces fake salts for unknown emails
SALT_HMAC_SECRET=<long random string>

# Key used to sign JWTs
JWT_SECRET=<long random string>
```

You can generate the secrets with `openssl rand -base64 32`. The same file is read by Docker Compose and by the Go programs, which look for `.env` in the current directory and then in each parent directory.

### 2. Start Postgres

```sh
docker compose up -d
```

### 3. Create the schema

```sh
go run ./cmd/migrate
```

To check that the app can reach the database:

```sh
go run ./cmd/dbtest
```

### 4. Run the server

```sh
go run ./cmd/server
```

The API listens on `http://localhost:8080`. Interactive Swagger docs are at **http://localhost:8080/swagger/index.html**.

Leave this terminal open. The port is fixed at 8080. If startup fails with `bind: address already in use` (on Windows: `Only one usage of each socket address…`), another copy of the server is already running.

### 5. Build the CLI

In a second terminal:

```sh
go build -o gopass ./cmd/gopass        # use gopass.exe on Windows
./gopass register
```

### Stopping

Press `Ctrl+C` in the server terminal, then stop Postgres:

```sh
docker compose down        # keeps your data
docker compose down -v     # also deletes the database volume (all data)
```

---

## Testing locally

Everything below assumes Postgres is running and migrated (steps 1–3 above).

### Automated tests

```sh
go test ./...                                   # whole suite
go test -count=1 ./...                          # bypass Go's test cache (use after the database changes)
go test ./internal/crypto                       # crypto only, no database needed
go test -v ./internal/repository -run TestCrossUserCredentialAccess   # a single test
```

| Package | Needs Postgres | What it covers |
|---|---|---|
| `internal/crypto` | No | Encrypt/decrypt round trip; auth and encryption keys differ; key derivation is deterministic; the input salt isn't modified; why reusing a nonce is dangerous |
| `internal/auth` | Only `salt_test.go` | Argon2id hash and verify; JWT issuing; real salts vs. deterministic fake salts |
| `internal/handlers` | Yes | `POST /register`: success, wrong salt or hash length, bad base64, missing email, duplicate returns 409 |
| `internal/repository` | Yes | Salt and ciphertext bytes come back unchanged; one user can't update or delete another user's credential |

To run only the `internal/auth` tests that don't need a database:

```sh
go test ./internal/auth -run 'TestHash|TestIssueToken'
```

> **Heads-up:** the tests that need Postgres use the same database as your `.env`. They create rows with fixed emails (`alice@test.com`, `handler-success@example.com`, …) and delete them afterwards. If a run is interrupted before cleanup, the next run fails with a duplicate-key error. Delete the leftover rows, or reset the database (this wipes **all** data):
>
> ```sh
> docker compose down -v && docker compose up -d && go run ./cmd/migrate
> ```

### End-to-end with the CLI

With the server running (step 4), go through the whole flow in a second terminal:

```sh
./gopass register
./gopass login
./gopass add
./gopass list          # should print your entry, decrypted
./gopass edit <id>
./gopass delete <id>
```

You can compare with the example output in [Using the CLI](#using-the-cli). Also check that `gopass list` with the wrong master password fails with `error: wrong master password`.

Then check what the server actually stored:

```sh
docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT email, auth_hash FROM users;"'
docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT site_name, username_ciphertext, password_ciphertext FROM credentials;"'
```

`auth_hash` should be an `$argon2id$v=19$…` string, and the ciphertext columns should be base64 blobs. Your usernames and passwords should not appear anywhere in plaintext.

### Manual API testing

The easiest option is the Swagger UI at http://localhost:8080/swagger/index.html. Use **Try it out** on each endpoint. For protected routes, click **Authorize** and enter `Bearer <token>`, including the word `Bearer`.

To use curl, note that the server only checks the *length* of the salt, auth hash and ciphertext. That means you can use all-zero dummy values instead of running real key derivation. An account created this way won't work from the CLI.

The examples below are for bash (on Windows, use Git Bash or WSL).

```sh
# Liveness
curl http://localhost:8080/health

# Register with a 16-byte salt and a 32-byte auth hash (all zeros)
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email":"curl@example.com","salt":"AAAAAAAAAAAAAAAAAAAAAA==","auth_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'

# Log in and copy the token from the response
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"curl@example.com","auth_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'

TOKEN=<paste token here>

# Store a credential (28 zero bytes = the minimum size, nonce + GCM tag)
curl -X POST http://localhost:8080/credentials \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"site_name":"example.com","username_ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","password_ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}'

# List, check the token, and delete
curl http://localhost:8080/credentials -H "Authorization: Bearer $TOKEN"
curl http://localhost:8080/me -H "Authorization: Bearer $TOKEN"
curl -X DELETE http://localhost:8080/credentials/<id> -H "Authorization: Bearer $TOKEN"
```

Behaviour worth checking by hand:

| Try | Expected |
|---|---|
| Register the same email twice | `409 {"error":"unable to register"}` |
| `GET /salt?email=nobody@example.com` twice | `200` with the same fake salt both times |
| Log in with a wrong `auth_hash` (e.g. change the first `A` to `B`) | `401 {"error":"invalid credentials"}` |
| Log in with an email that doesn't exist | The same `401 {"error":"invalid credentials"}` |
| Call `/credentials` with no token, or a bad one | `401` |
| Register a second account and use its token on the first account's credential ID with `PUT` or `DELETE` | `404 {"error":"credential not found"}` |
| Send ciphertext shorter than 28 bytes | `400 {"error":"ciphertext too short"}` |

---

## Using the CLI

```
usage: gopass <command>

commands:
  register      create an account
  login         log in and save a session token
  add           add a credential
  list          list and decrypt your credentials
  edit <id>     change a credential
  delete <id>   delete a credential
```

Password prompts don't echo what you type.

### Example session

```text
$ gopass register
Email: me@example.com
Master password:
Confirm password:
Registered. Now run: gopass login

$ gopass login
Email: me@example.com
Master password:
Logged in.

$ gopass add
Master password:
Site: github.com
Username: octocat
Password to store:
Added: 3f2a9c1e-…

$ gopass list
Master password:
3f2a9c1e-…  github.com            octocat                    hunter2

$ gopass edit 3f2a9c1e-…
Master password:
New site: github.com
New username: octocat
New password:
Updated.

$ gopass delete 3f2a9c1e-…
Deleted.
```

### How the CLI handles your session

- `login` saves your email and JWT to `session.json` in your OS config directory. On Windows that's `%AppData%\gopass\session.json`, on Linux `~/.config/gopass/session.json`, and on macOS `~/Library/Application Support/gopass/session.json`. The file has `0600` permissions.
- `add`, `list` and `edit` ask for your master password every time. The CLI logs in again to confirm it's correct and derives the encryption key in memory. The key is never written to disk.
- `edit` replaces all three fields (site, username, password).
- Set `GOPASS_SERVER` to point the CLI at a server other than `http://localhost:8080`.

---

## API reference

All request and response bodies are JSON. Binary values (salt, auth hash, ciphertext) are **standard base64**. Errors look like `{"error": "<message>"}`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | – | Liveness check |
| `POST` | `/register` | – | Create an account |
| `GET` | `/salt?email=` | – | Get the salt for an email (fake if the account doesn't exist) |
| `POST` | `/login` | – | Exchange an auth hash for a JWT |
| `GET` | `/me` | Bearer | Return the user ID from the token |
| `POST` | `/credentials` | Bearer | Store an encrypted credential |
| `GET` | `/credentials` | Bearer | List your encrypted credentials |
| `PUT` | `/credentials/{id}` | Bearer | Replace a credential |
| `DELETE` | `/credentials/{id}` | Bearer | Delete a credential |

### `POST /register`

```json
{
  "email": "me@example.com",
  "salt": "<base64, 16 bytes>",
  "auth_hash": "<base64, 32 bytes>"
}
```

| Status | Meaning |
|---|---|
| `201` | `{"message": "reigstered"}` |
| `400` | Missing field, bad base64, or wrong salt or hash length |
| `409` | Email already registered |

### `GET /salt?email=me@example.com`

```json
{ "salt": "<base64, 16 bytes>" }
```

Returns `400` if `email` is missing.

### `POST /login`

```json
{
  "email": "me@example.com",
  "auth_hash": "<base64, 32 bytes>"
}
```

| Status | Meaning |
|---|---|
| `200` | `{"token": "<JWT>"}` |
| `400` | Malformed request |
| `401` | Wrong email or password (same response for both) |

### `GET /me`

```json
{ "user_id": "<uuid>" }
```

### `POST /credentials`

```json
{
  "site_name": "github.com",
  "username_ciphertext": "<base64(nonce ‖ ciphertext ‖ tag)>",
  "password_ciphertext": "<base64(nonce ‖ ciphertext ‖ tag)>"
}
```

Returns `201` with the created credential:

```json
{
  "id": "<uuid>",
  "site_name": "github.com",
  "username_ciphertext": "…",
  "password_ciphertext": "…",
  "created_at": "2026-09-29T10:00:00Z",
  "updated_at": "2026-09-29T10:00:00Z"
}
```

### `GET /credentials`

```json
{ "credentials": [ { "id": "…", "site_name": "…", "…": "…" } ] }
```

### `PUT /credentials/{id}`

The request body is the same as `POST /credentials`. Returns `204` on success, `400` for an invalid ID or body, and `404` if the credential doesn't exist or isn't yours.

### `DELETE /credentials/{id}`

Returns `204` on success, `400` for an invalid ID, and `404` if the credential doesn't exist or isn't yours.

### Regenerating the Swagger docs

The spec in `docs/` is generated from the annotations on the handlers. After you change them, run:

```sh
swag init -g cmd/server/main.go
```

---

## Configuration

| Variable | Used by | Purpose |
|---|---|---|
| `POSTGRES_USER` | server, Docker Compose | Database user |
| `POSTGRES_PASSWORD` | server, Docker Compose | Database password |
| `POSTGRES_DB` | server, Docker Compose | Database name |
| `SALT_HMAC_SECRET` | server | Key for the HMAC that produces fake salts for unknown emails |
| `JWT_SECRET` | server | Key used to sign JWTs (HS256) |
| `GOPASS_SERVER` | CLI | API base URL (default `http://localhost:8080`) |

The server always connects to Postgres at `localhost:5432` and listens on `:8080`.

---

## Known limitations

- **Site names are stored in plaintext.** The server can see which sites you have accounts on, just not the usernames or passwords.
- **You can't change your master password.** Doing so would mean re-encrypting every entry with a new key, and nothing does that yet.
- **JWTs can't be revoked** and are valid for 24 hours. `gopass delete` uses the saved session token without asking for the master password.
- **Deleting a user doesn't delete their credentials.** `credentials.user_id` has no `ON DELETE CASCADE`, so credentials have to be removed first.
- **There's no rate limiting** on `/login` or `/salt`.
- **The database connection uses `sslmode=disable`**, and the host and port are hardcoded. This is fine for local development but not for a real deployment.
- **The server has no TLS.** Run it behind a TLS-terminating proxy if it's reachable over a network.
