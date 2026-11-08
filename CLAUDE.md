## Project

eyedp is a learning project: an OAuth 2.0 / OIDC identity provider in Go, close
to the stdlib and the specs. See README.md for architecture and roadmap.

## Division of work

The user is building this to learn. **Claude writes only boilerplate. Never
implement core IdP logic; that is the user's job.** If it's unclear which side
something falls on, ask before writing it.

- **Boilerplate (Claude):** HTTP handlers and routing, templates, middleware,
  cookie and CSRF plumbing, storage implementations, config and wiring in
  `main`, and tests for all of these.
- **Core logic (user):** password hashing and verification, the login decision
  (credential checks, timing-safe failures), session lifecycle (ID generation,
  expiry, rotation), and the protocol logic for later roadmap items (grants,
  PKCE, tokens, signing, claims, ...).

Decisions the user made so far:

- User owns hashing, login and sessions. Claude owns cookies, CSRF, handlers,
  templates and storage.
- Hand off domain parts as **stubs only, with no tests**: signatures, doc
  comments describing the contract, a `panic("TODO: ...")` body, and a
  `//nolint:revive` on the func line for unused params.
- Dev users are created at startup with `EYEDP_DEV_USER=username:password`.
  There is no signup UI yet.
- argon2id comes from `golang.org/x/crypto/argon2`. The user adds the
  dependency when implementing; don't add unused deps (CI checks `go mod tidy`).

## Conventions

- Handlers depend on small interfaces (e.g. `authn.CredentialChecker`), so the
  boilerplate is tested with fakes and never calls the user's stubs.
- Storage interfaces live in the domain package. Implementations go in
  `internal/storage/<impl>`.
- Commit, push or open PRs only when asked.

## Commands

```sh
go test ./...
go vet ./...
golangci-lint run
```

Windows dev machine notes:

- `-race` needs cgo, which isn't available here, so it only runs in CI.
- `golangci-lint` reports gofmt on some files because of CRLF (autocrlf).
  That's noise; CI uses LF.
- Python isn't installed.
