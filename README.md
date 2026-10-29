# eyedp

An identity provider built from scratch in Go, for learning how authentication,
OAuth 2.0 and OpenID Connect actually work.

The goal is to stick close to the standard library and the specs: protocol
logic is hand-written, and libraries are only used where rolling your own adds
no learning value (e.g. low-level JOSE/JWT signing).

## Running

Requires Go 1.24+.

```sh
go run ./cmd/eyedp
curl localhost:8080/healthz
# {"status":"ok"}
```

| Env var      | Default | Description           |
| ------------ | ------- | --------------------- |
| `EYEDP_ADDR` | `:8080` | Address to listen on. |

```sh
go test ./...                    # run tests
go build -o bin/eyedp ./cmd/eyedp
```

## Architecture

A single binary (modular monolith), split logically into packages under
`internal/`. Dependencies flow one way: `oidc` builds on `oauth`, never the
reverse, mirroring how OIDC is a layer on top of OAuth 2.0. Storage is
accessed through interfaces defined by the packages that need them, so an
in-memory implementation can come first and a SQL one later.

### Goal structure

Packages are created as the corresponding build step is reached.

```
eyedp/
├── cmd/eyedp/main.go          # wiring: config, storage, routers, listeners
├── internal/
│   ├── server/                # route registration, mounts each package's handlers
│   ├── httpx/                 # middleware, JSON helpers, RFC 6749 error responses
│   ├── oauth/                 # /authorize, /token, /revoke, /introspect; grants, PKCE
│   ├── oidc/                  # id_token, /userinfo, discovery, nonce, claims
│   ├── keys/                  # signing key generation/rotation, JWKS endpoint
│   ├── session/               # browser login sessions, cookies, CSRF
│   ├── authn/                 # password verification (argon2id), later MFA/WebAuthn
│   ├── user/                  # user domain + service
│   ├── client/                # registered OAuth clients, redirect URI validation
│   └── storage/               # interfaces + impls (memory first, then Postgres/SQLite)
└── web/templates/             # login + consent pages
```

## Roadmap

- [x] **Scaffold:** HTTP server, graceful shutdown, request logging, `/healthz`
- [ ] **Users & login:** user model, argon2id password hashing, login page, browser sessions (`user`, `authn`, `session`)
- [ ] **OAuth 2.0 Authorization Code + PKCE:** client registry, `/authorize`, `/token`, opaque access tokens ([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636))
- [ ] **JWT access tokens & keys:** signing key management, `/.well-known/jwks.json` ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068))
- [ ] **OpenID Connect:** `openid` scope, `id_token`, `/userinfo`, `/.well-known/openid-configuration` ([OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html))
- [ ] **Token lifecycle:** refresh tokens with rotation, `/revoke`, `/introspect` ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662))
- [ ] **More grants & consent:** client credentials grant, consent screen
- [ ] **Extras:** device authorization flow ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)), MFA (TOTP), WebAuthn/passkeys
- [ ] **Conformance:** run the [OpenID conformance suite](https://openid.net/certification/testing/)
