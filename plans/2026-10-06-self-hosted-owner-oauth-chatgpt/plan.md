---
title: "Self-Hosted Owner OAuth 2.1 Mode for ChatGPT Web"
description: "Implement a secure, single-owner self-hosted OAuth 2.1 Authorization Code + PKCE authentication mode (AUTH_MODE=owner-oauth) for direct ChatGPT Web custom MCP connection"
status: planned
priority: P1
effort: "2d"
branch: feat/owner-oauth
tags: [oauth, oauth2.1, pkce, chatgpt, mcp, security, auth]
created: 2026-10-06
---

# Plan: Self-Hosted Owner OAuth 2.1 Mode for ChatGPT Web

## Executive Summary

### Context & Goal
The Cloud Harness MCP deployment is a private, single-owner remote coding harness. We need to enable ChatGPT Web to connect directly as a custom MCP server (`/mcp`) without using external identity providers (Cloudflare Access, Auth0, Keycloak).

The server will act as both:
1. **OAuth 2.1 Authorization Server** (exposing discovery, owner login, authorization code issuance, token exchange, and refresh token rotation).
2. **MCP Resource Server** (validating opaque bearer access tokens on `/mcp` and mapping them to the owner principal).

Existing authentication modes (`AUTH_MODE=owner-bearer` and `AUTH_MODE=cloudflare-access`) must remain fully functional and intact.

---

## Architecture & Security Invariants

### 1. Storage & Container Boundaries
- **Safety invariant**: Per `AGENTS.md` and `scripts/verify-compose-boundaries.mjs`, the `api` container must run with `read_only: true` and **must never receive host volume mounts**. Only the `runner` container is authorized to receive state mounts and own the persistent SQLite database (`stateDb: /var/lib/cloud-harness/state/state.db`).
- **OAuth persistence**: OAuth state (authorization codes, access tokens, refresh tokens) must survive process/container restarts.
- **Design decision**:
  - The persistent SQLite tables for OAuth live in the `runner`'s `state.db` via a new `OAuthStore` class.
  - The `runner` exposes internal authenticated RPC endpoints under `/v1/internal/oauth` over the private `control` network (secured with `RUNNER_TOKEN`, identical to `/v1/internal/api-keys`).
  - The `api` container delegates code/token creation, atomic code consumption, token exchange, refresh token rotation, and token verification to the runner via `RunnerClient`.
  - For ultra-low latency, the `api` can maintain an in-memory cache for validated active access tokens.

### 2. OAuth Discovery Specification Compliance
- **Protected Resource Metadata (RFC 9728)**:
  - Unauthenticated requests to `/mcp` return `401 Unauthorized` (required by ChatGPT to trigger discovery) with header:
    ```http
    WWW-Authenticate: Bearer realm="cloud-harness-mcp", resource_metadata="<OAUTH_ISSUER>/.well-known/oauth-protected-resource"
    ```
  - `GET /.well-known/oauth-protected-resource` and alias `GET /.well-known/oauth-protected-resource/mcp` return:
    ```json
    {
      "resource": "<OAUTH_ISSUER>/mcp",
      "authorization_servers": ["<OAUTH_ISSUER>"],
      "scopes_supported": ["workspace:read", "workspace:write", "workspace:execute"],
      "bearer_methods_supported": ["header"]
    }
    ```
- **Authorization Server Metadata (RFC 8414)**:
  - `GET /.well-known/oauth-authorization-server` returns:
    ```json
    {
      "issuer": "<OAUTH_ISSUER>",
      "authorization_endpoint": "<OAUTH_ISSUER>/oauth/authorize",
      "token_endpoint": "<OAUTH_ISSUER>/oauth/token",
      "response_types_supported": ["code"],
      "grant_types_supported": ["authorization_code", "refresh_token"],
      "code_challenge_methods_supported": ["S256"],
      "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
      "scopes_supported": ["workspace:read", "workspace:write", "workspace:execute"]
    }
    ```

### 3. OAuth 2.1 Authorization Code Flow + PKCE
- **Pre-registered Client**: Static client ID and client secret (`OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`). No Dynamic Client Registration (DCR).
- **Exact Redirect URI Matching**: Configured via `OAUTH_ALLOWED_REDIRECT_URIS`. Wildcard or open redirect is strictly forbidden.
- **`GET /oauth/authorize`**:
  - Validates `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`, `code_challenge_method=S256`, `state`, and optional `resource`.
  - Renders a clean, server-rendered HTML login form.
  - Embeds a cryptographically signed CSRF token binding the authorization parameters.
- **`POST /oauth/authorize`**:
  - Validates CSRF token.
  - Applies rate-limiting to brute-force password attempts.
  - Constant-time password verification against `OAUTH_OWNER_PASSWORD` via `crypto.timingSafeEqual`.
  - Generates a cryptographically random authorization code (stored hashed at rest with SHA-256, single-use, 60–120s TTL).
  - Redirects browser to `<redirect_uri>?code=...&state=...&iss=<OAUTH_ISSUER>` (RFC 9207).

### 4. Token Exchange & Refresh Rotation
- **`POST /oauth/token`**:
  - Supports `grant_type=authorization_code` and `grant_type=refresh_token`.
  - Authenticates client using `client_secret_basic` (Authorization: Basic ...) or `client_secret_post` (request body).
  - For `authorization_code`:
    - Validates client credentials.
    - Atomically consumes code (single use).
    - Verifies PKCE: `BASE64URL(SHA256(code_verifier)) === code_challenge`.
    - Generates opaque `access_token` (default 900s TTL) and `refresh_token` (default 30 days TTL).
    - Both tokens stored hashed at rest (SHA-256).
  - For `refresh_token`:
    - Validates refresh token hash and active status.
    - Implements **Refresh Token Rotation**: Revokes old refresh token and issues a new refresh token + new access token.
    - Implements **Replay Detection**: If a revoked/already-rotated token is submitted, invalidates the entire token family.

### 5. Protected MCP Transport (`/mcp`)
- `Authorization: Bearer <access_token>`.
- In `owner-oauth` mode, verifies token hash against active tokens in OAuth store.
- Upon successful authentication, constructs `request.auth` with principal `{ kind: 'owner', ownerId: config.ownerId }` and scopes `['workspace:read', 'workspace:write', 'workspace:execute']`.
- Never accepts `OAUTH_CLIENT_SECRET` or `OAUTH_OWNER_PASSWORD` as MCP bearer tokens.
- Never logs any secret, password, token, or authorization code.

---

## Configuration & Environment Variables

| Variable | Description | Example / Default |
|---|---|---|
| `AUTH_MODE` | Auth mode selector | `owner-oauth` |
| `OAUTH_ISSUER` | HTTPS origin of the server | `https://codex-mcp.iamsoftware.com.vn` |
| `OAUTH_CLIENT_ID` | Pre-registered static client ID | `chatgpt-cloud-harness` |
| `OAUTH_CLIENT_SECRET` | Strong secret entered into ChatGPT (supports `_FILE`) | Generated via `openssl rand -hex 32` |
| `OAUTH_OWNER_PASSWORD` | Owner login password (supports `_FILE`) | Generated or strong passphrase |
| `OAUTH_ALLOWED_REDIRECT_URIS` | Exact callback URL(s) from ChatGPT | `https://chatgpt.com/connector/oauth/<unique-id>` |
| `OAUTH_ACCESS_TOKEN_TTL_SECONDS` | Lifetime of access tokens | `900` (15 mins) |
| `OAUTH_REFRESH_TOKEN_TTL_SECONDS` | Lifetime of refresh tokens | `2592000` (30 days) |

### Migration from `owner-bearer`
1. Keep `MCP_BEARER_TOKEN` in `.env` intact (for easy rollback).
2. Set `AUTH_MODE=owner-oauth`.
3. Add the `OAUTH_*` variables above.
4. Restart containers via Docker Compose.

---

## ChatGPT Web Form Configuration Values

When adding a Custom MCP Server in ChatGPT:
- **Server URL**: `https://codex-mcp.iamsoftware.com.vn/mcp`
- **Authentication**: `OAuth`
- **OAuth client ID**: `<OAUTH_CLIENT_ID>`
- **OAuth client secret**: `<OAUTH_CLIENT_SECRET>`
- **Token endpoint auth method**: `Basic` (or `Post`)
- **Scopes**: `workspace:read workspace:write workspace:execute` (or leave empty)
- **Callback URL**: Copy the displayed callback URL into `OAUTH_ALLOWED_REDIRECT_URIS` on the server.

---

## Phased Implementation Plan

| Phase | Description | Components / Files |
|---|---|---|
| **Phase 1: Contracts** | Extend `ApiConfigSchema`, `RunnerConfigSchema`, add OAuth RPC schemas and contract tests | `packages/contracts/src/config.ts`, `packages/contracts/src/oauth-api.ts`, `packages/contracts/test/contracts.test.ts` |
| **Phase 2: Runner OAuth Store** | Implement SQLite tables, migration, hashing, atomic code consume, PKCE verification, token rotation, and replay detection | `apps/runner/src/oauth-store.ts`, `apps/runner/src/app.ts`, `apps/runner/test/oauth-store.test.ts` |
| **Phase 3: API Endpoints & Auth Middleware** | Implement discovery metadata routes, owner login UI, token exchange, and update `/mcp` `bearerAuth` | `apps/api/src/oauth-router.ts`, `apps/api/src/auth.ts`, `apps/api/src/app.ts`, `apps/api/src/config.ts`, `apps/api/src/runner-client.ts` |
| **Phase 4: Routing & Boundaries** | Update Nginx config for `/.well-known/` and `/oauth/`, verify Compose boundaries | `deploy/nginx/cloud-harness-mcp.conf`, `scripts/verify-compose-boundaries.mjs` |
| **Phase 5: Automated Testing** | Implement complete suite of 22 test cases + full regression check | `apps/api/test/owner-oauth.test.ts`, `test/integration/owner-oauth-integration.test.ts` |
| **Phase 6: Documentation** | Document ChatGPT setup guide, curl verification scripts, secret generation | `README.md`, `docs/mcp-api.md`, `docs/configuration.md` |

---

## Acceptance Criteria & Test Matrix

- [ ] **Discovery**: `GET /.well-known/oauth-protected-resource` returns RFC 9728 metadata with canonical resource `https://codex-mcp.iamsoftware.com.vn/mcp`.
- [ ] **Discovery**: `GET /.well-known/oauth-authorization-server` returns RFC 8414 metadata with endpoints, S256 PKCE, supported grants.
- [ ] **Discovery Challenge**: Unauthenticated request to `/mcp` returns HTTP 401 with `WWW-Authenticate: Bearer resource_metadata="..."`.
- [ ] **Authorize Validation**: Rejects invalid `client_id`, unknown `redirect_uri`, non-S256 `code_challenge_method`, missing PKCE, or unsupported `response_type`.
- [ ] **Owner Login UI**: Server-renders HTML login form with CSRF token and requested scope/client details.
- [ ] **Owner Authentication**: Constant-time password check; rate-limits brute force attempts.
- [ ] **Auth Code Issuance**: Successfully issues short-lived single-use authorization code and redirects to `<redirect_uri>?code=...&state=...&iss=...`.
- [ ] **Token Exchange**: Validates client credentials (Basic or Post body), code, redirect_uri, and PKCE `code_verifier`.
- [ ] **Single-use Code**: Replaying an authorization code is rejected with `invalid_grant`.
- [ ] **Access Token Protected `/mcp`**: Valid access token authorizes MCP calls as `owner`.
- [ ] **Secret Isolation**: `OAUTH_CLIENT_SECRET` and `OAUTH_OWNER_PASSWORD` rejected as bearer tokens on `/mcp`.
- [ ] **Token Expiration**: Expired access tokens return 401.
- [ ] **Refresh Rotation**: Valid refresh token returns new access token and rotated refresh token; old refresh token is invalidated.
- [ ] **Refresh Replay Detection**: Replaying an invalidated refresh token triggers family revocation.
- [ ] **Restart Persistence**: Codes, tokens, and refresh tokens survive service restarts.
- [ ] **Regression**: 100% of existing tests pass (1502 unit tests, compose boundaries, lint, typecheck).
