# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] — 2026-06-22

### Fixed

- Git rebase merge conflicts resolved across all source files — history is now linear and clean
- `package.json` restored to valid JSON after rebase corruption
- Removed stale `DeviceAuthRequest` import from `device-auth.ts` and `index.ts`
- Added missing `fetchWithTLS` import to `oidc-client.ts`
- Added missing `tlsRejectUnauthorized`, `allowedGroups`, and `groupsClaim` fields to `ClientConfig` interface

### Changed

- `TokenStore` now always uses encryption — removed optional `encryptionSecret` parameter from constructor
- `TokenEncryption` constructor takes `dataDir` path instead of user-provided secret
- `ProviderConfig` cleaned up — removed `redirectPort`, `callbackUrl`; added `tlsRejectUnauthorized`, `allowedGroups`, `groupsClaim`
- `OAuth2PlatformConfig` cleaned up — removed `callbackHost`, `tokenRefreshInterval`, `encryptionSecret`, `managementPort`, `managementBindAddress`

[0.1.4]: https://github.com/lbenicio/homebridge-oauth2-oidc/releases/tag/v0.1.4

## [0.1.5] — 2026-06-22

### Fixed

- **ENOENT crash on first run** — `loadOrCreateKey` now creates the data directory before writing the encryption key file, preventing crash when the plugin storage directory doesn't exist yet

[0.1.5]: https://github.com/lbenicio/homebridge-oauth2-oidc/releases/tag/v0.1.5

## [0.1.3] — 2026-06-22

### Changed

- **TLS skip now uses native `https.Agent`** instead of `undici` Agent — more reliable across Node.js versions. The `undici` dependency has been removed
- **`fetchWithTLS` rewritten** — uses `https.request()` with `rejectUnauthorized: false` for TLS-skip requests; uses native `fetch()` for normal requests
- `TokenEncryption` now takes a `dataDir` path instead of a user-provided secret — key is auto-generated and persisted

### Fixed

- TLS certificate skip not working in Node.js v24 due to `undici` Agent incompatibility
- OIDC discovery failing on `.lan` domains with self-signed certificates
- `TokenStore` simplified — encryption always active, removed conditional logic

### Dependencies

- Removed `undici` — no longer needed

[0.1.3]: https://github.com/lbenicio/homebridge-oauth2-oidc/releases/tag/v0.1.3

## [0.1.2] — 2026-06-22

### Removed

- **Management HTTP server** — eliminated entirely. The UI server (`HomebridgePluginUiServer`) is now self-contained: it reads the Homebridge config directly, creates its own OAuth2/OIDC clients, and reads/writes the same token files as the platform. No extra HTTP server, no port file, no CORS.
- **Platform config fields**: `callbackHost`, `tokenRefreshInterval`, `encryptionSecret`, `managementPort`, `managementBindAddress` — all hardcoded to sensible defaults or eliminated
- **Provider config fields**: `authorizationEndpoint`, `tokenEndpoint`, `userInfoEndpoint` — auto-discovered from OIDC `.well-known/openid-configuration`. Still accepted in raw JSON for backward compat
- **Provider config field**: `redirectPort` — no longer needed
- **Provider config field**: `callbackUrl` — now auto-derived from `window.location.origin` passed by the browser

### Changed

- **Token encryption is now always-on** — a random 256-bit key is auto-generated on first use and persisted to disk. No user configuration required. Tokens are never stored as plaintext
- **Callback URL is now automatic** — derived from `window.location.origin + /plugin/homebridge-oauth2-oidc/callback/`. No config needed
- **Platform file** reduced from ~900 lines to ~300 lines
- **Config schema** reduced to only `name` and `providers[]` at the top level, and only essential fields per provider

### Fixed

- **EISDIR crash** — plugin data now stored under `api.user.storagePath()` instead of `persistPath()`, preventing `node-persist` from tripping over our data directory
- `DeviceAuthRequest` type alias removed (was unused)

[0.1.2]: https://github.com/lbenicio/homebridge-oauth2-oidc/releases/tag/v0.1.2

## [0.1.1] — 2026-06-22

### Added

- **TLS certificate skip** (`tlsRejectUnauthorized`) — per-provider option to bypass TLS validation for self-signed/internal certificates (e.g. `.lan` domains)
- **Static callback URL** (`callbackUrl`) — per-provider option for a predictable redirect URI. Callback page served by the Homebridge UI at `/plugin/homebridge-oauth2-oidc/callback/`
- **Group-based authorization** (`allowedGroups`, `groupsClaim`) — restrict access to users belonging to specific OIDC groups. Fetched from UserInfo endpoint or decoded from ID token payload
- **Management server bind address** (`managementBindAddress`) — configure which IP the management HTTP server binds to
- **`/api/exchange-code` endpoint** and **`/exchange-code` UI server handler** — bridge for the static callback page to exchange authorization codes
- **`fetchWithTLS` utility** — wrapper around Node's built-in `fetch` with optional TLS verification control via `undici` Agent
- **`getUserGroups()` and `isUserAuthorized()`** methods on `OAuth2Client` and `OAuth2OIDCPlatform`
- **Group information in management UI** — provider dashboard displays user's group memberships
- **Callback page** (`public/callback/index.html`) — receives OAuth2 redirect, exchanges code via Homebridge bridge

### Changed

- All `fetch()` calls now use `fetchWithTLS()` to respect `tlsRejectUnauthorized`
- `DeviceAuthResponse`, `DeviceAuthPollResult`, `ProviderInfo`, `AuthStatus` types re-exported for consuming plugins
- `ProviderInfo` includes `groups` and `allowedGroups` fields

### Fixed

- Management port file write failure when parent directory didn't exist
- TypeScript strict mode errors with config type casts

### Dependencies

- `undici` — TLS-aware HTTP agent for Node.js fetch

[0.1.1]: https://github.com/lbenicio/homebridge-oauth2-oidc/releases/tag/v0.1.1

## [0.1.0] — 2026-06-21

### Added

- **OAuth2 Authorization Code flow** with PKCE (S256) support
- **OIDC Discovery** — automatic endpoint resolution from `.well-known/openid-configuration`
- **OIDC ID Token validation** via provider JWKS endpoint
- **Client Credentials grant** for server-to-server authentication
- **Device Authorization Grant** (RFC 8628) for headless environments
- **Token persistence** — file-based storage under Homebridge's persist path
- **AES-256-GCM encryption** at rest for stored tokens (opt-in via `encryptionSecret` config)
- **Proactive token refresh** — configurable interval with smart expiry-aware scheduling
- **Multi-provider support** — configure multiple identity providers simultaneously
- **Event system** — `authorized`, `token_refreshed`, and `error` events for downstream plugins
- **Public TypeScript API** — fully typed exports for consuming plugins (`OAuth2OIDCPlatform`, `OAuth2Client`, `OIDCClient`, `TokenSet`, etc.)
- **Management REST API** — local HTTP server with endpoints for provider listing, authorization, device auth polling, token refresh, and revocation
- **Management dashboard** — embedded web UI accessible at the management port
- **Homebridge Config UI X integration** — custom plugin UI via `@homebridge/plugin-ui-utils` with `customUi` support
- **Configuration schema** (`config.schema.json`) for the Homebridge UI settings form
- **Token revocation** support for both access and refresh tokens
- **UserInfo endpoint** fetching for OIDC providers
- **Callback server** utility for receiving OAuth2 redirects on a temporary local HTTP server
- **Port auto-discovery** — callback server and management API use random available ports when not explicitly configured
- **State tracking** for OAuth2 callbacks to correctly route responses to the originating provider
- `homebridge-plugin` keyword for npm discovery

### Dependencies

- `jose` ^5.9.0 — JWT verification, JWKS handling, PKCE base64url encoding
- `openid-client` ^6.3.0 — OIDC discovery and client primitives
- `@homebridge/plugin-ui-utils` ^2.0.0 — Custom UI integration with homebridge-config-ui-x
- `homebridge` ^2.0.0-beta.0 (dev) — TypeScript types for the Homebridge API
- `vitest` ^3.0.0 (dev) — Test runner (infrastructure ready, tests pending)

[0.1.0]: https://github.com/lbenicio/homebridge-oauth2-oidc/releases/tag/v0.1.0
