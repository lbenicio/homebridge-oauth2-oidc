# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
