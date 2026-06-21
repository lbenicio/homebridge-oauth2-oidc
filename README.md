# Homebridge OAuth2 / OIDC Platform Plugin

A [Homebridge](https://homebridge.io) platform plugin that provides **native OAuth2 and OpenID Connect (OIDC)** authentication support. Think of it as an auth layer that other plugins can rely on — instead of every plugin implementing its own OAuth2 flows, they can use this centralized, well-tested implementation.

## Why?

Most smart home services (Google, Nest, Philips Hue, Tesla, etc.) use OAuth2 or OIDC for authentication. Homebridge plugins for these services typically implement their own auth flows, leading to duplicated code, inconsistent UX, and potential security gaps.

This plugin solves that by being a **shared authentication platform** — configure your identity providers once, and any compatible plugin can request tokens through a simple API.

## Features

- ✅ **Authorization Code flow** with PKCE (S256) — the recommended OAuth2 flow
- ✅ **Client Credentials grant** — for server-to-server authentication
- ✅ **OIDC Discovery** — automatically resolve endpoints from `.well-known/openid-configuration`
- ✅ **ID Token validation** using the provider's JWKS endpoint
- ✅ **Token persistence** — tokens stored securely on disk and survive restarts
- ✅ **Proactive token refresh** — configurable refresh before expiry
- ✅ **Multi-provider** — configure multiple identity providers simultaneously
- ✅ **Event system** — subscribe to `authorized`, `token_refreshed`, and `error` events
- ✅ **TypeScript** — fully typed, with all public types exported for consumers

## Installation

```bash
npm install homebridge-oauth2-oidc
```

## Configuration

Add a `platforms` entry to your Homebridge `config.json`:

```jsonc
{
  "platforms": [
    {
      "platform": "OAuth2OIDC",
      "name": "OAuth2OIDC",
      "callbackHost": "localhost",
      "tokenRefreshInterval": 5,
      "providers": [
        {
          "id": "google",
          "displayName": "Google",
          "discoveryUrl": "https://accounts.google.com/.well-known/openid-configuration",
          "clientId": "YOUR_CLIENT_ID",
          "clientSecret": "YOUR_CLIENT_SECRET",
          "scopes": "openid profile email",
          "pkce": true
        },
        {
          "id": "my-custom-api",
          "displayName": "My Custom API",
          "authorizationEndpoint": "https://api.example.com/oauth2/authorize",
          "tokenEndpoint": "https://api.example.com/oauth2/token",
          "clientId": "YOUR_CLIENT_ID",
          "clientSecret": "YOUR_CLIENT_SECRET",
          "scopes": "read write",
          "pkce": true
        }
      ]
    }
  ]
}
```

### Provider Configuration Options

| Option | Required | Description |
|--------|----------|-------------|
| `id` | Yes | Unique identifier for this provider |
| `displayName` | Yes | Human-readable name |
| `discoveryUrl` | No* | OIDC discovery URL (auto-populates endpoints) |
| `authorizationEndpoint` | No* | Manual authorization endpoint (if no discovery) |
| `tokenEndpoint` | No* | Manual token endpoint (if no discovery) |
| `userInfoEndpoint` | No | OIDC UserInfo endpoint |
| `clientId` | Yes | OAuth2 client identifier |
| `clientSecret` | No | OAuth2 client secret (recommended) |
| `scopes` | No | Space-separated scopes (default: `openid profile email`) |
| `redirectPort` | No | Fixed port for callback (default: random) |
| `pkce` | No | Use PKCE (default: `true`) |

\* Must provide either `discoveryUrl` OR both `authorizationEndpoint` and `tokenEndpoint`.

## Usage by Other Plugins

Other Homebridge plugins access this platform via the Homebridge API:

```ts
import type { API } from 'homebridge';
import type { OAuth2OIDCPlatform, TokenSet } from 'homebridge-oauth2-oidc';

export default function main(api: API) {
  api.registerPlatform('my-plugin', 'MyPlatform', class {
    async doSomething() {
      // Get the OAuth2 platform instance
      const oauth2 = api.getPlatform('OAuth2OIDC') as OAuth2OIDCPlatform;

      // Get a stored token
      const token: TokenSet | null = await oauth2.getToken('google');

      if (!token) {
        // No token — need to authorize first
        // This logs a URL; the user opens it in a browser
        const result = await oauth2.authorize('google', {
          scopes: ['https://www.googleapis.com/auth/nest'],
        });
        // result.tokenSet now contains the access token
      }

      // Use the access token for API calls
      const response = await fetch('https://smartapi.googleapis.com/v1/...', {
        headers: { Authorization: `Bearer ${token.access_token}` },
      });

      // Refresh proactively
      await oauth2.refreshToken('google');
    }
  });
}
```

### Platform API Reference

| Method | Description |
|--------|-------------|
| `getProviderIds()` | List all configured provider IDs |
| `getToken(providerId)` | Get the stored token set (or `null`) |
| `authorize(providerId, params?)` | Start authorization code flow |
| `clientCredentials(providerId, params?)` | Perform client credentials grant |
| `refreshToken(providerId, refreshToken?)` | Refresh an access token |
| `revokeToken(providerId)` | Revoke tokens and clear storage |
| `fetchUserInfo(providerId)` | Fetch user info from OIDC UserInfo endpoint |
| `validateIdToken(providerId, idToken)` | Validate an ID token via JWKS |
| `on(event, listener)` | Subscribe to platform events |
| `off(event, listener)` | Unsubscribe from events |

### Events

```ts
oauth2.on('authorized', (payload) => {
  console.log('New authorization:', payload.providerId);
});

oauth2.on('token_refreshed', (payload) => {
  console.log('Token refreshed:', payload.providerId);
});

oauth2.on('error', (payload) => {
  console.error('Auth error:', payload.providerId, payload.error);
});
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Homebridge                      │
│                                                  │
│  ┌──────────────┐    ┌──────────────────────┐   │
│  │  Plugin A    │───▶│                      │   │
│  │  (Nest)      │    │  OAuth2OIDC Platform │   │
│  └──────────────┘    │                      │   │
│                       │  ┌────────────────┐  │   │
│  ┌──────────────┐    │  │  OAuth2Client   │  │   │
│  │  Plugin B    │───▶│  │  OIDCClient     │  │   │
│  │  (Tesla)     │    │  └───────┬────────┘  │   │
│  └──────────────┘    │          │            │   │
│                       │  ┌───────▼────────┐  │   │
│  ┌──────────────┐    │  │  TokenStore     │  │   │
│  │  Plugin C    │───▶│  │  (filesystem)   │  │   │
│  │  (Hue)       │    │  └────────────────┘  │   │
│  └──────────────┘    └──────────────────────┘   │
│                                                  │
└──────────────────────────────────────────────────┘
```

## How Authorization Works (Headless)

Since Homebridge typically runs headless, the authorization code flow works as follows:

1. A plugin calls `platform.authorize('google')`
2. The platform starts a **temporary local HTTP server** to receive the callback
3. The authorization URL is printed to the Homebridge log
4. The user (you) copies the URL and opens it in a browser
5. You authenticate with the identity provider
6. The provider redirects back to `http://localhost:<random-port>`
7. The local server receives the code, exchanges it for tokens, and stores them
8. Tokens are now available for use by any plugin

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run watch

# Run tests
npm test
```

## License

MIT
