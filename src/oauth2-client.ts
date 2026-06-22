/**
 * Low-level OAuth2 client — handles token exchange, refresh, and revocation
 * using direct HTTP calls. Avoids heavy dependencies; uses only Node built-ins
 * for HTTP and the `jose` library for JWT / PKCE operations.
 */

import { randomBytes } from 'node:crypto';
import type {
  ProviderConfig,
  TokenSet,
  AuthorizationParams,
  ClientCredentialsParams,
  RefreshTokenParams,
  AuthorizationResult,
  DeviceAuthResponse,
  DeviceAuthPollResult,
} from './types';
import { startCallbackServer, findAvailablePort } from './callback-server';
import { requestDeviceCode, pollDeviceToken } from './device-auth';
import { fetchWithTLS } from './tls-fetch';

/**
 * Generate a PKCE code verifier and challenge.
 * Uses S256 method as recommended by the OAuth2 BCP.
 */
export async function generatePKCE(): Promise<{ verifier: string; challenge: string }> {
  // We use jose for this to get proper base64url encoding
  const { base64url } = await import('jose');

  const verifier = base64url.encode(randomBytes(32));
  // SHA-256 hash of the verifier, then base64url encoded
  const hash = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  );
  const challenge = base64url.encode(hash);
  return { verifier, challenge };
}

interface ClientConfig {
  clientId: string;
  clientSecret?: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userInfoEndpoint?: string;
  redirectUri: string;
  pkce: boolean;
  defaultScopes: string;
  tlsRejectUnauthorized: boolean;
  allowedGroups?: string[];
  groupsClaim: string;
}

export class OAuth2Client {
  readonly providerId: string;
  private config: ClientConfig;

  constructor(providerConfig: ProviderConfig, redirectUri: string) {
    this.providerId = providerConfig.id;
    this.config = {
      clientId: providerConfig.clientId,
      clientSecret: providerConfig.clientSecret,
      authorizationEndpoint: providerConfig.authorizationEndpoint!,
      tokenEndpoint: providerConfig.tokenEndpoint!,
      userInfoEndpoint: providerConfig.userInfoEndpoint,
      redirectUri,
      pkce: providerConfig.pkce,
      defaultScopes: providerConfig.scopes || 'openid profile email',
      tlsRejectUnauthorized: providerConfig.tlsRejectUnauthorized ?? true,
      allowedGroups: providerConfig.allowedGroups,
      groupsClaim: providerConfig.groupsClaim || 'groups',
    };
  }

  /** Build the authorization URL for starting the auth code flow */
  async buildAuthorizationUrl(params: AuthorizationParams): Promise<{ url: string; verifier?: string }> {
    const scopes = params.scopes?.join(' ') ?? this.config.defaultScopes;
    const state = params.state ?? randomBytes(16).toString('hex');
    const redirectUri = params.redirectUri ?? this.config.redirectUri;

    const authParams = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      scope: scopes,
      state,
    });

    // Add any extra params
    if (params.extraParams) {
      for (const [key, value] of Object.entries(params.extraParams)) {
        authParams.set(key, value);
      }
    }

    let verifier: string | undefined;
    if (this.config.pkce) {
      const pkce = await generatePKCE();
      authParams.set('code_challenge', pkce.challenge);
      authParams.set('code_challenge_method', 'S256');
      verifier = pkce.verifier;
    }

    const url = `${this.config.authorizationEndpoint}?${authParams.toString()}`;
    return { url, verifier };
  }

  /**
   * Perform the full authorization code flow:
   * 1. Start a local HTTP server to receive the callback
   * 2. Generate the authorization URL
   * 3. Wait for the callback
   * 4. Exchange the code for tokens
   */
  async authorize(params: AuthorizationParams): Promise<AuthorizationResult> {
    const host = '127.0.0.1';
    const port = await findAvailablePort();

    // Build the redirect URI pointing at our local server
    const redirectUri = `http://${host}:${port}`;
    const authParams: AuthorizationParams = {
      ...params,
      redirectUri,
    };

    const { url, verifier } = await this.buildAuthorizationUrl(authParams);

    // Start the server (don't await — we need to print the URL first)
    const callbackPromise = startCallbackServer(port, host, 120_000);

    // Log the URL the user needs to visit
    console.log(`[OAuth2OIDC] ╔══════════════════════════════════════════════════════════╗`);
    console.log(`[OAuth2OIDC] ║  Open this URL to authorize "${params.providerId}":`);
    console.log(`[OAuth2OIDC] ║  ${url}`);
    console.log(`[OAuth2OIDC] ╚══════════════════════════════════════════════════════════╝`);

    // Wait for the callback
    const { code } = await callbackPromise;

    // Exchange code for tokens
    const tokenSet = await this.exchangeCodeForTokens(code, redirectUri, verifier);

    return {
      providerId: this.providerId,
      tokenSet,
    };
  }

  /** Exchange an authorization code for tokens */
  async exchangeCodeForTokens(
    code: string,
    redirectUri: string,
    codeVerifier?: string
  ): Promise<TokenSet> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri,
      client_id: this.config.clientId,
    });

    if (codeVerifier) {
      body.set('code_verifier', codeVerifier);
    }

    return this.tokenRequest(body);
  }

  /** Perform the client credentials grant */
  async clientCredentials(params: ClientCredentialsParams): Promise<AuthorizationResult> {
    const scopes = params.scopes?.join(' ') ?? this.config.defaultScopes;

    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: scopes,
    });

    if (params.extraParams) {
      for (const [key, value] of Object.entries(params.extraParams)) {
        body.set(key, value);
      }
    }

    const tokenSet = await this.tokenRequest(body);

    return {
      providerId: this.providerId,
      tokenSet,
    };
  }

  /** Refresh an access token using a refresh token */
  async refreshAccessToken(params: RefreshTokenParams): Promise<TokenSet> {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: params.refreshToken,
      client_id: this.config.clientId,
    });

    return this.tokenRequest(body);
  }

  /** Revoke a token (access or refresh) */
  async revokeToken(token: string, tokenTypeHint?: 'access_token' | 'refresh_token'): Promise<void> {
    const body = new URLSearchParams({
      token,
      client_id: this.config.clientId,
    });
    if (tokenTypeHint) {
      body.set('token_type_hint', tokenTypeHint);
    }

    const url = this.config.tokenEndpoint.replace(/\/token$/, '/revoke');
    const response = await fetchWithTLS(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    }, this.config.tlsRejectUnauthorized);

    if (!response.ok && response.status !== 200) {
      const text = await response.text().catch(() => '');
      throw new Error(`Token revocation failed: ${response.status} ${text}`);
    }
  }

  /** Low-level token request */
  private async tokenRequest(body: URLSearchParams): Promise<TokenSet> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    };

    // HTTP Basic auth if client secret is provided
    if (this.config.clientSecret) {
      const credentials = Buffer.from(
        `${encodeURIComponent(this.config.clientId)}:${encodeURIComponent(this.config.clientSecret)}`
      ).toString('base64');
      headers['Authorization'] = `Basic ${credentials}`;
    }

    const response = await fetchWithTLS(this.config.tokenEndpoint, {
      method: 'POST',
      headers,
      body: body.toString(),
    }, this.config.tlsRejectUnauthorized);

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`Token request failed: ${response.status} ${text}`);
    }

    const data = await response.json() as Record<string, unknown>;

    // Convert the response to our TokenSet format
    const tokenSet: TokenSet = {
      access_token: data.access_token as string,
      refresh_token: data.refresh_token as string | undefined,
      id_token: data.id_token as string | undefined,
      token_type: (data.token_type as string) ?? 'Bearer',
      scope: data.scope as string | undefined,
    };

    // Compute expires_at from expires_in
    if (typeof data.expires_in === 'number') {
      tokenSet.expires_in = data.expires_in;
      tokenSet.expires_at = Date.now() + data.expires_in * 1000;
    }

    return tokenSet;
  }

  /**
   * Initiate the Device Authorization Grant (RFC 8628).
   *
   * This flow is ideal for headless environments: it returns a
   * user_code + verification_uri that the user opens on any device,
   * then polls until authorization is complete.
   *
   * @param deviceEndpoint The device authorization endpoint URL.
   *                        If not provided, it tries to derive it from
   *                        the token endpoint (common for some providers).
   */
  async startDeviceAuth(
    scopes?: string[],
    deviceEndpoint?: string,
    audience?: string
  ): Promise<DeviceAuthResponse> {
    const endpoint = deviceEndpoint ?? this.deriveDeviceEndpoint();
    return requestDeviceCode(
      {
        clientId: this.config.clientId,
        clientSecret: this.config.clientSecret,
        scopes: scopes?.join(' ') ?? this.config.defaultScopes,
      },
      endpoint,
      audience
    );
  }

  /**
   * Poll for completion of a device authorization.
   * Resolves with the token set on success, throws on failure.
   */
  async pollDeviceAuth(
    deviceCode: string,
    options?: {
      interval?: number;
      timeoutMs?: number;
      onStatus?: (status: DeviceAuthPollResult) => void;
    }
  ): Promise<TokenSet> {
    return pollDeviceToken(
      deviceCode,
      this.config.clientId,
      this.config.clientSecret,
      this.config.tokenEndpoint,
      options
    );
  }

  /**
   * Attempt to derive the device authorization endpoint from the
   * standard token endpoint. Many providers use a predictable path.
   */
  private deriveDeviceEndpoint(): string {
    const url = new URL(this.config.tokenEndpoint);
    // Common patterns: /oauth/device/code, /device, etc.
    // Default to replacing /token with /device/code
    if (url.pathname.endsWith('/token')) {
      url.pathname = url.pathname.replace(/\/token$/, '/device/code');
    } else if (url.pathname.endsWith('/oauth/token')) {
      url.pathname = url.pathname.replace(/\/token$/, '/device/code');
    } else {
      url.pathname = url.pathname.replace(/\/+$/, '') + '/device/code';
    }
    return url.toString();
  }

  /** Fetch user info from the UserInfo endpoint (requires a valid access token) */
  async fetchUserInfo(accessToken: string): Promise<Record<string, unknown>> {
    if (!this.config.userInfoEndpoint) {
      throw new Error('No UserInfo endpoint configured for this provider');
    }

    const response = await fetchWithTLS(this.config.userInfoEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }, this.config.tlsRejectUnauthorized);

    if (!response.ok) {
      throw new Error(`UserInfo request failed: ${response.status}`);
    }

    return response.json() as Promise<Record<string, unknown>>;
  }

  async getUserGroups(accessToken: string, idToken?: string): Promise<string[] | null> {
    let claims: Record<string, unknown> | null = null;
    if (this.config.userInfoEndpoint) {
      try { claims = await this.fetchUserInfo(accessToken); } catch { /* fall through */ }
    }
    if (!claims && idToken) {
      try {
        const parts = idToken.split('.');
        if (parts.length === 3) claims = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'));
      } catch { /* ignore */ }
    }
    if (!claims) return null;
    const raw = claims[this.config.groupsClaim];
    if (!raw) return null;
    if (Array.isArray(raw)) return raw.map(String);
    if (typeof raw === 'string') return raw.split(',').map(g => g.trim());
    return null;
  }

  async isUserAuthorized(accessToken: string, idToken?: string): Promise<{ authorized: boolean; groups: string[] | null }> {
    const allowed = this.config.allowedGroups;
    if (!allowed?.length) return { authorized: true, groups: null };
    const groups = await this.getUserGroups(accessToken, idToken);
    if (!groups) return { authorized: false, groups: null };
    const lower = allowed.map(g => g.toLowerCase());
    return { authorized: groups.some(g => lower.includes(g.toLowerCase())), groups };
  }
}
