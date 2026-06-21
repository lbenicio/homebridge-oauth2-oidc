/**
 * Homebridge OAuth2/OIDC Platform Plugin
 *
 * This platform plugin does not create HomeKit accessories directly.
 * Instead, it provides an OAuth2/OIDC authentication layer that other
 * Homebridge plugins can use to authenticate against identity providers.
 *
 * It also starts a local management HTTP API that powers the custom
 * configuration UI in homebridge-config-ui-x.
 *
 * Other plugins access this platform via the Homebridge API:
 *   const oauth2Platform = api.getPlatform('OAuth2OIDC') as OAuth2OIDCPlatform;
 */

import http from 'node:http';
import { URL } from 'node:url';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import type {
  API,
  IndependentPlatformPlugin,
  PlatformConfig,
  Logging,
} from 'homebridge';
import type {
  OAuth2PlatformConfig,
  ProviderConfig,
  AuthorizationParams,
  AuthorizationResult,
  ClientCredentialsParams,
  RefreshTokenParams,
  TokenSet,
  OAuth2PlatformEvent,
  TokenRefreshedPayload,
  AuthorizedPayload,
  ErrorPayload,
  DeviceAuthResponse,
  DeviceAuthPollResult,
  ProviderInfo,
  AuthStatus,
} from './types';
import { OAuth2Client } from './oauth2-client';
import { OIDCClient, fetchDiscoveryMetadata } from './oidc-client';
import { TokenStore } from './token-store';

/** Typed event listener */
type EventListener<T> = (payload: T) => void;

/** Path to the port file that the UI server reads */
const PORT_FILE = 'homebridge-oauth2-oidc/.management-port';

/** Pending device auth flows: providerId → { deviceCode, client } */
interface PendingDeviceAuth {
  deviceCode: string;
  expiresAt: number;
}

export class OAuth2OIDCPlatform implements IndependentPlatformPlugin {
  private readonly log: Logging;
  private readonly config: OAuth2PlatformConfig;
  private readonly api: API;
  private readonly tokenStore: TokenStore;

  /** Map of provider ID → OAuth2/OIDC client instance */
  private readonly clients = new Map<string, OAuth2Client | OIDCClient>();

  /** Active refresh timers by provider ID */
  private readonly refreshTimers = new Map<string, ReturnType<typeof setTimeout>>();

  /** Event listeners */
  private readonly listeners = new Map<OAuth2PlatformEvent, Set<EventListener<unknown>>>();

  /** Management HTTP server */
  private managementServer: http.Server | null = null;
  private managementPort: number = 0;

  /** Pending device auth flows tracked for the management API */
  private readonly pendingDeviceAuths = new Map<string, PendingDeviceAuth>();

  constructor(log: Logging, config: PlatformConfig, api: API) {
    this.log = log;
    this.api = api;

    // Parse and validate the platform config
    this.config = config as unknown as OAuth2PlatformConfig;
    if (!this.config.providers || !Array.isArray(this.config.providers)) {
      throw new Error('OAuth2OIDC platform requires a "providers" array in config');
    }

    // Create the token store using the filesystem with optional encryption
    const storagePath = api.user.persistPath();
    const encryptionSecret = this.config.encryptionSecret;
    this.tokenStore = new TokenStore(storagePath, encryptionSecret);

    // Initialize each configured provider
    this.initializeProviders().catch((err) => {
      this.log.error('Failed to initialize OAuth2/OIDC providers:', err.message);
    });

    // Start the management API server
    this.startManagementServer().catch((err) => {
      this.log.error('Failed to start management API server:', err.message);
    });

    this.log.info(`OAuth2OIDC platform initialized with ${this.config.providers.length} provider(s)`);
  }

  // ─── Provider Initialization ────────────────────────────────────────

  private async initializeProviders(): Promise<void> {
    const callbackHost = this.config.callbackHost || 'localhost';

    for (const providerConfig of this.config.providers) {
      try {
        const client = await this.createClient(providerConfig, callbackHost);
        this.clients.set(providerConfig.id, client);

        // Load existing tokens from storage
        const storedTokens = await this.tokenStore.get(providerConfig.id);
        if (storedTokens) {
          this.log.info(`Loaded stored tokens for provider "${providerConfig.id}"`);

          // Schedule proactive refresh if a refresh token is available
          if (storedTokens.refresh_token) {
            this.scheduleTokenRefresh(providerConfig.id, storedTokens);
          }
        }
      } catch (err) {
        this.log.error(
          `Failed to initialize provider "${providerConfig.id}":`,
          (err as Error).message
        );
      }
    }
  }

  private async createClient(
    providerConfig: ProviderConfig,
    callbackHost: string
  ): Promise<OAuth2Client | OIDCClient> {
    // Determine the redirect URI base
    const host = providerConfig.redirectPort
      ? `${callbackHost}:${providerConfig.redirectPort}`
      : callbackHost;
    const redirectUri = `http://${host}`;

    // Try OIDC discovery if a discovery URL is configured
    if (providerConfig.discoveryUrl) {
      try {
        this.log.info(`Performing OIDC discovery for "${providerConfig.id}"...`);
        const metadata = await fetchDiscoveryMetadata(providerConfig.discoveryUrl);
        this.log.info(`OIDC discovery complete for "${providerConfig.id}" — issuer: ${metadata.issuer}`);
        return new OIDCClient(providerConfig, redirectUri, metadata);
      } catch (err) {
        this.log.warn(
          `OIDC discovery failed for "${providerConfig.id}", falling back to manual config:`,
          (err as Error).message
        );
      }
    }

    // Fall back to manual endpoint configuration
    if (!providerConfig.authorizationEndpoint || !providerConfig.tokenEndpoint) {
      throw new Error(
        `Provider "${providerConfig.id}": must provide either discoveryUrl or both authorizationEndpoint and tokenEndpoint`
      );
    }

    return new OIDCClient(providerConfig, redirectUri, null);
  }

  // ─── Public API for Other Plugins ───────────────────────────────────

  /**
   * Get a list of all configured provider IDs.
   * Other plugins can use this to discover available providers.
   */
  getProviderIds(): string[] {
    return Array.from(this.clients.keys());
  }

  /**
   * Get the stored token set for a provider (if available).
   * Returns null if no tokens have been obtained yet.
   */
  async getToken(providerId: string): Promise<TokenSet | null> {
    return this.tokenStore.get(providerId);
  }

  /**
   * Initiate the authorization code flow for a provider.
   * This will start a local HTTP server and log the authorization URL.
   * The resulting tokens are automatically stored.
   *
   * NOTE: In a headless Homebridge environment, the user must manually
   * open the printed URL in a browser. The callback goes to the local
   * HTTP server that is started temporarily.
   */
  async authorize(providerId: string, params?: Partial<AuthorizationParams>): Promise<AuthorizationResult> {
    const client = this.getClient(providerId);

    const result = await client.authorize({
      providerId,
      ...params,
    });

    // Store the tokens
    await this.tokenStore.set(providerId, result.tokenSet);
    this.emit('authorized', { providerId, tokenSet: result.tokenSet } as AuthorizedPayload);

    // Schedule refresh if a refresh token is present
    if (result.tokenSet.refresh_token) {
      this.scheduleTokenRefresh(providerId, result.tokenSet);
    }

    return result;
  }

  /**
   * Initiate the authorization code flow and return the authorization URL
   * WITHOUT blocking. The caller must later call completeAuthorization().
   *
   * This is used by the management API so the UI can start auth and poll.
   */
  async startAuthorization(providerId: string, params?: Partial<AuthorizationParams>): Promise<{ authUrl: string; verifier?: string }> {
    const client = this.getClient(providerId);

    // Use the management server as the callback target
    const redirectUri = `http://127.0.0.1:${this.managementPort}/callback`;

    const { url, verifier } = await client.buildAuthorizationUrl({
      providerId,
      redirectUri,
      ...params,
    });

    this.log.info(`Authorization URL for "${providerId}": ${url}`);

    return { authUrl: url, verifier };
  }

  /**
   * Complete an authorization code flow using a code received by the
   * management server's callback endpoint.
   */
  async completeAuthorization(providerId: string, code: string, verifier?: string): Promise<AuthorizationResult> {
    const client = this.getClient(providerId);
    const redirectUri = `http://127.0.0.1:${this.managementPort}/callback`;

    const tokenSet = await client.exchangeCodeForTokens(code, redirectUri, verifier);

    await this.tokenStore.set(providerId, tokenSet);
    this.emit('authorized', { providerId, tokenSet } as AuthorizedPayload);

    if (tokenSet.refresh_token) {
      this.scheduleTokenRefresh(providerId, tokenSet);
    }

    return { providerId, tokenSet };
  }

  /**
   * Perform a client credentials grant for a provider.
   * The resulting tokens are automatically stored.
   */
  async clientCredentials(
    providerId: string,
    params?: Partial<ClientCredentialsParams>
  ): Promise<AuthorizationResult> {
    const client = this.getClient(providerId);

    const result = await client.clientCredentials({
      providerId,
      ...params,
    });

    await this.tokenStore.set(providerId, result.tokenSet);
    this.emit('authorized', { providerId, tokenSet: result.tokenSet } as AuthorizedPayload);

    return result;
  }

  /**
   * Start a Device Authorization Grant (RFC 8628).
   * Returns the user_code + verification_uri for the user to complete
   * on another device. Poll getDeviceAuthStatus() for completion.
   */
  async startDeviceAuth(
    providerId: string,
    scopes?: string[],
    audience?: string
  ): Promise<DeviceAuthResponse> {
    const client = this.getClient(providerId);
    const response = await client.startDeviceAuth(scopes, undefined, audience);

    // Track this pending flow
    this.pendingDeviceAuths.set(providerId, {
      deviceCode: response.device_code,
      expiresAt: Date.now() + response.expires_in * 1000,
    });

    // Start polling in the background; resolve when complete
    this.pollDeviceAuthInBackground(providerId, client, response.device_code);

    this.log.info(
      `Device auth for "${providerId}": go to ${response.verification_uri} and enter code ${response.user_code}`
    );

    return response;
  }

  /**
   * Get the current device auth status for a provider.
   */
  getDeviceAuthStatus(providerId: string): { status: 'pending' | 'complete' | 'none' } {
    if (this.pendingDeviceAuths.has(providerId)) {
      return { status: 'pending' };
    }
    // Check if we have a token for this provider
    // We'll do this async in the API handler — for sync, just check the map
    return { status: 'none' };
  }

  private async pollDeviceAuthInBackground(
    providerId: string,
    client: OAuth2Client | OIDCClient,
    deviceCode: string
  ): Promise<void> {
    try {
      const tokenSet = await client.pollDeviceAuth(deviceCode);
      await this.tokenStore.set(providerId, tokenSet);
      this.pendingDeviceAuths.delete(providerId);
      this.emit('authorized', { providerId, tokenSet } as AuthorizedPayload);

      if (tokenSet.refresh_token) {
        this.scheduleTokenRefresh(providerId, tokenSet);
      }

      this.log.info(`Device auth complete for "${providerId}"`);
    } catch (err) {
      this.pendingDeviceAuths.delete(providerId);
      this.log.error(`Device auth failed for "${providerId}":`, (err as Error).message);
      this.emit('error', { providerId, error: err as Error } as ErrorPayload);
    }
  }

  /**
   * Refresh an access token for a provider.
   * The new token set is automatically stored.
   */
  async refreshToken(providerId: string, refreshToken?: string): Promise<TokenSet> {
    const client = this.getClient(providerId);

    // If no refresh token is provided, try to get it from storage
    if (!refreshToken) {
      const stored = await this.tokenStore.get(providerId);
      if (!stored?.refresh_token) {
        throw new Error(`No refresh token available for provider "${providerId}"`);
      }
      refreshToken = stored.refresh_token;
    }

    const tokenSet = await client.refreshAccessToken({
      providerId,
      refreshToken,
    });

    await this.tokenStore.set(providerId, tokenSet);
    this.emit('token_refreshed', { providerId, tokenSet } as TokenRefreshedPayload);

    return tokenSet;
  }

  /**
   * Revoke all tokens for a provider and clear stored data.
   */
  async revokeToken(providerId: string): Promise<void> {
    const stored = await this.tokenStore.get(providerId);
    if (stored) {
      const client = this.getClient(providerId);
      try {
        await client.revokeToken(stored.access_token, 'access_token');
        if (stored.refresh_token) {
          await client.revokeToken(stored.refresh_token, 'refresh_token');
        }
      } catch (err) {
        this.log.warn(`Error revoking tokens for "${providerId}":`, (err as Error).message);
      }
    }

    await this.tokenStore.delete(providerId);
    this.clearRefreshTimer(providerId);
  }

  /**
   * Fetch user info from the OIDC UserInfo endpoint.
   * Only available if the provider has a UserInfo endpoint configured.
   */
  async fetchUserInfo(providerId: string): Promise<Record<string, unknown>> {
    const client = this.getClient(providerId);
    const tokenSet = await this.tokenStore.get(providerId);
    if (!tokenSet) {
      throw new Error(`No tokens available for provider "${providerId}"`);
    }
    return client.fetchUserInfo(tokenSet.access_token);
  }

  /**
   * Validate an ID token (requires OIDC discovery metadata).
   * Returns the decoded payload if valid.
   */
  async validateIdToken(providerId: string, idToken: string): Promise<Record<string, unknown>> {
    const client = this.getClient(providerId);
    if (!(client instanceof OIDCClient)) {
      throw new Error(`Provider "${providerId}" is not an OIDC client`);
    }
    return client.validateIdToken(idToken);
  }

  // ─── Event System ───────────────────────────────────────────────────

  /**
   * Subscribe to platform events.
   *
   * Events:
   * - 'authorized' — emitted when a new authorization completes
   * - 'token_refreshed' — emitted when tokens are proactively refreshed
   * - 'token_revoked' — emitted when tokens are revoked
   * - 'error' — emitted on errors during refresh or other operations
   */
  on(event: OAuth2PlatformEvent, listener: EventListener<unknown>): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(listener);
  }

  /** Unsubscribe from platform events */
  off(event: OAuth2PlatformEvent, listener: EventListener<unknown>): void {
    this.listeners.get(event)?.delete(listener);
  }

  private emit(event: OAuth2PlatformEvent, payload: unknown): void {
    this.listeners.get(event)?.forEach((listener) => {
      try {
        listener(payload);
      } catch (err) {
        this.log.error(`Error in event listener for "${event}":`, (err as Error).message);
      }
    });
  }

  // ─── Token Refresh Scheduling ──────────────────────────────────────

  private scheduleTokenRefresh(providerId: string, tokenSet: TokenSet): void {
    this.clearRefreshTimer(providerId);

    const intervalMinutes = this.config.tokenRefreshInterval ?? 5;
    if (intervalMinutes <= 0) return;

    // If we know when the token expires, refresh a bit before that
    let delayMs: number;
    if (tokenSet.expires_at) {
      const expiresIn = tokenSet.expires_at - Date.now();
      // Refresh when 80% of the lifetime has elapsed, or at least 30s before expiry
      delayMs = Math.max(expiresIn * 0.8, expiresIn - 30_000);
    } else {
      // If no expiry info, use the configured interval
      delayMs = intervalMinutes * 60_000;
    }

    // Ensure we don't set a negative or zero delay
    delayMs = Math.max(delayMs, 10_000);

    this.log.debug(`Scheduling token refresh for "${providerId}" in ${Math.round(delayMs / 1000)}s`);

    const timer = setTimeout(async () => {
      try {
        this.log.info(`Proactively refreshing token for "${providerId}"`);
        await this.refreshToken(providerId);
      } catch (err) {
        this.log.error(`Failed to refresh token for "${providerId}":`, (err as Error).message);
        this.emit('error', {
          providerId,
          error: err as Error,
        } as ErrorPayload);
      }
    }, delayMs);

    this.refreshTimers.set(providerId, timer);
  }

  private clearRefreshTimer(providerId: string): void {
    const timer = this.refreshTimers.get(providerId);
    if (timer) {
      clearTimeout(timer);
      this.refreshTimers.delete(providerId);
    }
  }

  // ─── Management HTTP API ────────────────────────────────────────────

  private async startManagementServer(): Promise<void> {
    // Use a configured port or find an available one
    const configuredPort = this.config.managementPort;
    const port = configuredPort || await this.findAvailablePort();

    this.managementServer = http.createServer((req, res) => {
      this.handleManagementRequest(req, res);
    });

    return new Promise((resolve, reject) => {
      this.managementServer!.listen(port, '127.0.0.1', async () => {
        this.managementPort = port;
        this.log.info(`Management API listening on http://127.0.0.1:${port}`);

        // Write the port to a well-known file for the UI server
        try {
          const portFilePath = join(this.api.user.persistPath(), PORT_FILE);
          await writeFile(portFilePath, String(port), 'utf-8');
        } catch (err) {
          this.log.warn('Could not write management port file:', (err as Error).message);
        }

        resolve();
      });

      this.managementServer!.on('error', reject);
    });
  }

  private findAvailablePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = http.createServer();
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (!addr || typeof addr === 'string') {
          server.close();
          reject(new Error('Could not determine port'));
          return;
        }
        const port = addr.port;
        server.close(() => resolve(port));
      });
      server.on('error', reject);
    });
  }

  private async handleManagementRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    // CORS for the UI (served from homebridge UI or direct access)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const parsedUrl = new URL(req.url ?? '/', `http://127.0.0.1:${this.managementPort}`);
    const path = parsedUrl.pathname;
    const parts = path.split('/').filter(Boolean);

    try {
      // GET /api/providers
      if (req.method === 'GET' && path === '/api/providers' && parts.length === 2) {
        return this.handleGetProviders(res);
      }

      // GET /api/providers/:id/status
      if (req.method === 'GET' && parts[0] === 'api' && parts[1] === 'providers' && parts[3] === 'status') {
        return this.handleGetProviderStatus(parts[2], res);
      }

      // GET /api/providers/:id/device-auth-status
      if (req.method === 'GET' && parts[0] === 'api' && parts[1] === 'providers' && parts[3] === 'device-auth-status') {
        return this.handleGetDeviceAuthStatus(parts[2], res);
      }

      // POST /api/providers/:id/authorize
      if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'providers' && parts[3] === 'authorize') {
        return this.handleStartAuthorization(parts[2], req, res);
      }

      // POST /api/providers/:id/device-authorize
      if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'providers' && parts[3] === 'device-authorize') {
        return this.handleStartDeviceAuth(parts[2], req, res);
      }

      // POST /api/providers/:id/refresh
      if (req.method === 'POST' && parts[0] === 'api' && parts[1] === 'providers' && parts[3] === 'refresh') {
        return this.handleRefreshToken(parts[2], res);
      }

      // DELETE /api/providers/:id/token
      if (req.method === 'DELETE' && parts[0] === 'api' && parts[1] === 'providers' && parts[3] === 'token') {
        return this.handleRevokeToken(parts[2], res);
      }

      // GET /callback — OAuth2 redirect callback
      if (req.method === 'GET' && path === '/callback') {
        return this.handleCallback(req, res);
      }

      // GET / — serve the management UI
      if (req.method === 'GET' && (path === '/' || path === '')) {
        return this.handleServeUI(res);
      }

      // 404
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    } catch (err) {
      this.log.error('Management API error:', (err as Error).message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: (err as Error).message }));
    }
  }

  private async handleGetProviders(res: http.ServerResponse): Promise<void> {
    const providers: ProviderInfo[] = [];

    for (const [id, client] of this.clients) {
      const token = await this.tokenStore.get(id);
      providers.push({
        id,
        displayName: (this.config.providers.find(p => p.id === id))?.displayName ?? id,
        hasToken: token !== null,
        isOIDC: client instanceof OIDCClient && client.usesDiscovery,
        tokenExpiry: token?.expires_at,
        scopes: token?.scope,
      });
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(providers));
  }

  private async handleGetProviderStatus(providerId: string, res: http.ServerResponse): Promise<void> {
    const token = await this.tokenStore.get(providerId);
    const deviceAuth = this.pendingDeviceAuths.get(providerId);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      hasToken: token !== null,
      expiresAt: token?.expires_at ?? null,
      scopes: token?.scope ?? null,
      deviceAuthPending: deviceAuth !== null,
      encryptionEnabled: this.tokenStore.isEncrypted,
    }));
  }

  private async handleGetDeviceAuthStatus(providerId: string, res: http.ServerResponse): Promise<void> {
    const pending = this.pendingDeviceAuths.get(providerId);
    const token = await this.tokenStore.get(providerId);

    if (token && !pending) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'complete' }));
      return;
    }

    if (pending && Date.now() < pending.expiresAt) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'pending' }));
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'expired' }));
  }

  private async handleStartAuthorization(
    providerId: string,
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    const body = await readRequestBody(req);
    const scopes = body.scopes ? (Array.isArray(body.scopes) ? body.scopes : [body.scopes]) : undefined;

    // Use the state-tracking version so the callback knows which provider
    const { authUrl } = await this.startAuthorizationWithState(providerId, { scopes });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ authUrl }));
  }

  private async handleStartDeviceAuth(
    providerId: string,
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    const body = await readRequestBody(req);
    const scopes = body.scopes ? (Array.isArray(body.scopes) ? body.scopes : [body.scopes]) : undefined;

    const response = await this.startDeviceAuth(providerId, scopes);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(response));
  }

  private async handleRefreshToken(providerId: string, res: http.ServerResponse): Promise<void> {
    const tokenSet = await this.refreshToken(providerId);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      success: true,
      expiresAt: tokenSet.expires_at,
      scopes: tokenSet.scope,
    }));
  }

  private async handleRevokeToken(providerId: string, res: http.ServerResponse): Promise<void> {
    await this.revokeToken(providerId);

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
  }

  private async handleCallback(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    const parsedUrl = new URL(req.url ?? '/', `http://127.0.0.1:${this.managementPort}`);
    const code = parsedUrl.searchParams.get('code');
    const state = parsedUrl.searchParams.get('state');
    const error = parsedUrl.searchParams.get('error');
    const errorDescription = parsedUrl.searchParams.get('error_description');

    if (error) {
      res.writeHead(400, { 'Content-Type': 'text/html' });
      res.end(`<html><body><h1>Authorization Error</h1><p>${errorDescription ?? error}</p></body></html>`);
      return;
    }

    if (!code) {
      res.writeHead(400, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Missing Code</h1><p>No authorization code received.</p></body></html>');
      return;
    }

    // The state parameter should encode the provider ID
    // For now, we need a mapping. Let's use a simple approach:
    // The state is used to identify which provider initiated this flow.
    // We'll read the state → providerId mapping from a pending map.
    const providerId = this.resolveProviderFromState(state);

    try {
      const result = await this.completeAuthorization(providerId, code);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><body><h1>Authorization Successful</h1><p>Provider "${result.providerId}" authorized. You may close this window.</p></body></html>`);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/html' });
      res.end(`<html><body><h1>Authorization Failed</h1><p>${(err as Error).message}</p></body></html>`);
    }
  }

  private pendingStates = new Map<string, string>(); // state → providerId

  private resolveProviderFromState(state: string | null): string {
    if (state && this.pendingStates.has(state)) {
      const providerId = this.pendingStates.get(state)!;
      this.pendingStates.delete(state);
      return providerId;
    }
    // Fallback: return first provider (for single-provider setups)
    const firstProvider = this.clients.keys().next().value;
    if (!firstProvider) {
      throw new Error('No providers configured');
    }
    return firstProvider;
  }

  // Override startAuthorization to track state → providerId mapping
  async startAuthorizationWithState(providerId: string, params?: Partial<AuthorizationParams>): Promise<{ authUrl: string }> {
    const client = this.getClient(providerId);
    const redirectUri = `http://127.0.0.1:${this.managementPort}/callback`;
    const state = Math.random().toString(36).substring(2, 15);

    this.pendingStates.set(state, providerId);

    const { url } = await client.buildAuthorizationUrl({
      providerId,
      redirectUri,
      state,
      ...params,
    });

    this.log.info(`Authorization URL for "${providerId}": ${url}`);

    return { authUrl: url };
  }

  private async handleServeUI(res: http.ServerResponse): Promise<void> {
    const html = getManagementUIHTML();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  }

  // ─── Helpers ────────────────────────────────────────────────────────

  private getClient(providerId: string): OAuth2Client | OIDCClient {
    const client = this.clients.get(providerId);
    if (!client) {
      throw new Error(`Provider "${providerId}" is not configured`);
    }
    return client;
  }

  // ─── Homebridge PlatformPlugin Interface ───────────────────────────

  /**
   * Called by Homebridge when cached accessories are restored.
   * This platform doesn't create accessories, so this is a no-op.
   */
  configureAccessory(): void {
    // No-op: this platform does not create accessories
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────

async function readRequestBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

// ─── Management UI HTML ───────────────────────────────────────────────

function getManagementUIHTML(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OAuth2/OIDC — Homebridge</title>
  <style>
    :root {
      --bg: #1a1a2e;
      --surface: #16213e;
      --card: #0f3460;
      --accent: #e94560;
      --accent-hover: #ff6b81;
      --text: #eee;
      --text-muted: #a0a0b0;
      --success: #2ecc71;
      --warning: #f39c12;
      --danger: #e74c3c;
      --border: rgba(255,255,255,0.08);
      --radius: 10px;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      padding: 24px;
    }
    h1 { font-size: 1.6rem; font-weight: 600; margin-bottom: 4px; }
    .subtitle { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 24px; }
    .grid { display: grid; gap: 20px; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      transition: border-color 0.2s;
    }
    .card:hover { border-color: rgba(255,255,255,0.15); }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }
    .card-header h2 { font-size: 1.1rem; font-weight: 600; }
    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 0.72rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-active { background: rgba(46,204,113,0.15); color: var(--success); }
    .badge-inactive { background: rgba(160,160,176,0.1); color: var(--text-muted); }
    .badge-oidc { background: rgba(233,69,96,0.12); color: var(--accent); }
    .meta { font-size: 0.78rem; color: var(--text-muted); margin-bottom: 14px; }
    .meta span { margin-right: 16px; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    button {
      padding: 7px 16px;
      border: 1px solid var(--border);
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s;
      background: transparent;
      color: var(--text);
    }
    button:hover { border-color: rgba(255,255,255,0.25); background: rgba(255,255,255,0.04); }
    button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    button.primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
    button.danger { color: var(--danger); }
    button.danger:hover { background: rgba(231,76,60,0.1); border-color: var(--danger); }
    button:disabled { opacity: 0.4; cursor: not-allowed; }
    .device-auth-box {
      margin-top: 12px;
      padding: 14px;
      background: rgba(0,0,0,0.25);
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .device-auth-box .code {
      font-size: 1.8rem;
      font-weight: 700;
      letter-spacing: 4px;
      color: var(--accent);
      text-align: center;
      margin: 8px 0;
    }
    .device-auth-box .uri {
      font-size: 0.82rem;
      color: var(--text-muted);
      text-align: center;
      word-break: break-all;
    }
    .device-auth-box .expiry {
      font-size: 0.72rem;
      color: var(--warning);
      text-align: center;
      margin-top: 6px;
    }
    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 500;
      opacity: 0;
      transform: translateY(10px);
      transition: all 0.3s;
      z-index: 100;
      pointer-events: none;
    }
    .toast.show { opacity: 1; transform: translateY(0); }
    .toast-success { background: var(--success); color: #fff; }
    .toast-error { background: var(--danger); color: #fff; }
    .loading { opacity: 0.6; pointer-events: none; }
  </style>
</head>
<body>
  <h1>🔐 OAuth2 / OIDC</h1>
  <p class="subtitle">Manage identity providers and authentication tokens</p>
  <div class="grid" id="provider-grid"></div>
  <div class="toast" id="toast"></div>

  <script>
    const API = window.location.origin;
    const grid = document.getElementById('grid');
    const toast = document.getElementById('toast');

    function showToast(msg, type) {
      toast.textContent = msg;
      toast.className = 'toast toast-' + type + ' show';
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    async function api(path, opts) {
      const res = await fetch(API + path, {
        headers: { 'Content-Type': 'application/json' },
        ...opts,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Request failed');
      }
      return res.json();
    }

    async function loadProviders() {
      try {
        const providers = await api('/api/providers');
        renderProviders(providers);
      } catch (e) {
        grid.innerHTML = '<div class="card"><p style="color:var(--danger)">Failed to load: ' + e.message + '</p></div>';
      }
    }

    function renderProviders(providers) {
      grid.innerHTML = providers.map(p => {
        const statusBadge = p.hasToken
          ? '<span class="badge badge-active">Authorized</span>'
          : '<span class="badge badge-inactive">No Token</span>';
        const oidcBadge = p.isOIDC ? ' <span class="badge badge-oidc">OIDC</span>' : '';
        const expiry = p.tokenExpiry
          ? '<span>Expires: ' + new Date(p.tokenExpiry).toLocaleString() + '</span>'
          : '';
        const scopes = p.scopes ? '<span>Scopes: ' + p.scopes + '</span>' : '';

        return '<div class="card" id="card-' + p.id + '">' +
          '<div class="card-header">' +
            '<h2>' + p.displayName + '</h2>' +
            '<div>' + statusBadge + oidcBadge + '</div>' +
          '</div>' +
          '<div class="meta">' + expiry + scopes + '</div>' +
          '<div class="actions">' +
            '<button class="primary" onclick="startAuth(\\'' + p.id + '\\')">🔗 Authorize</button>' +
            '<button onclick="startDeviceAuth(\\'' + p.id + '\\')">📱 Device Auth</button>' +
            (p.hasToken ? '<button onclick="refreshToken(\\'' + p.id + '\\')">🔄 Refresh</button>' : '') +
            (p.hasToken ? '<button class="danger" onclick="revokeToken(\\'' + p.id + '\\')">🗑 Revoke</button>' : '') +
          '</div>' +
          '<div id="device-' + p.id + '"></div>' +
        '</div>';
      }).join('');
    }

    window.startAuth = async function(providerId) {
      try {
        const data = await api('/api/providers/' + providerId + '/authorize', { method: 'POST' });
        // Open the auth URL in a new window/tab
        window.open(data.authUrl, '_blank');
        showToast('Authorization URL opened. Complete the flow in the new window.', 'success');
        // Poll for status
        pollAuthStatus(providerId);
      } catch (e) {
        showToast(e.message, 'error');
      }
    };

    async function pollAuthStatus(providerId) {
      for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 2000));
        try {
          const status = await api('/api/providers/' + providerId + '/status');
          if (status.hasToken) {
            showToast('Authorization complete!', 'success');
            loadProviders();
            return;
          }
        } catch {}
      }
      loadProviders();
    }

    window.startDeviceAuth = async function(providerId) {
      try {
        const data = await api('/api/providers/' + providerId + '/device-authorize', { method: 'POST' });
        const el = document.getElementById('device-' + providerId);
        const expiresIn = data.expires_in ? Math.round(data.expires_in / 60) : '?';
        el.innerHTML = '<div class="device-auth-box">' +
          '<p style="text-align:center;font-size:0.85rem;">Go to this URL on any device:</p>' +
          '<p class="uri">' + data.verification_uri + '</p>' +
          '<p style="text-align:center;font-size:0.85rem;margin-top:10px;">Enter this code:</p>' +
          '<p class="code">' + data.user_code + '</p>' +
          '<p class="expiry">Expires in ~' + expiresIn + ' minutes</p>' +
          '</div>';
        showToast('Device auth started. Enter the code on another device.', 'success');
        pollDeviceAuthStatus(providerId);
      } catch (e) {
        showToast(e.message, 'error');
      }
    };

    async function pollDeviceAuthStatus(providerId) {
      for (let i = 0; i < 120; i++) {
        await new Promise(r => setTimeout(r, 3000));
        try {
          const status = await api('/api/providers/' + providerId + '/device-auth-status');
          if (status.status === 'complete') {
            showToast('Device authorization complete!', 'success');
            loadProviders();
            return;
          }
          if (status.status === 'expired') {
            showToast('Device authorization expired.', 'error');
            loadProviders();
            return;
          }
        } catch {}
      }
      loadProviders();
    }

    window.refreshToken = async function(providerId) {
      try {
        await api('/api/providers/' + providerId + '/refresh', { method: 'POST' });
        showToast('Token refreshed!', 'success');
        loadProviders();
      } catch (e) {
        showToast(e.message, 'error');
      }
    };

    window.revokeToken = async function(providerId) {
      if (!confirm('Are you sure you want to revoke tokens for "' + providerId + '"?')) return;
      try {
        await api('/api/providers/' + providerId + '/token', { method: 'DELETE' });
        showToast('Tokens revoked.', 'success');
        loadProviders();
      } catch (e) {
        showToast(e.message, 'error');
      }
    };

    loadProviders();
  </script>
</body>
</html>`;
}
