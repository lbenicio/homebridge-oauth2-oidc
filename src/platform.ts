/**
 * Homebridge OAuth2/OIDC Platform Plugin
 *
 * Provides an OAuth2/OIDC authentication layer that other Homebridge
 * plugins can use to authenticate against identity providers.
 *
 * Other plugins access this platform via the Homebridge API:
 *   const oauth2 = api.getPlatform('OAuth2OIDC') as OAuth2OIDCPlatform;
 */

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
} from './types';
import { OAuth2Client } from './oauth2-client';
import { OIDCClient, fetchDiscoveryMetadata } from './oidc-client';
import { TokenStore } from './token-store';

type EventListener<T> = (payload: T) => void;

export class OAuth2OIDCPlatform implements IndependentPlatformPlugin {
  private readonly log: Logging;
  private readonly config: OAuth2PlatformConfig;
  private readonly api: API;
  private readonly tokenStore: TokenStore;

  private readonly clients = new Map<string, OAuth2Client | OIDCClient>();
  private readonly refreshTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly listeners = new Map<OAuth2PlatformEvent, Set<EventListener<unknown>>>();

  constructor(log: Logging, config: PlatformConfig, api: API) {
    this.log = log;
    this.api = api;
    this.config = config as unknown as OAuth2PlatformConfig;

    if (!this.config.providers?.length) {
      throw new Error('OAuth2OIDC platform requires a "providers" array in config');
    }

    this.tokenStore = new TokenStore(api.user.storagePath());

    this.initializeProviders().catch((err) => {
      this.log.error('Failed to initialize OAuth2/OIDC providers:', err.message);
    });

    this.log.info(`OAuth2OIDC platform initialized with ${this.config.providers.length} provider(s)`);
  }

  // ─── Provider Initialization ──────────────────────────────────────

  private async initializeProviders(): Promise<void> {
    for (const cfg of this.config.providers) {
      try {
        const client = await this.createClient(cfg);
        this.clients.set(cfg.id, client);

        const stored = await this.tokenStore.get(cfg.id);
        if (stored) {
          this.log.info(`Loaded stored tokens for "${cfg.id}"`);
          if (stored.refresh_token) {
            this.scheduleTokenRefresh(cfg.id, stored);
          }
        }
      } catch (err) {
        this.log.error(`Failed to initialize provider "${cfg.id}":`, (err as Error).message);
      }
    }
  }

  private async createClient(cfg: ProviderConfig): Promise<OAuth2Client | OIDCClient> {
    const redirectUri = 'http://localhost';

    if (cfg.discoveryUrl) {
      // Normalize: accept "false" string or boolean false
      const skipTLS = cfg.tlsRejectUnauthorized === false || (cfg.tlsRejectUnauthorized as unknown) === 'false';
      this.log.info(`Discovering OIDC metadata from ${cfg.discoveryUrl} (TLS verify: ${!skipTLS})`);
      try {
        const metadata = await fetchDiscoveryMetadata(cfg.discoveryUrl, !skipTLS);
        this.log.info(`OIDC discovery complete for "${cfg.id}" — issuer: ${metadata.issuer}`);
        return new OIDCClient(cfg, redirectUri, metadata);
      } catch (err) {
        this.log.error(`OIDC discovery failed for "${cfg.id}":`, (err as Error).message);
        throw err;
      }
    }

    if (!cfg.authorizationEndpoint || !cfg.tokenEndpoint) {
      throw new Error(
        `Provider "${cfg.id}": must provide discoveryUrl or both authorizationEndpoint and tokenEndpoint`
      );
    }

    return new OIDCClient(cfg, redirectUri, null);
  }

  // ─── Public API for Other Plugins ─────────────────────────────────

  getProviderIds(): string[] {
    return Array.from(this.clients.keys());
  }

  async getToken(providerId: string): Promise<TokenSet | null> {
    return this.tokenStore.get(providerId);
  }

  async authorize(providerId: string, params?: Partial<AuthorizationParams>): Promise<AuthorizationResult> {
    const client = this.getClient(providerId);
    const result = await client.authorize({ providerId, ...params });
    await this.tokenStore.set(providerId, result.tokenSet);
    this.emit('authorized', { providerId, tokenSet: result.tokenSet } as AuthorizedPayload);
    if (result.tokenSet.refresh_token) {
      this.scheduleTokenRefresh(providerId, result.tokenSet);
    }
    return result;
  }

  async clientCredentials(providerId: string, params?: Partial<ClientCredentialsParams>): Promise<AuthorizationResult> {
    const client = this.getClient(providerId);
    const result = await client.clientCredentials({ providerId, ...params });
    await this.tokenStore.set(providerId, result.tokenSet);
    this.emit('authorized', { providerId, tokenSet: result.tokenSet } as AuthorizedPayload);
    return result;
  }

  async startDeviceAuth(providerId: string, scopes?: string[], audience?: string): Promise<DeviceAuthResponse> {
    const client = this.getClient(providerId);
    const response = await client.startDeviceAuth(scopes, undefined, audience);
    this.log.info(
      `Device auth for "${providerId}": go to ${response.verification_uri} and enter code ${response.user_code}`
    );
    this.pollDeviceAuthInBackground(providerId, client, response.device_code);
    return response;
  }

  private async pollDeviceAuthInBackground(
    providerId: string,
    client: OAuth2Client | OIDCClient,
    deviceCode: string
  ): Promise<void> {
    try {
      const tokenSet = await client.pollDeviceAuth(deviceCode);
      await this.tokenStore.set(providerId, tokenSet);
      this.emit('authorized', { providerId, tokenSet } as AuthorizedPayload);
      if (tokenSet.refresh_token) {
        this.scheduleTokenRefresh(providerId, tokenSet);
      }
      this.log.info(`Device auth complete for "${providerId}"`);
    } catch (err) {
      this.log.error(`Device auth failed for "${providerId}":`, (err as Error).message);
      this.emit('error', { providerId, error: err as Error } as ErrorPayload);
    }
  }

  async refreshToken(providerId: string, refreshToken?: string): Promise<TokenSet> {
    const client = this.getClient(providerId);
    if (!refreshToken) {
      const stored = await this.tokenStore.get(providerId);
      if (!stored?.refresh_token) {
        throw new Error(`No refresh token available for "${providerId}"`);
      }
      refreshToken = stored.refresh_token;
    }
    const tokenSet = await client.refreshAccessToken({ providerId, refreshToken });
    await this.tokenStore.set(providerId, tokenSet);
    this.emit('token_refreshed', { providerId, tokenSet } as TokenRefreshedPayload);
    return tokenSet;
  }

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

  async fetchUserInfo(providerId: string): Promise<Record<string, unknown>> {
    const client = this.getClient(providerId);
    const tokenSet = await this.tokenStore.get(providerId);
    if (!tokenSet) throw new Error(`No tokens available for "${providerId}"`);
    return client.fetchUserInfo(tokenSet.access_token);
  }

  async getUserGroups(providerId: string): Promise<string[] | null> {
    const client = this.getClient(providerId);
    const tokenSet = await this.tokenStore.get(providerId);
    if (!tokenSet) throw new Error(`No tokens available for "${providerId}"`);
    return client.getUserGroups(tokenSet.access_token, tokenSet.id_token);
  }

  async isUserAuthorized(providerId: string): Promise<{ authorized: boolean; groups: string[] | null }> {
    const client = this.getClient(providerId);
    const tokenSet = await this.tokenStore.get(providerId);
    if (!tokenSet) throw new Error(`No tokens available for "${providerId}"`);
    return client.isUserAuthorized(tokenSet.access_token, tokenSet.id_token);
  }

  async validateIdToken(providerId: string, idToken: string): Promise<Record<string, unknown>> {
    const client = this.getClient(providerId);
    if (!(client instanceof OIDCClient)) {
      throw new Error(`Provider "${providerId}" is not an OIDC client`);
    }
    return client.validateIdToken(idToken);
  }

  // ─── Event System ─────────────────────────────────────────────────

  on(event: OAuth2PlatformEvent, listener: EventListener<unknown>): void {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event)!.add(listener);
  }

  off(event: OAuth2PlatformEvent, listener: EventListener<unknown>): void {
    this.listeners.get(event)?.delete(listener);
  }

  private emit(event: OAuth2PlatformEvent, payload: unknown): void {
    this.listeners.get(event)?.forEach((fn) => {
      try { fn(payload); } catch (err) {
        this.log.error(`Error in event listener for "${event}":`, (err as Error).message);
      }
    });
  }

  // ─── Token Refresh ────────────────────────────────────────────────

  private scheduleTokenRefresh(providerId: string, tokenSet: TokenSet): void {
    this.clearRefreshTimer(providerId);

    let delayMs: number;
    if (tokenSet.expires_at) {
      const expiresIn = tokenSet.expires_at - Date.now();
      delayMs = Math.max(expiresIn * 0.8, expiresIn - 30_000);
    } else {
      delayMs = 5 * 60_000;
    }

    delayMs = Math.max(delayMs, 10_000);

    const timer = setTimeout(async () => {
      try {
        this.log.info(`Proactively refreshing token for "${providerId}"`);
        await this.refreshToken(providerId);
      } catch (err) {
        this.log.error(`Failed to refresh token for "${providerId}":`, (err as Error).message);
        this.emit('error', { providerId, error: err as Error } as ErrorPayload);
      }
    }, delayMs);

    this.refreshTimers.set(providerId, timer);
  }

  private clearRefreshTimer(providerId: string): void {
    const timer = this.refreshTimers.get(providerId);
    if (timer) { clearTimeout(timer); this.refreshTimers.delete(providerId); }
  }

  // ─── Helpers ──────────────────────────────────────────────────────

  private getClient(providerId: string): OAuth2Client | OIDCClient {
    const client = this.clients.get(providerId);
    if (!client) throw new Error(`Provider "${providerId}" is not configured`);
    return client;
  }

  configureAccessory(): void {}
}
