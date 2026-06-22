/**
 * Homebridge Plugin UI Server
 *
 * Self-contained UI backend. Reads the Homebridge config to get provider
 * settings, manages OAuth2/OIDC clients, and reads/writes the same token
 * files as the platform process. No separate management HTTP server needed.
 */

import { readFile } from 'node:fs/promises';
import { HomebridgePluginUiServer } from '@homebridge/plugin-ui-utils';
import type { ProviderConfig } from './types';
import { OAuth2Client } from './oauth2-client';
import { OIDCClient, fetchDiscoveryMetadata } from './oidc-client';
import { TokenStore } from './token-store';

interface ParsedConfig {
  platforms?: Array<{
    platform?: string;
    name?: string;
    providers?: ProviderConfig[];
  }>;
}

class OAuth2OIDCUIServer extends HomebridgePluginUiServer {
  private clients = new Map<string, OAuth2Client | OIDCClient>();
  private tokenStore!: TokenStore;
  private providers: ProviderConfig[] = [];

  // device_code → providerId for polling
  private deviceAuthMap = new Map<string, string>();

  // state → { providerId, verifier } for callback routing
  private pendingStates = new Map<string, { providerId: string; verifier?: string }>();

  constructor() {
    super();

    this.init().then(() => {
      this.registerHandlers();
      this.ready();
    }).catch((err) => {
      console.error('[OAuth2OIDC UI] Failed to start:', err.message);
      this.ready();
    });
  }

  private async init(): Promise<void> {
    const storagePath = this.homebridgeStoragePath;
    const configPath = this.homebridgeConfigPath;
    if (!storagePath || !configPath) {
      throw new Error('Cannot determine Homebridge paths');
    }

    // Parse the Homebridge config to find our platform configuration
    const raw = await readFile(configPath, 'utf-8');
    const config: ParsedConfig = JSON.parse(raw);

    const ourPlatform = config.platforms?.find(
      (p) => p.platform === 'OAuth2OIDC' || p.name === 'OAuth2OIDC'
    );
    if (!ourPlatform?.providers?.length) {
      throw new Error('No OAuth2OIDC platform configured, or no providers defined');
    }

    this.providers = ourPlatform.providers;
    this.tokenStore = new TokenStore(storagePath);

    // Initialize each provider
    for (const cfg of this.providers) {
      await this.initProvider(cfg);
    }

    console.log(`[OAuth2OIDC UI] Initialized with ${this.providers.length} provider(s)`);
  }

  private async initProvider(cfg: ProviderConfig): Promise<void> {
    try {
      let client: OAuth2Client | OIDCClient;
      const redirectUri = 'http://localhost';

      if (cfg.discoveryUrl) {
        const metadata = await fetchDiscoveryMetadata(
          cfg.discoveryUrl,
          cfg.tlsRejectUnauthorized ?? true
        );
        client = new OIDCClient(cfg, redirectUri, metadata);
      } else if (cfg.authorizationEndpoint && cfg.tokenEndpoint) {
        client = new OIDCClient(cfg, redirectUri, null);
      } else {
        console.error(`[OAuth2OIDC UI] Provider "${cfg.id}": no discoveryUrl or endpoints configured`);
        return;
      }

      this.clients.set(cfg.id, client);
    } catch (err) {
      console.error(`[OAuth2OIDC UI] Failed to initialize provider "${cfg.id}":`, (err as Error).message);
    }
  }

  private getClient(providerId: string): OAuth2Client | OIDCClient {
    const client = this.clients.get(providerId);
    if (!client) throw new Error(`Provider "${providerId}" not found`);
    return client;
  }

  // ─── Request Handlers ──────────────────────────────────────────────

  private registerHandlers(): void {
    this.onRequest('/providers', async () => this.handleProviders());
    this.onRequest('/status', async (p: { providerId: string }) => this.handleStatus(p.providerId));
    this.onRequest('/authorize', async (p: { providerId: string; scopes?: string[]; origin?: string }) => this.handleAuthorize(p.providerId, p.origin, p.scopes));
    this.onRequest('/device-authorize', async (p: { providerId: string; scopes?: string[] }) => this.handleDeviceAuth(p.providerId, p.scopes));
    this.onRequest('/device-auth-status', async (p: { providerId: string }) => this.handleDeviceAuthStatus(p.providerId));
    this.onRequest('/refresh', async (p: { providerId: string }) => this.handleRefresh(p.providerId));
    this.onRequest('/revoke', async (p: { providerId: string }) => this.handleRevoke(p.providerId));
    this.onRequest('/exchange-code', async (p: { code: string; state: string; origin?: string }) => this.handleExchangeCode(p.code, p.state, p.origin));
  }

  private async handleProviders(): Promise<unknown[]> {
    const result = [];
    for (const cfg of this.providers) {
      const client = this.clients.get(cfg.id);
      const token = await this.tokenStore.get(cfg.id);
      result.push({
        id: cfg.id,
        displayName: cfg.displayName,
        hasToken: token !== null,
        isOIDC: client instanceof OIDCClient && client.usesDiscovery,
        tokenExpiry: token?.expires_at,
        scopes: token?.scope,
      });
    }
    return result;
  }

  private async handleStatus(providerId: string): Promise<unknown> {
    const token = await this.tokenStore.get(providerId);
    return {
      hasToken: token !== null,
      expiresAt: token?.expires_at ?? null,
      scopes: token?.scope ?? null,
    };
  }

  private async handleAuthorize(providerId: string, origin?: string, scopes?: string[]): Promise<unknown> {
    const client = this.getClient(providerId);
    const state = Math.random().toString(36).substring(2, 15);
    const baseUrl = origin || 'http://localhost';
    const redirectUri = `${baseUrl}/plugin/homebridge-oauth2-oidc/callback/`;

    const { url, verifier } = await client.buildAuthorizationUrl({
      providerId,
      redirectUri,
      state,
      scopes,
    });

    this.pendingStates.set(state, { providerId, verifier });

    return { authUrl: url };
  }

  private async handleExchangeCode(code: string, state: string, origin?: string): Promise<unknown> {
    const pending = this.pendingStates.get(state);
    if (!pending) throw new Error('Unknown state — authorization may have expired');

    this.pendingStates.delete(state);

    const client = this.getClient(pending.providerId);
    const baseUrl = origin || 'http://localhost';
    const redirectUri = `${baseUrl}/plugin/homebridge-oauth2-oidc/callback/`;

    const tokenSet = await client.exchangeCodeForTokens(code, redirectUri, pending.verifier);
    await this.tokenStore.set(pending.providerId, tokenSet);

    return { success: true, providerId: pending.providerId };
  }

  private async handleDeviceAuth(providerId: string, scopes?: string[]): Promise<unknown> {
    const client = this.getClient(providerId);
    const response = await client.startDeviceAuth(scopes);

    // Start background polling
    this.deviceAuthMap.set(response.device_code, providerId);
    this.pollDeviceAuthBackground(providerId, client, response.device_code);

    return response;
  }

  private async pollDeviceAuthBackground(
    providerId: string,
    client: OAuth2Client | OIDCClient,
    deviceCode: string
  ): Promise<void> {
    try {
      const tokenSet = await client.pollDeviceAuth(deviceCode);
      await this.tokenStore.set(providerId, tokenSet);
      this.deviceAuthMap.delete(deviceCode);
      this.pushEvent('token-updated', { providerId });
    } catch (err) {
      this.deviceAuthMap.delete(deviceCode);
      console.error(`[OAuth2OIDC UI] Device auth failed for "${providerId}":`, (err as Error).message);
    }
  }

  private async handleDeviceAuthStatus(providerId: string): Promise<unknown> {
    const token = await this.tokenStore.get(providerId);
    if (token) return { status: 'complete' };

    // Check if any pending device auth for this provider
    for (const [code, pid] of this.deviceAuthMap) {
      if (pid === providerId) return { status: 'pending' };
    }
    return { status: 'none' };
  }

  private async handleRefresh(providerId: string): Promise<unknown> {
    const client = this.getClient(providerId);
    const stored = await this.tokenStore.get(providerId);
    if (!stored?.refresh_token) throw new Error('No refresh token available');

    const tokenSet = await client.refreshAccessToken({
      providerId,
      refreshToken: stored.refresh_token,
    });
    await this.tokenStore.set(providerId, tokenSet);

    return { success: true, expiresAt: tokenSet.expires_at, scopes: tokenSet.scope };
  }

  private async handleRevoke(providerId: string): Promise<unknown> {
    const stored = await this.tokenStore.get(providerId);
    if (stored) {
      const client = this.getClient(providerId);
      try {
        await client.revokeToken(stored.access_token, 'access_token');
        if (stored.refresh_token) {
          await client.revokeToken(stored.refresh_token, 'refresh_token');
        }
      } catch {
        // Best-effort
      }
    }
    await this.tokenStore.delete(providerId);
    return { success: true };
  }
}

// Start the UI server
(() => new OAuth2OIDCUIServer())();
