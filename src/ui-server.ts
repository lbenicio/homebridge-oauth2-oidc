/**
 * Homebridge Plugin UI Server
 *
 * This file is executed by homebridge-config-ui-x as a standalone process.
 * It bridges the browser UI (which uses homebridge.request()) to the
 * platform's management HTTP API.
 *
 * The management port is read from a well-known file written by the platform.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HomebridgePluginUiServer } from '@homebridge/plugin-ui-utils';

const PORT_FILE = 'homebridge-oauth2-oidc/.management-port';

class OAuth2OIDCUIServer extends HomebridgePluginUiServer {
  private managementBaseUrl: string | null = null;

  constructor() {
    super();

    // Discover the management API port
    this.discoverManagementPort().then(() => {
      this.registerHandlers();
      this.ready();
    }).catch((err) => {
      console.error('[OAuth2OIDC UI] Failed to start:', err.message);
      // Still call ready() so the UI doesn't hang
      this.ready();
    });
  }

  private async discoverManagementPort(): Promise<void> {
    const storagePath = this.homebridgeStoragePath;
    if (!storagePath) {
      throw new Error('Cannot determine Homebridge storage path');
    }

    const portFile = join(storagePath, PORT_FILE);
    const port = (await readFile(portFile, 'utf-8')).trim();
    this.managementBaseUrl = `http://127.0.0.1:${port}`;
    console.log(`[OAuth2OIDC UI] Connected to management API at ${this.managementBaseUrl}`);
  }

  private registerHandlers(): void {
    if (!this.managementBaseUrl) return;

    const baseUrl = this.managementBaseUrl;

    // GET /api/providers
    this.onRequest('/providers', async () => {
      const res = await fetch(`${baseUrl}/api/providers`);
      return res.json();
    });

    // GET /api/providers/:id/status
    this.onRequest('/status', async (payload: { providerId: string }) => {
      const res = await fetch(`${baseUrl}/api/providers/${payload.providerId}/status`);
      return res.json();
    });

    // GET /api/providers/:id/device-auth-status
    this.onRequest('/device-auth-status', async (payload: { providerId: string }) => {
      const res = await fetch(`${baseUrl}/api/providers/${payload.providerId}/device-auth-status`);
      return res.json();
    });

    // POST /api/providers/:id/authorize
    this.onRequest('/authorize', async (payload: { providerId: string; scopes?: string[] }) => {
      const res = await fetch(`${baseUrl}/api/providers/${payload.providerId}/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scopes: payload.scopes }),
      });
      return res.json();
    });

    // POST /api/providers/:id/device-authorize
    this.onRequest('/device-authorize', async (payload: { providerId: string; scopes?: string[] }) => {
      const res = await fetch(`${baseUrl}/api/providers/${payload.providerId}/device-authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scopes: payload.scopes }),
      });
      return res.json();
    });

    // POST /api/providers/:id/refresh
    this.onRequest('/refresh', async (payload: { providerId: string }) => {
      const res = await fetch(`${baseUrl}/api/providers/${payload.providerId}/refresh`, {
        method: 'POST',
      });
      return res.json();
    });

    // DELETE /api/providers/:id/token
    this.onRequest('/revoke', async (payload: { providerId: string }) => {
      const res = await fetch(`${baseUrl}/api/providers/${payload.providerId}/token`, {
        method: 'DELETE',
      });
      return res.json();
    });
  }
}

// Start the UI server
(() => {
  return new OAuth2OIDCUIServer();
})();
