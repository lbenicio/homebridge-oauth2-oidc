/**
 * Local HTTP server for receiving OAuth2 authorization callbacks.
 * Spawns a lightweight HTTP server on a configurable port.
 */

import http from 'node:http';
import { URL } from 'node:url';

export interface CallbackResult {
  code: string;
  state: string | null;
}

/**
 * Starts a temporary HTTP server to listen for the OAuth2 redirect.
 * Returns a Promise that resolves with the authorization code and state.
 */
export function startCallbackServer(port: number, host: string, timeoutMs = 120_000): Promise<CallbackResult> {
  return new Promise<CallbackResult>((resolve, reject) => {
    const server = http.createServer((req, res) => {
      // Set CORS headers for development convenience
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET');

      const parsedUrl = new URL(req.url ?? '/', `http://${host}:${port}`);
      const code = parsedUrl.searchParams.get('code');
      const state = parsedUrl.searchParams.get('state');
      const error = parsedUrl.searchParams.get('error');
      const errorDescription = parsedUrl.searchParams.get('error_description');

      if (error) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(`<html><body><h1>Authorization Error</h1><p>${errorDescription ?? error}</p></body></html>`);
        server.close();
        reject(new Error(`Authorization error: ${error}${errorDescription ? ` - ${errorDescription}` : ''}`));
        return;
      }

      if (!code) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<html><body><h1>Missing Code</h1><p>No authorization code received.</p></body></html>');
        server.close();
        reject(new Error('No authorization code received in callback'));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body><h1>Authorization Successful</h1><p>You may close this window.</p></body></html>');
      server.close();
      resolve({ code, state });
    });

    // Set a timeout so we don't wait forever
    const timer = setTimeout(() => {
      server.close();
      reject(new Error(`Authorization callback timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    server.on('close', () => clearTimeout(timer));

    server.listen(port, host, () => {
      console.log(`[OAuth2OIDC] Callback server listening on http://${host}:${port}`);
    });

    server.on('error', (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      server.close();
      reject(new Error(`Failed to start callback server: ${err.message}`));
    });
  });
}

/**
 * Find an available port starting from the given port.
 * Returns a Promise resolving to an available port number.
 */
export function findAvailablePort(preferredPort?: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.listen(preferredPort ?? 0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close();
        reject(new Error('Could not determine port'));
        return;
      }
      const port = address.port;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}
