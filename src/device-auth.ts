/**
 * Device Authorization Grant (RFC 8628) implementation.
 *
 * This flow is designed for devices with limited input capabilities
 * (like a headless Homebridge server). Instead of requiring a local
 * browser to handle callbacks, it:
 *
 * 1. Requests a device code from the authorization server
 * 2. Returns a user_code + verification_uri for the user
 * 3. The user visits the URL on any device and enters the code
 * 4. We poll the token endpoint until authorization is complete
 */

import type {
  ProviderConfig,
  TokenSet,
  DeviceAuthResponse,
  DeviceAuthPollResult,
} from './types';
import { fetchWithTLS } from './tls-fetch';

const DEFAULT_POLL_INTERVAL = 5_000;
const DEFAULT_TIMEOUT = 600_000;

/**
 * Request a device authorization code from the provider.
 */
export async function requestDeviceCode(
  config: Pick<ProviderConfig, 'clientId' | 'clientSecret' | 'scopes' | 'tlsRejectUnauthorized'>,
  deviceEndpoint: string,
  audience?: string
): Promise<DeviceAuthResponse> {
  const body = new URLSearchParams({
    client_id: config.clientId,
    scope: config.scopes || 'openid profile email',
  });

  if (audience) {
    body.set('audience', audience);
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  };

  if (config.clientSecret) {
    const credentials = Buffer.from(
      `${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`
    ).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetchWithTLS(deviceEndpoint, {
    method: 'POST',
    headers,
    body: body.toString(),
  }, config.tlsRejectUnauthorized ?? true);

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Device authorization request failed: ${response.status} ${text}`);
  }

  const data = (await response.json()) as Record<string, unknown>;

  return {
    device_code: data.device_code as string,
    user_code: data.user_code as string,
    verification_uri: data.verification_uri as string,
    verification_uri_complete: data.verification_uri_complete as string | undefined,
    expires_in: data.expires_in as number,
    interval: (data.interval as number) || 5,
  };
}

/**
 * Poll the token endpoint with the device code until authorization
 * is complete, the code expires, or the timeout is reached.
 */
export async function pollDeviceToken(
  deviceCode: string,
  clientId: string,
  clientSecret: string | undefined,
  tokenEndpoint: string,
  options?: {
    interval?: number;
    timeoutMs?: number;
    onStatus?: (status: DeviceAuthPollResult) => void;
    tlsRejectUnauthorized?: boolean;
  }
): Promise<TokenSet> {
  const interval = options?.interval ?? DEFAULT_POLL_INTERVAL;
  const timeoutMs = options?.timeoutMs ?? DEFAULT_TIMEOUT;
  const tlsRejectUnauthorized = options?.tlsRejectUnauthorized ?? true;
  const startTime = Date.now();

  while (Date.now() - startTime < timeoutMs) {
    const result = await pollOnce(deviceCode, clientId, clientSecret, tokenEndpoint, tlsRejectUnauthorized);

    options?.onStatus?.(result);

    if (result.status === 'success') {
      return result.tokenSet!;
    }

    if (result.status === 'error' && result.error !== 'authorization_pending' && result.error !== 'slow_down') {
      throw new Error(`Device authorization failed: ${result.error} — ${result.errorDescription ?? ''}`);
    }

    const delay = result.error === 'slow_down' ? interval * 2 : interval;
    await sleep(delay);
  }

  throw new Error('Device authorization timed out');
}

async function pollOnce(
  deviceCode: string,
  clientId: string,
  clientSecret: string | undefined,
  tokenEndpoint: string,
  tlsRejectUnauthorized = true
): Promise<DeviceAuthPollResult> {
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    device_code: deviceCode,
    client_id: clientId,
  });

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  };

  if (clientSecret) {
    const credentials = Buffer.from(
      `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`
    ).toString('base64');
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetchWithTLS(tokenEndpoint, {
    method: 'POST',
    headers,
    body: body.toString(),
  }, tlsRejectUnauthorized);

  const data = (await response.json()) as Record<string, unknown>;

  if (response.ok) {
    const tokenSet: TokenSet = {
      access_token: data.access_token as string,
      refresh_token: data.refresh_token as string | undefined,
      id_token: data.id_token as string | undefined,
      token_type: (data.token_type as string) ?? 'Bearer',
      scope: data.scope as string | undefined,
    };

    if (typeof data.expires_in === 'number') {
      tokenSet.expires_in = data.expires_in;
      tokenSet.expires_at = Date.now() + data.expires_in * 1000;
    }

    return { status: 'success', tokenSet };
  }

  return {
    status: 'pending',
    error: data.error as string,
    errorDescription: data.error_description as string | undefined,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
