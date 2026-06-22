/**
 * Homebridge OAuth2 / OIDC Platform Plugin — Entry Point
 *
 * Registers the platform with Homebridge so it can be configured
 * via config.json or the Homebridge UI.
 */

import type { API } from 'homebridge';
import { OAuth2OIDCPlatform } from './platform';

const PLATFORM_NAME = 'OAuth2OIDC';
const PLUGIN_NAME = 'homebridge-oauth2-oidc';

export default function main(api: API): void {
  api.registerPlatform(PLUGIN_NAME, PLATFORM_NAME, OAuth2OIDCPlatform);
}

// Re-export types for consumers (other plugins)
export type {
  OAuth2PlatformConfig,
  ProviderConfig,
  TokenSet,
  AuthorizationParams,
  AuthorizationResult,
  ClientCredentialsParams,
  RefreshTokenParams,
  OAuth2PlatformEvent,
  TokenRefreshedPayload,
  AuthorizedPayload,
  ErrorPayload,
  OIDCDiscoveryMetadata,
  DeviceAuthResponse,
  DeviceAuthPollResult,
  ProviderInfo,
  AuthStatus,
} from './types';

export { OAuth2OIDCPlatform } from './platform';
export { OAuth2Client } from './oauth2-client';
export { OIDCClient, fetchDiscoveryMetadata } from './oidc-client';
export { TokenStore } from './token-store';
export { TokenEncryption } from './token-encryption';
