/**
 * Core type definitions for the homebridge-oauth2-oidc plugin.
 */

/** Provider configuration as defined in config.schema.json */
export interface ProviderConfig {
  id: string;
  displayName: string;
  discoveryUrl?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userInfoEndpoint?: string;
  clientId: string;
  clientSecret?: string;
  scopes: string;
  redirectPort?: number;
  pkce: boolean;
}

/** Full platform configuration */
export interface OAuth2PlatformConfig {
  name: string;
  providers: ProviderConfig[];
  callbackHost: string;
  tokenRefreshInterval: number;
  encryptionSecret?: string;
  managementPort?: number;
}

/** OIDC Discovery metadata (subset) */
export interface OIDCDiscoveryMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
  [key: string]: unknown;
}

/** Represents an OAuth2 token set */
export interface TokenSet {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_at?: number;
  expires_in?: number;
  scope?: string;
}

/** Supported OAuth2 grant types */
export type GrantType = 'authorization_code' | 'client_credentials' | 'refresh_token';

/** Parameters for initiating the authorization code flow */
export interface AuthorizationParams {
  providerId: string;
  scopes?: string[];
  state?: string;
  redirectUri?: string;
  /** Additional parameters to include in the authorization request */
  extraParams?: Record<string, string>;
}

/** Result returned after a successful authorization code grant */
export interface AuthorizationResult {
  providerId: string;
  tokenSet: TokenSet;
  /** Claims from the ID token or UserInfo endpoint, if available */
  claims?: Record<string, unknown>;
}

/** Parameters for the client credentials grant */
export interface ClientCredentialsParams {
  providerId: string;
  scopes?: string[];
  extraParams?: Record<string, string>;
}

/** Parameters for a token refresh */
export interface RefreshTokenParams {
  providerId: string;
  refreshToken: string;
}

/** Events emitted by the platform plugin */
export type OAuth2PlatformEvent =
  | 'token_refreshed'
  | 'token_revoked'
  | 'authorized'
  | 'error';

export interface TokenRefreshedPayload {
  providerId: string;
  tokenSet: TokenSet;
}

export interface AuthorizedPayload {
  providerId: string;
  tokenSet: TokenSet;
}

export interface ErrorPayload {
  providerId: string;
  error: Error;
}

// ─── Device Authorization Grant (RFC 8628) ──────────────────────

/** Parameters for initiating device authorization */
export interface DeviceAuthRequest {
  providerId: string;
  scopes?: string[];
  audience?: string;
}

/** Response from the device authorization endpoint */
export interface DeviceAuthResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

/** Result of a single poll attempt */
export interface DeviceAuthPollResult {
  status: 'success' | 'pending' | 'error';
  tokenSet?: TokenSet;
  error?: string;
  errorDescription?: string;
}

// ─── Management API Types ────────────────────────────────────────

/** Safe provider info returned by the management API (no secrets) */
export interface ProviderInfo {
  id: string;
  displayName: string;
  hasToken: boolean;
  isOIDC: boolean;
  tokenExpiry?: number;
  scopes?: string;
}

/** Response for auth status polling */
export interface AuthStatus {
  status: 'pending' | 'complete' | 'error';
  error?: string;
}
