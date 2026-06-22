/**
 * Core type definitions for the homebridge-oauth2-oidc plugin.
 */

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
  pkce: boolean;
  tlsRejectUnauthorized?: boolean;
  allowedGroups?: string[];
  groupsClaim?: string;
}

export interface OAuth2PlatformConfig {
  name: string;
  providers: ProviderConfig[];
}

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

export interface TokenSet {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_at?: number;
  expires_in?: number;
  scope?: string;
}

export type GrantType = 'authorization_code' | 'client_credentials' | 'refresh_token';

export interface AuthorizationParams {
  providerId: string;
  scopes?: string[];
  state?: string;
  redirectUri?: string;
  extraParams?: Record<string, string>;
}

export interface AuthorizationResult {
  providerId: string;
  tokenSet: TokenSet;
  claims?: Record<string, unknown>;
}

export interface ClientCredentialsParams {
  providerId: string;
  scopes?: string[];
  extraParams?: Record<string, string>;
}

export interface RefreshTokenParams {
  providerId: string;
  refreshToken: string;
}

export type OAuth2PlatformEvent = 'token_refreshed' | 'token_revoked' | 'authorized' | 'error';

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

export interface DeviceAuthResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

export interface DeviceAuthPollResult {
  status: 'success' | 'pending' | 'error';
  tokenSet?: TokenSet;
  error?: string;
  errorDescription?: string;
}

export interface ProviderInfo {
  id: string;
  displayName: string;
  hasToken: boolean;
  isOIDC: boolean;
  tokenExpiry?: number;
  scopes?: string;
}

export interface AuthStatus {
  status: 'pending' | 'complete' | 'error';
  error?: string;
}
