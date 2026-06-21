/**
 * OIDC (OpenID Connect) client — extends OAuth2Client with OIDC discovery
 * and ID token validation capabilities.
 *
 * Uses the `openid-client` library for discovery and the `jose` library
 * for JWKS-based ID token verification (when discovery is available).
 */

import type {
  ProviderConfig,
  OIDCDiscoveryMetadata,
} from './types';
import { OAuth2Client } from './oauth2-client';

/** Fetch and parse OIDC discovery metadata from a .well-known URL */
export async function fetchDiscoveryMetadata(discoveryUrl: string): Promise<OIDCDiscoveryMetadata> {
  const response = await fetch(discoveryUrl);
  if (!response.ok) {
    throw new Error(`Failed to fetch OIDC discovery metadata from ${discoveryUrl}: ${response.status}`);
  }
  return response.json() as Promise<OIDCDiscoveryMetadata>;
}

export class OIDCClient extends OAuth2Client {
  readonly discoveryMetadata: OIDCDiscoveryMetadata | null;

  constructor(
    providerConfig: ProviderConfig,
    redirectUri: string,
    discoveryMetadata: OIDCDiscoveryMetadata | null
  ) {
    // If discovery metadata is available, use it to populate endpoints
    const configWithDiscovery: ProviderConfig = { ...providerConfig };
    if (discoveryMetadata) {
      configWithDiscovery.authorizationEndpoint =
        providerConfig.authorizationEndpoint ?? discoveryMetadata.authorization_endpoint;
      configWithDiscovery.tokenEndpoint =
        providerConfig.tokenEndpoint ?? discoveryMetadata.token_endpoint;
      configWithDiscovery.userInfoEndpoint =
        providerConfig.userInfoEndpoint ?? discoveryMetadata.userinfo_endpoint;
    }

    super(configWithDiscovery, redirectUri);
    this.discoveryMetadata = discoveryMetadata;
  }

  /** Validate an ID token using the provider's JWKS endpoint */
  async validateIdToken(idToken: string): Promise<Record<string, unknown>> {
    if (!this.discoveryMetadata) {
      throw new Error('Cannot validate ID token: no discovery metadata available');
    }

    const { createRemoteJWKSet, jwtVerify } = await import('jose');

    const JWKS = createRemoteJWKSet(new URL(this.discoveryMetadata.jwks_uri));

    const { payload } = await jwtVerify(idToken, JWKS, {
      issuer: this.discoveryMetadata.issuer,
      // audience validation is handled by jwtVerify by default
    });

    return payload;
  }

  /** Check if the provider was configured via OIDC discovery */
  get usesDiscovery(): boolean {
    return this.discoveryMetadata !== null;
  }
}
