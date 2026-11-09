import { createPublicKey, verify as verifySignature } from 'node:crypto';
import { InvalidTokenError } from './errors.js';
import type { TokenClaims } from './types.js';
import { isObject, isUuid, safeEqual } from './util.js';

export const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/** Clock skew allowed for exp / iat / nbf. */
export const LEEWAY = 30;

export interface VerifierHost {
  readonly issuer: string;
  readonly clientId: string;
  jwks(fresh?: boolean): Promise<Record<string, unknown>>;
  now(): number;
}

export interface VerifyOptions {
  /** The nonce saved at beginLogin(). Compared in constant time. */
  nonce?: string | null;
  /** Back-channel logout token rules: jti, events, no nonce, issued within 5 minutes. */
  logout?: boolean;
}

/** A key or signature problem: the JWKS is fetched again once before the token is rejected. */
class KeyProblem extends Error {}

const SEGMENT = /^[A-Za-z0-9_-]+$/;

/**
 * Verifies RS256 ID and logout tokens against the issuer's JWKS (cached; refetched once when the key is unknown or
 * the signature does not match).
 */
export class TokenVerifier {
  constructor(private readonly host: VerifierHost) {}

  async verify(token: string, options: VerifyOptions = {}): Promise<TokenClaims> {
    const parts = typeof token === 'string' ? token.split('.') : [];
    const header = parts.length === 3 && parts.every((part) => SEGMENT.test(part)) ? decodeJson(parts[0]!) : null;
    if (!isObject(header) || header.alg !== 'RS256' || typeof header.kid !== 'string') {
      throw new InvalidTokenError('Invalid token algorithm.');
    }
    const kid = header.kid;
    let claims: Record<string, unknown>;
    try {
      claims = this.decode(parts as [string, string, string], await this.host.jwks(), kid);
    } catch (error) {
      if (error instanceof InvalidTokenError) {
        throw error;
      }
      try {
        claims = this.decode(parts as [string, string, string], await this.host.jwks(true), kid);
      } catch (retryError) {
        if (retryError instanceof InvalidTokenError) {
          throw retryError;
        }
        throw new InvalidTokenError('Invalid token signature.', { cause: retryError });
      }
    }

    const now = this.host.now();
    const audience = Array.isArray(claims.aud) ? claims.aud : claims.aud === undefined || claims.aud === null ? [] : [claims.aud];
    if (
      claims.iss !== this.host.issuer ||
      !audience.includes(this.host.clientId) ||
      !isUuid(claims.sub) ||
      typeof claims.exp !== 'number' ||
      typeof claims.iat !== 'number' ||
      claims.iat > now + LEEWAY
    ) {
      throw new InvalidTokenError('Invalid token claims.');
    }
    const nonce = options.nonce;
    if (nonce !== undefined && nonce !== null && (typeof claims.nonce !== 'string' || !safeEqual(nonce, claims.nonce))) {
      throw new InvalidTokenError('Invalid token nonce.');
    }
    if (options.logout) {
      const events = claims.events;
      if (
        claims.jti === undefined ||
        claims.jti === null ||
        (claims.nonce !== undefined && claims.nonce !== null) ||
        !isObject(events) ||
        !Object.prototype.hasOwnProperty.call(events, LOGOUT_EVENT) ||
        Math.abs(now - claims.iat) > 300
      ) {
        throw new InvalidTokenError('Invalid logout token.');
      }
    }

    return claims as TokenClaims;
  }

  private decode(parts: [string, string, string], jwks: Record<string, unknown>, kid: string): Record<string, unknown> {
    const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
    const jwk = keys.find((key) => isObject(key) && key.kid === kid);
    if (!isObject(jwk)) {
      throw new KeyProblem('Unknown signing key.');
    }
    if (jwk.kty !== 'RSA' || (jwk.alg !== undefined && jwk.alg !== 'RS256') || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
      throw new KeyProblem('The signing key is not an RS256 key.');
    }
    let valid = false;
    try {
      const key = createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' });
      valid = verifySignature('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], 'base64url'));
    } catch (error) {
      throw new KeyProblem('The signing key could not be used.', { cause: error });
    }
    if (!valid) {
      throw new KeyProblem('Signature verification failed.');
    }
    const claims = decodeJson(parts[1]);
    if (!isObject(claims)) {
      throw new InvalidTokenError('Invalid token payload.');
    }
    const now = this.host.now();
    if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || Math.floor(claims.nbf) > now + LEEWAY)) {
      throw new InvalidTokenError('The token is not valid yet.');
    }
    if (claims.nbf === undefined && typeof claims.iat === 'number' && Math.floor(claims.iat) > now + LEEWAY) {
      throw new InvalidTokenError('The token is not valid yet.');
    }
    if (claims.exp !== undefined && (typeof claims.exp !== 'number' || now - LEEWAY >= claims.exp)) {
      throw new InvalidTokenError('The token has expired.');
    }

    return claims;
  }
}

function decodeJson(segment: string): unknown {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}
