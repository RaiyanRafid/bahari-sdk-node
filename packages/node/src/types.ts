/** "client" signs in customers (OIDC + PKCE). "admin" signs in platform administrators (Bahari admin SSO). */
export type Kind = 'client' | 'admin';

export const KINDS: readonly Kind[] = ['client', 'admin'];

/** Present on a customer profile when the account is linked to an administrator of this app's platform. */
export interface AdminAccess {
  platform: string;
  role: 'ADMIN' | 'SUPER_ADMIN';
  two_factor_ready: boolean;
  [key: string]: unknown;
}

/** A Bahari profile. Customer profiles come from profile_endpoint; admin profiles from the admin exchange/session. */
export interface BahariProfile {
  id: string;
  name: string;
  email: string;
  status?: string;
  customer?: { id: string; [key: string]: unknown };
  /** Customer profiles: the administrator access linked to this account for this platform, or null. */
  admin_access?: AdminAccess | null;
  /** Admin profiles. */
  platform?: string;
  role?: string;
  /** Admin profiles: the linked Bahari customer user id, or null. */
  user_id?: string | null;
  [key: string]: unknown;
}

/** Server-side secrets. Never send them to the browser; store them encrypted. */
export interface Tokens {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  token_type?: string;
  session_token?: string;
  [key: string]: unknown;
}

/**
 * A signed-in Bahari identity. tokens must be stored encrypted on the server. accessExpiresIn is in seconds
 * (client sessions only).
 */
export interface Identity {
  kind: Kind;
  subject: string;
  tokens: Tokens;
  profile: BahariProfile;
  accessExpiresIn: number | null;
  tokensChanged: boolean;
}

/** What beginLogin() returns. Keep transaction in the server-side session under state; redirect the browser to url. */
export interface LoginRequest {
  url: string;
  state: string;
  transaction: LoginTransaction;
}

export interface LoginTransaction {
  kind: Kind;
  nonce: string;
  verifier: string;
  redirectUri: string;
  /** Unix seconds. */
  createdAt: number;
}

export interface TokenClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nonce?: string;
  jti?: string;
  sid?: string;
  events?: Record<string, unknown>;
  [key: string]: unknown;
}

export type SdkStatus = 'ok' | 'outdated' | 'unsupported' | 'unknown' | (string & {});

export interface Logger {
  warn(message: string, context?: Record<string, unknown>): void;
  info?(message: string, context?: Record<string, unknown>): void;
}
