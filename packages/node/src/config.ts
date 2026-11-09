export const DEFAULT_ISSUER = 'https://accounts.baharione.com';

export const DEFAULT_SCOPES = 'openid profile email phone profile:read identity:read wallet:read platform:read';

export interface BahariConfigInput {
  /** The permanent Bahari issuer, for example https://accounts.baharione.com. Must be https (http only for localhost). */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** This app's platform key in Bahari. Required for admin sign-in and wallet links. */
  platform?: string | null;
  scopes?: string;
  /** Only used while discovery is unreachable and nothing is cached. */
  adminIssuer?: string | null;
  /** Seconds the discovery document is cached. Default 300. */
  discoveryTtl?: number;
}

/**
 * The only settings an app needs. Everything else (endpoints, the admin host, API URLs) comes from discovery.
 */
export class Config {
  readonly issuer: string;

  readonly clientId: string;

  readonly clientSecret: string;

  readonly platform: string | null;

  readonly scopes: string;

  readonly adminIssuer: string | null;

  readonly discoveryTtl: number;

  constructor(input: BahariConfigInput) {
    this.issuer = Config.origin(String(input.issuer ?? ''), 'issuer');
    this.clientId = String(input.clientId ?? '');
    this.clientSecret = String(input.clientSecret ?? '');
    this.platform = input.platform ? String(input.platform) : null;
    this.scopes = input.scopes ? String(input.scopes) : DEFAULT_SCOPES;
    this.adminIssuer = input.adminIssuer ? Config.origin(String(input.adminIssuer), 'admin issuer') : null;
    this.discoveryTtl = Math.max(1, Math.trunc(Number(input.discoveryTtl ?? 300)) || 300);
  }

  /**
   * Reads BAHARI_ACCOUNTS_ISSUER (default https://accounts.baharione.com), BAHARI_CLIENT_ID, BAHARI_CLIENT_SECRET,
   * BAHARI_PLATFORM_KEY and the optional BAHARI_SCOPES and BAHARI_ADMIN_ISSUER.
   */
  static fromEnv(env: Record<string, string | undefined> = process.env, overrides: Partial<BahariConfigInput> = {}): Config {
    return new Config({
      issuer: env.BAHARI_ACCOUNTS_ISSUER || DEFAULT_ISSUER,
      clientId: env.BAHARI_CLIENT_ID ?? '',
      clientSecret: env.BAHARI_CLIENT_SECRET ?? '',
      platform: env.BAHARI_PLATFORM_KEY || null,
      scopes: env.BAHARI_SCOPES || DEFAULT_SCOPES,
      adminIssuer: env.BAHARI_ADMIN_ISSUER || null,
      ...overrides,
    });
  }

  /** True once the client ID and secret are set. */
  configured(): boolean {
    return this.clientId !== '' && this.clientSecret !== '';
  }

  private static origin(value: string, name: string): string {
    const url = value.trim().replace(/\/+$/, '');
    const error = new TypeError(`The Bahari ${name} must be an https URL such as https://accounts.baharione.com.`);
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw error;
    }
    const host = parsed.hostname.replace(/^\[|\]$/g, '');
    const local = ['localhost', '127.0.0.1', '::1'].includes(host);
    const scheme = parsed.protocol;
    if (
      host === '' ||
      !(scheme === 'https:' || (scheme === 'http:' && local)) ||
      parsed.username !== '' ||
      parsed.password !== '' ||
      url.includes('?') ||
      url.includes('#') ||
      !/^https?:\/\//i.test(url)
    ) {
      throw error;
    }

    return url;
  }
}
