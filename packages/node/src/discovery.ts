import type { Config } from './config.js';
import { BahariError } from './errors.js';
import { isObject } from './util.js';

export type DiscoveryDocument = Record<string, unknown>;

/**
 * The Bahari discovery document (/.well-known/bahari-configuration). Read values with dot paths:
 * get('admin.authorize_endpoint').
 */
export class Discovery {
  constructor(
    private readonly data: DiscoveryDocument,
    /** False when the defaults below are used because Bahari answered for another issuer or not at all. */
    readonly fromServer: boolean = true,
  ) {}

  /** Endpoints Bahari has always used, for when discovery cannot be reached and nothing is cached yet. */
  static fallback(config: Config): Discovery {
    const issuer = config.issuer;
    const admin = config.adminIssuer ?? issuer;
    const api = `${issuer}/api/v1`;

    return new Discovery(
      {
        issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        userinfo_endpoint: `${issuer}/oauth/userinfo`,
        profile_endpoint: `${issuer}/oauth/user`,
        jwks_uri: `${issuer}/oauth/jwks`,
        revocation_endpoint: `${issuer}/oauth/revoke`,
        end_session_endpoint: `${issuer}/oauth/logout`,
        client: {
          dashboard_url: `${issuer}/dashboard`,
          profile_url: `${issuer}/dashboard/personal-details`,
          security_url: `${issuer}/dashboard/security`,
          identity_url: `${issuer}/dashboard/identity-verification`,
          wallet_url: `${issuer}/dashboard/wallet`,
          billing_url: `${issuer}/dashboard/billing`,
          applications_url: `${issuer}/dashboard/applications`,
        },
        admin: {
          origin: admin,
          panel_url: `${admin}/admin`,
          billing_url: `${admin}/admin/billing`,
          profile_url: `${admin}/admin/profile`,
          authorize_endpoint: `${admin}/admin-sso/authorize`,
          exchange_endpoint: `${api}/admin-sso/exchange`,
          session_endpoint: `${api}/admin-sso/session`,
          revoke_endpoint: `${api}/admin-sso/revoke`,
          navigation_endpoint: `${api}/admin-sso/navigation`,
        },
        api: { base_url: api, platform_navigation: `${api}/platform-navigation`, platform_branding: `${api}/platform-branding/{key}` },
        sdk: { packages: {} },
      },
      false,
    );
  }

  get(path: string, fallback?: unknown): unknown {
    let value: unknown = this.data;
    for (const segment of path.split('.')) {
      if (!isObject(value) || !Object.prototype.hasOwnProperty.call(value, segment)) {
        return fallback;
      }
      value = value[segment];
    }

    return value;
  }

  /** A URL from the document. Throws when it is missing so a typo never sends a request to the wrong place. */
  url(path: string): string {
    const url = this.get(path);
    if (typeof url !== 'string' || !/^https?:\/\//.test(url)) {
      throw new BahariError(`Bahari discovery has no URL for '${path}'.`);
    }

    return url;
  }

  toJSON(): DiscoveryDocument {
    return this.data;
  }
}
