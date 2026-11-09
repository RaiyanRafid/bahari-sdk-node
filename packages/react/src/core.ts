/*
 * Framework-free browser helpers. They only call your app's own backend routes (default prefix /auth); the browser
 * never sees a client secret, an access token or a refresh token.
 */

export type Kind = 'client' | 'admin';

export interface BahariSession {
  kind: Kind;
  profile: {
    id: string;
    name?: string;
    email?: string;
    admin_access?: { platform: string; role: string; two_factor_ready: boolean } | null;
    [key: string]: unknown;
  };
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface RequestOptions {
  prefix?: string;
  kind?: Kind | null;
  fetch?: FetchLike;
}

export interface PinnedResult {
  ok: boolean;
  status: number;
  data: unknown;
}

const SECRET_KEY = /(?:^|_)(?:tokens?|secret)$/i;

export function normalizePrefix(prefix: string | null | undefined = '/auth'): string {
  const trimmed = String(prefix ?? '/auth').replace(/^\/+|\/+$/g, '');

  return trimmed === '' ? '' : `/${trimmed}`;
}

/** "/auth/login" (automatic: admins continue to the admin sign-in) or "/auth/{kind}/login", with return_to. */
export function loginHref(prefix?: string | null, kind?: Kind | null, returnTo?: string | null): string {
  const base = normalizePrefix(prefix);
  const path = kind ? `${base}/${kind}/login` : `${base}/login`;

  return returnTo ? `${path}?return_to=${encodeURIComponent(returnTo)}` : path;
}

/** "Create account": Bahari registration, then back into the app ({prefix}/register). */
export function registerHref(prefix?: string | null, returnTo?: string | null): string {
  const path = `${normalizePrefix(prefix)}/register`;

  return returnTo ? `${path}?return_to=${encodeURIComponent(returnTo)}` : path;
}

/** The form action for signing out (POST). */
export function logoutAction(prefix: string | null | undefined, kind: Kind): string {
  return `${normalizePrefix(prefix)}/${kind}/logout`;
}

export function sessionHref(prefix?: string | null, kind?: Kind | null): string {
  return `${normalizePrefix(prefix)}/session${kind ? `?kind=${kind}` : ''}`;
}

export function navigationHref(prefix?: string | null, kind?: Kind | null): string {
  return `${normalizePrefix(prefix)}/navigation${kind ? `?kind=${kind}` : ''}`;
}

/** The signed-in session from the app's backend, or null when signed out. Throws on other failures. */
export async function fetchSession(options: RequestOptions = {}): Promise<BahariSession | null> {
  const response = await resolveFetch(options.fetch)(sessionHref(options.prefix, options.kind), {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  if (response.status === 401) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Bahari session request failed (${response.status}).`);
  }
  const data = (await response.json()) as unknown;
  if (!isObject(data) || (data.kind !== 'client' && data.kind !== 'admin') || !isObject(data.profile) || typeof data.profile.id !== 'string') {
    throw new Error('Bahari session response is invalid.');
  }

  return { kind: data.kind, profile: stripSecrets(data.profile) as BahariSession['profile'] };
}

/** The platform switcher (data of GET {prefix}/navigation), or null when signed out. */
export async function fetchNavigation(options: RequestOptions = {}): Promise<Record<string, unknown> | null> {
  const response = await resolveFetch(options.fetch)(navigationHref(options.prefix, options.kind), {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  if (response.status === 401) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Bahari navigation request failed (${response.status}).`);
  }
  const data = (await response.json()) as unknown;

  return isObject(data) && isObject(data.data) ? data.data : {};
}

/** Saves the customer's pinned platforms. Validation errors (422) come back with ok false and Bahari's message. */
export async function savePinned(keys: string[], options: Omit<RequestOptions, 'kind'> = {}): Promise<PinnedResult> {
  const response = await resolveFetch(options.fetch)(navigationHref(options.prefix), {
    method: 'PUT',
    credentials: 'same-origin',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ pinned_keys: Array.from(keys) }),
  });
  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  return { ok: response.ok, status: response.status, data };
}

/** Removes token- and secret-like keys (defence in depth; the backend never sends them). */
export function stripSecrets(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stripSecrets);
  }
  if (isObject(value)) {
    const result: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      if (!SECRET_KEY.test(key)) {
        result[key] = stripSecrets(item);
      }
    }

    return result;
  }

  return value;
}

function resolveFetch(fetcher?: FetchLike): FetchLike {
  if (fetcher) {
    return fetcher;
  }
  if (typeof globalThis.fetch !== 'function') {
    throw new Error('fetch is not available.');
  }

  return (input, init) => globalThis.fetch(input, init);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
