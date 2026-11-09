/*
 * Edge-safe: no Node built-ins. Import from "@bahari/nextjs/middleware" in middleware.ts (or proxy.ts).
 */
import { kindForPath, normalizeAreaPath } from '@bahari/node/return-path';

type Kind = 'client' | 'admin';

export interface BahariMiddlewareOptions {
  /** Route prefix of the Bahari handlers. Default "/auth". */
  prefix?: string;
  /** Protected areas. Default { client: { path: '/dashboard' }, admin: { path: '/admin' } }. */
  kinds?: Partial<Record<Kind, { path: string }>>;
  /** Default "bahari_sid". */
  cookieName?: string;
}

const SID = /^[A-Za-z0-9_-]{43}$/;

/**
 * A fast gate for protected paths: requests without a Bahari session cookie are sent to the sign-in (API callers
 * asking for JSON get 401). It does not check the session with Bahari; server components and route handlers do that
 * with getSession()/authenticate(). Returns undefined when the request may continue.
 */
export function createBahariMiddleware(options: BahariMiddlewareOptions = {}): (request: Request) => Response | undefined {
  const prefix = normalizeAreaPath(options.prefix ?? '/auth');
  const kinds = options.kinds ?? { client: { path: '/dashboard' }, admin: { path: '/admin' } };
  const cookieName = options.cookieName ?? 'bahari_sid';

  return (request) => {
    const url = new URL(request.url);
    if (url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)) {
      return undefined;
    }
    const kind = kindForPath<Kind | 'none'>(kinds, url.pathname, 'none');
    if (kind === 'none') {
      return undefined;
    }
    const sid = readCookie(request.headers.get('cookie'), cookieName);
    if (sid && SID.test(sid)) {
      return undefined;
    }
    const accept = (request.headers.get('accept') ?? '').toLowerCase();
    if ((accept.includes('/json') || accept.includes('+json')) && !accept.startsWith('text/html')) {
      return new Response(JSON.stringify({ message: 'Bahari sign-in is required.' }), {
        status: 401,
        headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
      });
    }
    const login = new URL(`${prefix}/${kind}/login`, url);
    login.searchParams.set('return_to', url.pathname + url.search);

    return new Response(null, { status: 307, headers: { location: login.toString(), 'cache-control': 'no-store' } });
  };
}

/**
 * Ready-made gate with the default options:
 *
 *   export function middleware(request) { return bahariMiddleware(request) ?? NextResponse.next(); }
 */
export function bahariMiddleware(request: Request, options?: BahariMiddlewareOptions): Response | undefined {
  return createBahariMiddleware(options)(request);
}

function readCookie(header: string | null, name: string): string | null {
  for (const part of (header ?? '').split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }

  return null;
}
