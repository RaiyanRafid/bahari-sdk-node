/*
 * Pure helpers (no Node built-ins), safe for edge runtimes: import from "@bahari/node/return-path".
 */

const MAX_LENGTH = 2048;

/** "/dashboard/" -> "/dashboard", "" -> "/". */
export function normalizeAreaPath(path: string | null | undefined): string {
  return `/${String(path ?? '/').replace(/^\/+|\/+$/g, '')}`;
}

/**
 * A local return path inside an area (for example "/dashboard"), or the area itself. Blocks external URLs,
 * protocol-relative URLs, backslashes, control characters and traversal (also when percent-encoded).
 */
export function safeReturnPath(areaPath: string, value: unknown): string {
  const prefix = normalizeAreaPath(areaPath);
  if (typeof value !== 'string' || value === '' || utf8Length(value) > MAX_LENGTH) {
    return prefix;
  }
  const base = prefix.replace(/\/+$/, '');
  const inside = new RegExp(`^${escapeRegExp(base)}(?:[/?]|$)`);
  const decoded = rawUrlDecode(value);
  // eslint-disable-next-line no-control-regex
  if (!inside.test(value) || /[\\\x00-\x20\x7f]/.test(decoded) || decoded.includes('..') || value.startsWith('//')) {
    return prefix;
  }

  return value;
}

/** Which area a path belongs to: the first kind whose path is the request path or a parent of it. */
export function kindForPath<K extends string>(kinds: Partial<Record<K, { path?: string } | undefined>>, pathname: string, fallback: K): K {
  for (const [kind, settings] of Object.entries(kinds) as [K, { path?: string } | undefined][]) {
    const path = normalizeAreaPath(settings?.path ?? '/').replace(/^\//, '');
    if (path === '') {
      continue;
    }
    const target = pathname.replace(/^\/+/, '');
    if (target === path || target.startsWith(`${path}/`)) {
      return kind;
    }
  }

  return fallback;
}

/** PHP rawurldecode(): %XX sequences become the byte they name; invalid sequences stay as they are. */
function rawUrlDecode(value: string): string {
  return value.replace(/%([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\/~-]/g, '\\$&');
}
