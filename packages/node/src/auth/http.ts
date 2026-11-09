import type { IncomingMessage, ServerResponse } from 'node:http';

/** A framework-neutral request. Build one from a Web Request (fromWebRequest) or a Node/Express request (fromNodeRequest). */
export interface AuthRequest {
  readonly method: string;
  readonly url: URL;
  header(name: string): string | null;
  /** The raw body. Rejects with PayloadTooLargeError when it is longer than limit bytes. */
  text(limit: number): Promise<string>;
}

/** A framework-neutral response. Convert with toWebResponse() or writeNodeResponse(). */
export interface AuthResult {
  status: number;
  headers: Record<string, string>;
  /** Set-Cookie header values. */
  cookies: string[];
  body: string;
}

export class PayloadTooLargeError extends Error {}

export function isAuthRequest(value: unknown): value is AuthRequest {
  return typeof value === 'object' && value !== null && (value as AuthRequest).url instanceof URL && typeof (value as AuthRequest).header === 'function';
}

export function fromWebRequest(request: Request): AuthRequest {
  const url = new URL(request.url);

  return {
    method: request.method.toUpperCase(),
    url,
    header: (name) => request.headers.get(name),
    text: async (limit) => {
      const length = Number(request.headers.get('content-length') ?? '0');
      if (length > limit) {
        throw new PayloadTooLargeError('Payload too large.');
      }
      const body = await request.text();
      if (Buffer.byteLength(body) > limit) {
        throw new PayloadTooLargeError('Payload too large.');
      }

      return body;
    },
  };
}

export function toWebResponse(result: AuthResult): Response {
  const headers = new Headers(result.headers);
  for (const cookie of result.cookies) {
    headers.append('Set-Cookie', cookie);
  }
  const empty = result.status === 204 || result.status === 304 || (result.status >= 300 && result.status < 400 && result.body === '');

  return new Response(empty ? null : result.body, { status: result.status, headers });
}

/** Express/Connect request: Express adds originalUrl, protocol and (with a body parser) body. */
export type NodeRequest = IncomingMessage & {
  originalUrl?: string;
  protocol?: string;
  body?: unknown;
  _body?: boolean;
};

export function fromNodeRequest(req: NodeRequest, baseUrl?: string | null): AuthRequest {
  const headers = req.headers;
  const header = (name: string): string | null => {
    const value = headers[name.toLowerCase()];
    if (value === undefined) {
      return null;
    }

    return Array.isArray(value) ? value.join(name.toLowerCase() === 'cookie' ? '; ' : ', ') : String(value);
  };
  const encrypted = Boolean((req.socket as { encrypted?: boolean } | undefined)?.encrypted);
  const origin = baseUrl ? new URL(baseUrl).origin : `${req.protocol ?? (encrypted ? 'https' : 'http')}://${header('host') ?? 'localhost'}`;
  const url = new URL(req.originalUrl ?? req.url ?? '/', origin);

  return {
    method: (req.method ?? 'GET').toUpperCase(),
    url,
    header,
    text: async (limit) => {
      if (req._body === true || req.readableEnded) {
        return serializeParsedBody(req.body, header('content-type'), limit);
      }
      const length = Number(header('content-length') ?? '0');
      if (length > limit) {
        throw new PayloadTooLargeError('Payload too large.');
      }
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
        size += buffer.length;
        if (size > limit) {
          throw new PayloadTooLargeError('Payload too large.');
        }
        chunks.push(buffer);
      }

      return Buffer.concat(chunks).toString('utf8');
    },
  };
}

function serializeParsedBody(body: unknown, contentType: string | null, limit: number): string {
  let text = '';
  if (typeof body === 'string') {
    text = body;
  } else if (Buffer.isBuffer(body)) {
    text = body.toString('utf8');
  } else if (typeof body === 'object' && body !== null) {
    if ((contentType ?? '').includes('json')) {
      text = JSON.stringify(body);
    } else {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
          params.append(key, String(value));
        }
      }
      text = params.toString();
    }
  }
  if (Buffer.byteLength(text) > limit) {
    throw new PayloadTooLargeError('Payload too large.');
  }

  return text;
}

export function writeNodeResponse(res: ServerResponse, result: AuthResult): void {
  res.statusCode = result.status;
  for (const [name, value] of Object.entries(result.headers)) {
    res.setHeader(name, value);
  }
  if (result.cookies.length > 0) {
    const existing = res.getHeader('set-cookie');
    const previous = existing === undefined ? [] : Array.isArray(existing) ? existing : [String(existing)];
    res.setHeader('Set-Cookie', [...previous, ...result.cookies]);
  }
  res.end(result.body);
}

export function redirect(location: string, status = 302, headers: Record<string, string> = {}, cookies: string[] = []): AuthResult {
  return { status, headers: { Location: location, 'Cache-Control': 'private, no-store', ...headers }, cookies, body: '' };
}

export function json(status: number, data: unknown, headers: Record<string, string> = {}, cookies: string[] = []): AuthResult {
  return {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers },
    cookies,
    body: JSON.stringify(data),
  };
}

export function text(status: number, message: string, headers: Record<string, string> = {}, cookies: string[] = []): AuthResult {
  return {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers },
    cookies,
    body: message,
  };
}

/** Like Laravel's expectsJson(): XHR/fetch callers asking for JSON get 401 instead of a redirect. */
export function expectsJson(request: AuthRequest): boolean {
  const accept = (request.header('accept') ?? '').toLowerCase();
  const xhr = (request.header('x-requested-with') ?? '').toLowerCase() === 'xmlhttprequest';

  return xhr || ((accept.includes('/json') || accept.includes('+json')) && !accept.startsWith('text/html'));
}
