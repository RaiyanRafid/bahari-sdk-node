import type { HttpResponse } from './http.js';

/** Base error: Bahari could not be reached or answered unexpectedly. */
export class BahariError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
  }
}

/** Bahari answered with a non-2xx status. The response is kept for inspection (status, body, headers). */
export class HttpError extends BahariError {
  readonly response: HttpResponse;

  readonly status: number;

  constructor(response: HttpResponse, url: string, options?: { cause?: unknown }) {
    let path = url;
    try {
      path = new URL(url).pathname;
    } catch {
      // keep the raw value
    }
    super(`Bahari Accounts answered ${response.status} for ${path}.`, options);
    this.response = response;
    this.status = response.status;
  }
}

/** A token failed signature, issuer, audience, nonce or lifetime checks. */
export class InvalidTokenError extends BahariError {}

/**
 * The account or admin session is no longer allowed (revoked, suspended, role removed, identity changed).
 * End the local session.
 */
export class AccessDeniedError extends BahariError {}
