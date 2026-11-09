import { isObject } from './util.js';

/** The subset of the global fetch the SDK uses. Pass your own (for example a mock) in BahariClient options. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** A buffered Bahari response. Header names are lower-case. */
export class HttpResponse {
  constructor(
    readonly status: number,
    readonly body: string,
    readonly headers: Readonly<Record<string, string>> = {},
  ) {}

  /** The parsed JSON body (or one top-level key of it), or null when the body is not JSON. */
  json(key?: string): unknown {
    let data: unknown;
    try {
      data = JSON.parse(this.body);
    } catch {
      return null;
    }
    if (key === undefined) {
      return data;
    }

    return isObject(data) && key in data ? data[key] : null;
  }

  header(name: string): string | null {
    return this.headers[name.toLowerCase()] ?? null;
  }

  get ok(): boolean {
    return this.status >= 200 && this.status < 300;
  }
}
