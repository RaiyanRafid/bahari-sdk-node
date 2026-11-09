import { clone } from './util.js';

type MaybePromise<T> = T | Promise<T>;

/**
 * A small key/value cache. Values are JSON-serialisable. Pass a shared implementation (Redis, Memcached, ...) when
 * the app runs in several processes so discovery, JWKS, machine tokens and logout de-duplication are shared.
 */
export interface BahariCache {
  get(key: string): MaybePromise<unknown>;
  /** ttlSeconds undefined means "no expiry". */
  set(key: string, value: unknown, ttlSeconds?: number): MaybePromise<void>;
  delete(key: string): MaybePromise<void>;
}

/** In-process cache for development, tests and single-process apps. */
export class MemoryCache implements BahariCache {
  private readonly items = new Map<string, { value: unknown; expiresAt: number | null }>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  get(key: string): unknown {
    const item = this.items.get(key);
    if (!item) {
      return undefined;
    }
    if (item.expiresAt !== null && item.expiresAt <= this.now()) {
      this.items.delete(key);

      return undefined;
    }

    return clone(item.value);
  }

  set(key: string, value: unknown, ttlSeconds?: number): void {
    this.items.set(key, { value: clone(value), expiresAt: ttlSeconds === undefined ? null : this.now() + ttlSeconds * 1000 });
  }

  delete(key: string): void {
    this.items.delete(key);
  }

  clear(): void {
    this.items.clear();
  }

  get size(): number {
    return this.items.size;
  }
}
