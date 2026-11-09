import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const EMAIL =
  /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
}

export function isEmail(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 254 && EMAIL.test(value);
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function base64Url(bytes: Uint8Array | string): string {
  return Buffer.from(bytes).toString('base64url');
}

export function sha256(value: string | Uint8Array): Buffer {
  return createHash('sha256').update(value).digest();
}

export function sha256Hex(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

export function randomHex(bytes = 32): string {
  return randomBytes(bytes).toString('hex');
}

/** Constant-time string comparison (both sides are hashed first so the length does not leak). */
export function safeEqual(a: string, b: string): boolean {
  return timingSafeEqual(sha256(a), sha256(b)) && a === b;
}

export function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}

/**
 * PHP http_build_query(): nested objects and arrays become key[sub]=value, null and undefined are skipped,
 * booleans are 1/0 and spaces are encoded as "+".
 */
export function buildQuery(data: Record<string, unknown>): string {
  const params = new URLSearchParams();
  const add = (key: string, value: unknown): void => {
    if (value === null || value === undefined) {
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item, index) => add(`${key}[${index}]`, item));
    } else if (typeof value === 'object') {
      for (const [name, item] of Object.entries(value as Record<string, unknown>)) {
        add(`${key}[${name}]`, item);
      }
    } else if (typeof value === 'boolean') {
      params.append(key, value ? '1' : '0');
    } else {
      params.append(key, String(value));
    }
  };
  for (const [key, value] of Object.entries(data)) {
    add(key, value);
  }

  return params.toString();
}

/** A deep copy of JSON-like data. */
export function clone<T>(value: T): T {
  return value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T);
}

/**
 * Serialises async work per key inside this process (for example one refresh per session at a time).
 * Use a distributed lock in your SessionStore when you run several processes.
 */
export class KeyedLock {
  private readonly tails = new Map<string, Promise<unknown>>();

  async run<T>(key: string, task: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(key) ?? Promise.resolve();
    const result = previous.then(task, task);
    const tail = result.then(
      () => undefined,
      () => undefined,
    );
    this.tails.set(key, tail);
    try {
      return await result;
    } finally {
      if (this.tails.get(key) === tail) {
        this.tails.delete(key);
      }
    }
  }
}
