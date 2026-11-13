import { randomUUID } from 'node:crypto';
import type { BahariProfile, Kind, Tokens } from '../types.js';
import { clone, unixNow } from '../util.js';

/** A Bahari session saved by the app. Lives on the server only; tokens must be stored encrypted at rest. */
export interface StoredSession {
  id: string;
  kind: Kind;
  subject: string;
  tokens: Tokens;
  profile: BahariProfile;
  /** Unix seconds when the client access token expires (null for admin sessions). */
  accessExpiresAt: number | null;
  /** Unix seconds: the absolute end of the local session. */
  expiresAt: number;
  createdAt: number;
  revokedAt: number | null;
}

export type NewSession = Omit<StoredSession, 'id' | 'createdAt' | 'revokedAt'>;

export type SessionChanges = Partial<Pick<StoredSession, 'tokens' | 'profile' | 'accessExpiresAt'>>;

/**
 * Where Bahari sessions are kept. Implement it on your database (encrypt tokens) for multi-process apps; the
 * MemoryStore default only suits one process.
 */
export interface SessionStore {
  /** Saves a new session and returns it with its id. */
  create(session: NewSession): Promise<StoredSession>;
  /** The active (not revoked, not expired) session with this id and kind, or null. */
  find(id: string, kind: Kind): Promise<StoredSession | null>;
  /** Saves a rechecked profile and, after a rotation, new tokens. Returns the updated session or null when gone. */
  update(id: string, changes: SessionChanges): Promise<StoredSession | null>;
  revoke(id: string): Promise<void>;
  /** Ends every active session of this Bahari account and kind (back-channel logout). */
  revokeSubject(kind: Kind, subject: string): Promise<void>;
  /**
   * Optional: ends the admin sessions whose profile user_id is this Bahari account. Bahari's back-channel logout
   * names the account when someone loses admin access; without this, admin sessions end at their next check.
   */
  revokeLinkedUser?(userId: string): Promise<void>;
}

/** In-process SessionStore for development, tests and single-process apps. */
export class MemoryStore implements SessionStore {
  private readonly sessions = new Map<string, StoredSession>();

  constructor(private readonly now: () => number = unixNow) {}

  async create(session: NewSession): Promise<StoredSession> {
    const stored: StoredSession = { ...clone(session), id: randomUUID(), createdAt: this.now(), revokedAt: null };
    this.sessions.set(stored.id, stored);

    return clone(stored);
  }

  async find(id: string, kind: Kind): Promise<StoredSession | null> {
    const session = this.sessions.get(id);
    if (!session || session.kind !== kind || session.revokedAt !== null || session.expiresAt <= this.now()) {
      return null;
    }

    return clone(session);
  }

  async update(id: string, changes: SessionChanges): Promise<StoredSession | null> {
    const session = this.sessions.get(id);
    if (!session || session.revokedAt !== null) {
      return null;
    }
    Object.assign(session, clone(changes));

    return clone(session);
  }

  async revoke(id: string): Promise<void> {
    const session = this.sessions.get(id);
    if (session && session.revokedAt === null) {
      session.revokedAt = this.now();
    }
  }

  async revokeSubject(kind: Kind, subject: string): Promise<void> {
    for (const session of this.sessions.values()) {
      if (session.kind === kind && session.subject === subject && session.revokedAt === null) {
        session.revokedAt = this.now();
      }
    }
  }

  async revokeLinkedUser(userId: string): Promise<void> {
    for (const session of this.sessions.values()) {
      if (session.kind === 'admin' && session.profile?.user_id === userId && session.revokedAt === null) {
        session.revokedAt = this.now();
      }
    }
  }

  /** Removes revoked and expired sessions. */
  prune(): void {
    const now = this.now();
    for (const [id, session] of this.sessions) {
      if (session.revokedAt !== null || session.expiresAt <= now) {
        this.sessions.delete(id);
      }
    }
  }

  get size(): number {
    return this.sessions.size;
  }
}
