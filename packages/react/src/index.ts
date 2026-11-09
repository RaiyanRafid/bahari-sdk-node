'use client';

import {
  type AnchorHTMLAttributes,
  type ButtonHTMLAttributes,
  type FormHTMLAttributes,
  type ReactElement,
  type ReactNode,
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { type BahariSession, type FetchLike, type Kind, type PinnedResult, fetchNavigation, fetchSession, loginHref, logoutAction, normalizePrefix, registerHref, savePinned } from './core.js';

export * from './core.js';

export const VERSION = '0.3.0';

export type SessionStatus = 'loading' | 'authenticated' | 'unauthenticated' | 'error';

export interface BahariContextValue {
  session: BahariSession | null;
  status: SessionStatus;
  error: Error | null;
  /** Fetches the session again from the app's backend (which rechecks it with Bahari). */
  refresh(): Promise<void>;
  prefix: string;
  kind: Kind | null;
  fetch: FetchLike | undefined;
}

const BahariContext = createContext<BahariContextValue | null>(null);

export interface BahariProviderProps {
  /** Where the app mounted the Bahari routes. Default "/auth". */
  prefix?: string;
  /** "client" or "admin". Default: the customer session, then the admin session. */
  kind?: Kind | null;
  /** A session already loaded on the server (skips the first request). null means signed out. */
  initialSession?: BahariSession | null;
  /** Fetch the session again when the window regains focus. Default true. */
  refetchOnFocus?: boolean;
  fetch?: FetchLike;
  children?: ReactNode;
}

/** Loads the signed-in session from your backend ({prefix}/session) and shares it with useBahariSession(). */
export function BahariProvider(props: BahariProviderProps): ReactElement {
  const prefix = normalizePrefix(props.prefix ?? '/auth');
  const kind = props.kind ?? null;
  const fetcher = props.fetch;
  const [session, setSession] = useState<BahariSession | null>(props.initialSession ?? null);
  const [status, setStatus] = useState<SessionStatus>(props.initialSession === undefined ? 'loading' : props.initialSession ? 'authenticated' : 'unauthenticated');
  const [error, setError] = useState<Error | null>(null);
  const mounted = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const next = await fetchSession({ prefix, kind, fetch: fetcher });
      if (mounted.current) {
        setSession(next);
        setStatus(next ? 'authenticated' : 'unauthenticated');
        setError(null);
      }
    } catch (failure) {
      if (mounted.current) {
        setSession(null);
        setStatus('error');
        setError(failure instanceof Error ? failure : new Error(String(failure)));
      }
    }
  }, [prefix, kind, fetcher]);

  useEffect(() => {
    mounted.current = true;
    if (props.initialSession === undefined) {
      void refresh();
    }
    if (props.refetchOnFocus === false || typeof window === 'undefined') {
      return () => {
        mounted.current = false;
      };
    }
    const onFocus = (): void => {
      void refresh();
    };
    window.addEventListener('focus', onFocus);

    return () => {
      mounted.current = false;
      window.removeEventListener('focus', onFocus);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh, props.refetchOnFocus]);

  const value = useMemo<BahariContextValue>(() => ({ session, status, error, refresh, prefix, kind, fetch: fetcher }), [session, status, error, refresh, prefix, kind, fetcher]);

  return createElement(BahariContext.Provider, { value }, props.children);
}

/** The signed-in Bahari session: { session, status, error, refresh }. Requires <BahariProvider>. */
export function useBahariSession(): BahariContextValue {
  const context = useContext(BahariContext);
  if (!context) {
    throw new Error('useBahariSession() must be used inside <BahariProvider>.');
  }

  return context;
}

export interface NavigationState {
  navigation: Record<string, unknown> | null;
  status: 'loading' | 'ready' | 'unauthenticated' | 'error';
  error: Error | null;
  reload(): Promise<void>;
  /** Saves pinned platforms (customers) and reloads the switcher on success. */
  updatePinned(keys: string[]): Promise<PinnedResult>;
}

/** The platform switcher for the signed-in person (GET {prefix}/navigation). */
export function useBahariNavigation(options: { kind?: Kind | null; prefix?: string; fetch?: FetchLike } = {}): NavigationState {
  const context = useContext(BahariContext);
  const prefix = normalizePrefix(options.prefix ?? context?.prefix ?? '/auth');
  const kind = options.kind ?? context?.session?.kind ?? context?.kind ?? null;
  const fetcher = options.fetch ?? context?.fetch;
  const [navigation, setNavigation] = useState<Record<string, unknown> | null>(null);
  const [status, setStatus] = useState<NavigationState['status']>('loading');
  const [error, setError] = useState<Error | null>(null);

  const reload = useCallback(async () => {
    try {
      const data = await fetchNavigation({ prefix, kind, fetch: fetcher });
      setNavigation(data);
      setStatus(data ? 'ready' : 'unauthenticated');
      setError(null);
    } catch (failure) {
      setStatus('error');
      setError(failure instanceof Error ? failure : new Error(String(failure)));
    }
  }, [prefix, kind, fetcher]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const updatePinned = useCallback(
    async (keys: string[]) => {
      const result = await savePinned(keys, { prefix, fetch: fetcher });
      if (result.ok) {
        await reload();
      }

      return result;
    },
    [prefix, fetcher, reload],
  );

  return { navigation, status, error, reload, updatePinned };
}

export interface SignInButtonProps extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> {
  /** Omit for the automatic sign-in (admins continue to the admin sign-in). */
  kind?: Kind | null;
  /** A path inside the kind's area to come back to. The backend sanitises it. */
  returnTo?: string | null;
  prefix?: string;
  children?: ReactNode;
}

/** A link to {prefix}/login or {prefix}/{kind}/login. */
export function SignInButton({ kind, returnTo, prefix, children, ...rest }: SignInButtonProps): ReactElement {
  const context = useContext(BahariContext);
  const href = loginHref(prefix ?? context?.prefix ?? '/auth', kind ?? null, returnTo ?? null);

  return createElement('a', { ...rest, href }, children ?? 'Sign in with Bahari');
}

export interface CreateAccountButtonProps extends Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> {
  returnTo?: string;
  prefix?: string;
  children?: ReactNode;
}

/** A link to Bahari registration; the person comes back signed in. The app has no registration form of its own. */
export function CreateAccountButton({ returnTo, prefix, children, ...rest }: CreateAccountButtonProps): ReactElement {
  const context = useContext(BahariContext);
  const href = registerHref(prefix ?? context?.prefix ?? '/auth', returnTo ?? null);

  return createElement('a', { ...rest, href }, children ?? 'Create a Bahari account');
}

export interface SignOutButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'type' | 'form'> {
  kind: Kind;
  prefix?: string;
  formProps?: Omit<FormHTMLAttributes<HTMLFormElement>, 'method' | 'action'>;
  children?: ReactNode;
}

/** A POST form to {prefix}/{kind}/logout (sign-out is never a GET link). */
export function SignOutButton({ kind, prefix, formProps, children, ...rest }: SignOutButtonProps): ReactElement {
  const context = useContext(BahariContext);
  const action = logoutAction(prefix ?? context?.prefix ?? '/auth', kind);

  return createElement('form', { ...formProps, method: 'post', action }, createElement('button', { ...rest, type: 'submit' }, children ?? 'Sign out'));
}

