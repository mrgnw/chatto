import { hasAppOrigin } from './security.mjs';

export const authorizationAuthorizeChannel = 'chatto:authorization:authorize';

/** Matches the frontend's sign-in timeout, so both sides give up together. */
export const AUTHORIZATION_TTL_MS = 5 * 60 * 1000;

/** Sign-ins that can wait for the browser at the same time. */
export const MAX_PENDING_AUTHORIZATIONS = 4;

const MAX_STATE_LENGTH = 256;

/**
 * Return the `state` of a desktop OAuth callback URL, or `null` for any other
 * URL. Only the exact callback path on the app origin with one `state` counts.
 */
export function authorizationCallbackState(value) {
  if (!hasAppOrigin(value)) return null;
  const url = new URL(value);
  if (url.pathname !== '/servers/callback') return null;
  const states = url.searchParams.getAll('state');
  if (states.length !== 1 || !isValidState(states[0])) return null;
  return states[0];
}

/** Return the first desktop OAuth callback URL in a command line, or `null`. */
export function authorizationCallbackFromArgv(argv) {
  return argv.find((argument) => authorizationCallbackState(argument) !== null) ?? null;
}

/**
 * Sign-ins that wait for a callback from the system browser, keyed by the
 * OAuth `state`. A callback completes the attempt whose state it names. Every
 * other callback is dropped: an unknown, expired, or already-used state.
 */
export class PendingAuthorizations {
  #entries = new Map();

  get size() {
    return this.#entries.size;
  }

  /**
   * Wait for the callback of one sign-in. Resolves with the callback URL.
   * Rejects after `AUTHORIZATION_TTL_MS` or on `cancel`. Throws at once for
   * an invalid, duplicate, or excess state, before any browser opens.
   */
  begin(state) {
    if (!isValidState(state)) throw new Error('Invalid sign-in state.');
    if (this.#entries.has(state)) throw new Error('Duplicate sign-in state.');
    if (this.#entries.size >= MAX_PENDING_AUTHORIZATIONS) {
      throw new Error('Too many sign-ins are waiting for the browser.');
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => this.#settle(state, (entry) => entry.reject(new Error('The sign-in timed out.'))),
        AUTHORIZATION_TTL_MS
      );
      timer.unref?.();
      this.#entries.set(state, { resolve, reject, timer });
    });
  }

  /** Deliver a callback URL. Returns whether it completed a waiting sign-in. */
  complete(url) {
    const state = authorizationCallbackState(url);
    if (state === null) return false;
    return this.#settle(state, (entry) => entry.resolve(url));
  }

  /** Stop waiting for one sign-in. Returns whether one was waiting. */
  cancel(state, message = 'The sign-in was cancelled.') {
    if (!isValidState(state)) return false;
    return this.#settle(state, (entry) => entry.reject(new Error(message)));
  }

  /** Stop waiting for every sign-in, for example when the window closes. */
  cancelAll(message) {
    for (const state of [...this.#entries.keys()]) this.cancel(state, message);
  }

  #settle(state, finish) {
    const entry = this.#entries.get(state);
    if (!entry) return false;
    this.#entries.delete(state);
    clearTimeout(entry.timer);
    finish(entry);
    return true;
  }
}

function isValidState(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_STATE_LENGTH;
}
