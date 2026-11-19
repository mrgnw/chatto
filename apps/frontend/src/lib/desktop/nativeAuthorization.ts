import { Capacitor, registerPlugin } from '@capacitor/core';
import { oauthPopupResponseFromURL, type OAuthPopupResponse } from '$lib/oauth/popup';
import { OAuthPopupError } from '$lib/oauth/popupError';

/** The official mobile client has one exact OAuth identity and callback. */
export const MOBILE_CLIENT_ID = 'eu.chattocorp.chatto.mobile';
export const MOBILE_CALLBACK = 'eu.chattocorp.chatto.mobile:/oauth/callback';
/** Chatto Desktop keeps its built-in client and callback for the system-browser flow. */
export const DESKTOP_CLIENT_ID = 'chatto://desktop';
export const DESKTOP_CALLBACK = 'chatto://desktop/servers/callback?mode=popup';

/** A host that signs in through the system instead of an in-app window. */
export type NativeAuthorization = {
  clientId: string;
  callback: string;
  /** Native code owns presentation and the bounded session lifetime. `attemptId` names this attempt. */
  authorize(url: string, attemptId: string): Promise<OAuthPopupResponse>;
  /**
   * Close the attempt `attemptId`. Resolves after the host has stopped it; the
   * pending `authorize` then rejects as `cancelled`. Absent when the host
   * cannot cancel from the page.
   */
  cancel?(attemptId: string): Promise<void>;
};

type DesktopAuthorizationResult =
  { status: 'ok'; url: string } | { status: 'cancelled' | 'failed' };

const mobilePlugin = registerPlugin<{
  authorize(options: { url: string }): Promise<{ url: string }>;
}>('ChattoAuthorization');

/**
 * Detect the narrow authentication capability for `serverUrl`, independently of
 * other host features. Returns `null` when sign-in uses the browser popup.
 * The Desktop helper accepts HTTPS servers only.
 */
export function nativeAuthorization(serverUrl: string): NativeAuthorization | null {
  if (Capacitor.isPluginAvailable('ChattoAuthorization')) {
    return {
      clientId: MOBILE_CLIENT_ID,
      callback: MOBILE_CALLBACK,
      authorize: async (url, attemptId) => {
        const result = await mobilePlugin.authorize({ url });
        if (typeof result?.url !== 'string') throw new Error('Invalid sign-in callback.');
        return validateNativeCallback(result.url, MOBILE_CALLBACK, attemptId);
      }
    };
  }
  const desktop = typeof window === 'undefined' ? undefined : window.chattoDesktop?.authorization;
  if (
    typeof desktop?.authorize !== 'function' ||
    typeof desktop.cancel !== 'function' ||
    !URL.canParse(serverUrl) ||
    new URL(serverUrl).protocol !== 'https:'
  ) {
    return null;
  }
  return {
    clientId: DESKTOP_CLIENT_ID,
    callback: DESKTOP_CALLBACK,
    authorize: async (url, attemptId) => {
      const result: Partial<DesktopAuthorizationResult> | undefined = await desktop.authorize(
        url,
        attemptId
      );
      if (result?.status === 'cancelled') {
        throw new OAuthPopupError('Sign-in cancelled.', 'cancelled');
      }
      if (result?.status !== 'ok' || typeof result.url !== 'string') {
        throw new Error('Sign-in failed.');
      }
      return validateNativeCallback(result.url, DESKTOP_CALLBACK, attemptId);
    },
    cancel: (attemptId) => desktop.cancel(attemptId)
  };
}

const SINGLE_VALUE_PARAMETERS = ['state', 'code', 'error', 'error_description', 'iss', 'mode'];

/**
 * Reject unrelated callbacks before an authorization code can reach the token
 * endpoint. The callback must be `expectedCallback` with its fixed parameters
 * and the response of the attempt `state`. The server issuer is checked later.
 */
export function validateNativeCallback(
  callback: string,
  expectedCallback: string,
  state: string
): OAuthPopupResponse {
  const url = new URL(callback);
  const expected = new URL(expectedCallback);
  const hasExpectedParameters = [...expected.searchParams].every(([name, value]) => {
    const values = url.searchParams.getAll(name);
    return values.length === 1 && values[0] === value;
  });
  if (
    url.protocol !== expected.protocol ||
    url.host !== expected.host ||
    url.pathname !== expected.pathname ||
    url.username ||
    url.password ||
    url.hash ||
    !hasExpectedParameters ||
    (url.searchParams.has('mode') && !expected.searchParams.has('mode')) ||
    SINGLE_VALUE_PARAMETERS.some((name) => url.searchParams.getAll(name).length > 1) ||
    url.searchParams.getAll('state').length !== 1
  ) {
    throw new Error('Invalid sign-in callback.');
  }
  const response = oauthPopupResponseFromURL(url);
  if (!response || response.state !== state || (response.code && response.error)) {
    throw new Error('Invalid sign-in callback.');
  }
  return response;
}
