import { Capacitor, registerPlugin } from '@capacitor/core';
import { oauthPopupResponseFromURL, type OAuthPopupResponse } from '$lib/oauth/popup';

/** The official mobile client has one exact OAuth identity and callback. */
export const MOBILE_CLIENT_ID = 'eu.chattocorp.chatto.mobile';
export const MOBILE_CALLBACK = 'eu.chattocorp.chatto.mobile:/oauth/callback';

/** Chatto Desktop's built-in OAuth identity and the exact callback servers trust. */
export const DESKTOP_CLIENT_ID = 'chatto://desktop';
export const DESKTOP_CALLBACK = 'chatto://desktop/servers/callback?mode=popup';

const mobileAuthorization = registerPlugin<{
  authorize(options: { url: string }): Promise<{ url: string }>;
}>('ChattoAuthorization');

/**
 * A host-owned sign-in: the host presents the authorization URL outside the
 * renderer and returns the OAuth callback URL. The host owns presentation,
 * cancellation, and the bounded session lifetime.
 */
export type NativeAuthorizer = {
  clientId: string;
  callback: string;
  authorize(url: string, state: string): Promise<OAuthPopupResponse>;
};

/**
 * The host's sign-in capability, independent of other host features: the
 * mobile plugin, the desktop system-browser bridge, or `null` for a browser.
 */
export function nativeAuthorizer(): NativeAuthorizer | null {
  if (Capacitor.isPluginAvailable('ChattoAuthorization')) {
    return {
      clientId: MOBILE_CLIENT_ID,
      callback: MOBILE_CALLBACK,
      authorize: async (url, state) => {
        const result = await mobileAuthorization.authorize({ url });
        return validateNativeResult(result, MOBILE_CALLBACK, state);
      }
    };
  }
  const desktop = typeof window === 'undefined' ? undefined : window.chattoDesktop?.authorization;
  if (typeof desktop?.authorize === 'function') {
    return {
      clientId: DESKTOP_CLIENT_ID,
      callback: DESKTOP_CALLBACK,
      authorize: async (url, state) => {
        const result = await desktop.authorize({ url, state });
        return validateNativeResult(result, DESKTOP_CALLBACK, state);
      }
    };
  }
  return null;
}

function validateNativeResult(
  result: unknown,
  expectedCallback: string,
  state: string
): OAuthPopupResponse {
  const url = (result as { url?: unknown } | null)?.url;
  if (typeof url !== 'string') throw new Error('Invalid sign-in callback.');
  return validateNativeCallback(url, expectedCallback, state);
}

/** Reject unrelated callbacks before an authorization code can reach the token endpoint. */
export function validateNativeCallback(
  callback: string,
  expectedCallback: string,
  state: string
): OAuthPopupResponse {
  const url = new URL(callback);
  const expected = new URL(expectedCallback);
  if (
    url.protocol !== expected.protocol ||
    url.host !== expected.host ||
    url.pathname !== expected.pathname ||
    url.username ||
    url.password ||
    url.hash ||
    url.searchParams.getAll('state').length !== 1 ||
    url.searchParams.getAll('code').length > 1 ||
    url.searchParams.getAll('error').length > 1
  ) {
    throw new Error('Invalid sign-in callback.');
  }
  const response = oauthPopupResponseFromURL(url);
  if (!response || response.state !== state || (response.code && response.error)) {
    throw new Error('Invalid sign-in callback.');
  }
  return response;
}
