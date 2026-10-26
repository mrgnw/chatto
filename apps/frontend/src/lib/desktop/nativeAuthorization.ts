import { Capacitor, registerPlugin } from '@capacitor/core';
import { oauthPopupResponseFromURL, type OAuthPopupResponse } from '$lib/oauth/popup';

/** The official mobile client has one exact OAuth identity and callback. */
export const MOBILE_CLIENT_ID = 'eu.chattocorp.chatto.mobile';
export const MOBILE_CALLBACK = 'eu.chattocorp.chatto.mobile:/oauth/callback';
/** Chatto Desktop keeps its built-in client and callback for the system-browser flow (FDR-034). */
export const DESKTOP_CLIENT_ID = 'chatto://desktop';
export const DESKTOP_CALLBACK = 'chatto://desktop/servers/callback?mode=popup';

/** A host that signs in through a system authentication session instead of a popup. */
export type NativeAuthorization = {
  clientId: string;
  callback: string;
  /** Native code owns presentation, cancellation, and the bounded session lifetime. */
  authorize(url: string, state: string): Promise<OAuthPopupResponse>;
};

const mobilePlugin = registerPlugin<{
  authorize(options: { url: string }): Promise<{ url: string }>;
}>('ChattoAuthorization');

/** Detect the narrow authentication capability, independently of other host features. */
export function nativeAuthorization(): NativeAuthorization | null {
  if (Capacitor.isPluginAvailable('ChattoAuthorization')) {
    return host(MOBILE_CLIENT_ID, MOBILE_CALLBACK, async (url) => {
      const result = await mobilePlugin.authorize({ url });
      return result?.url;
    });
  }
  const desktop = typeof window === 'undefined' ? undefined : window.chattoDesktop?.authorization;
  if (typeof desktop?.authorize === 'function') {
    return host(DESKTOP_CLIENT_ID, DESKTOP_CALLBACK, (url) => desktop.authorize(url));
  }
  return null;
}

function host(
  clientId: string,
  callback: string,
  authorize: (url: string) => Promise<unknown>
): NativeAuthorization {
  return {
    clientId,
    callback,
    authorize: async (url, state) => {
      const result = await authorize(url);
      if (typeof result !== 'string') throw new Error('Invalid sign-in callback.');
      return validateNativeCallback(result, callback, state);
    }
  };
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
    [...expected.searchParams].some(
      ([name, value]) => url.searchParams.getAll(name).join() !== value
    ) ||
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
