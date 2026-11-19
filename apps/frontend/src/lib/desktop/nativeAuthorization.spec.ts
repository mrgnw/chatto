import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  DESKTOP_CALLBACK,
  DESKTOP_CLIENT_ID,
  MOBILE_CALLBACK,
  nativeAuthorization,
  validateNativeCallback
} from './nativeAuthorization';

describe('native authorization callback boundary', () => {
  it('accepts a code only for the current attempt and exact callback', () => {
    expect(
      validateNativeCallback(
        `${MOBILE_CALLBACK}?state=current&code=code`,
        MOBILE_CALLBACK,
        'current'
      ).code
    ).toBe('code');
    expect(
      validateNativeCallback(
        `${DESKTOP_CALLBACK}&state=current&code=code&iss=https%3A%2F%2Fchat.example`,
        DESKTOP_CALLBACK,
        'current'
      )
    ).toMatchObject({ code: 'code', iss: 'https://chat.example' });
  });

  it('preserves an OAuth error for the current attempt', () => {
    expect(
      validateNativeCallback(
        `${MOBILE_CALLBACK}?state=current&error=access_denied`,
        MOBILE_CALLBACK,
        'current'
      ).error
    ).toBe('access_denied');
  });

  it.each([
    'https://example.com/oauth/callback?state=current&code=code',
    'eu.chattocorp.chatto.mobile://evil/oauth/callback?state=current&code=code',
    'eu.chattocorp.chatto.mobile://user:password@/oauth/callback?state=current&code=code',
    `${MOBILE_CALLBACK}?state=old&code=code`,
    `${MOBILE_CALLBACK}?state=current&state=other&code=code`,
    `${MOBILE_CALLBACK}?state=current&code=one&code=two`,
    `${MOBILE_CALLBACK}?state=current&code=code&error=access_denied`,
    `${MOBILE_CALLBACK}?state=current`,
    `${MOBILE_CALLBACK}?state=current&code=code#fragment`,
    `${MOBILE_CALLBACK}?mode=provider&state=current&code=code`,
    `${MOBILE_CALLBACK}?state=current&code=code&iss=a&iss=b`
  ])('rejects an unrelated or ambiguous mobile callback: %s', (callback) => {
    expect(() => validateNativeCallback(callback, MOBILE_CALLBACK, 'current')).toThrow();
  });

  it.each([
    'chatto://desktop/servers/callback?state=current&code=code',
    'chatto://desktop/servers/callback?mode=provider&state=current&code=code',
    'chatto://desktop/servers/callback?mode=popup&mode=popup&state=current&code=code',
    'chatto://desktop/servers/callback?mode=popup&mode=other&state=current&code=code',
    'chatto://attacker/servers/callback?mode=popup&state=current&code=code',
    'chatto://desktop/servers/authorize?mode=popup&state=current&code=code',
    'chatto://desktop/servers/callback?mode=popup&state=current&code=code&iss=a&iss=b',
    'chatto://desktop/servers/callback?mode=popup&state=current&code=code#fragment',
    `${DESKTOP_CALLBACK}&state=old&code=code`
  ])('rejects a desktop callback outside the popup contract: %s', (callback) => {
    expect(() => validateNativeCallback(callback, DESKTOP_CALLBACK, 'current')).toThrow();
  });
});

describe('native authorization hosts', () => {
  const serverUrl = 'https://chat.example';

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function stubDesktop(authorization: unknown) {
    vi.stubGlobal('window', { chattoDesktop: { authorization } });
  }

  it('is absent in an ordinary browser', () => {
    vi.stubGlobal('window', {});
    expect(nativeAuthorization(serverUrl)).toBeNull();
  });

  it('is absent when the desktop host lacks cancellation', () => {
    stubDesktop({ authorize: vi.fn() });
    expect(nativeAuthorization(serverUrl)).toBeNull();
  });

  it.each(['http://chat.example', 'http://localhost:4000', 'not a url'])(
    'leaves %s on the popup',
    (url) => {
      stubDesktop({ authorize: vi.fn(), cancel: vi.fn() });
      expect(nativeAuthorization(url)).toBeNull();
    }
  );

  it('uses the desktop client and validates the callback the host returns', async () => {
    const authorize = vi.fn(async () => ({
      status: 'ok',
      url: `${DESKTOP_CALLBACK}&state=current&code=code`
    }));
    const cancel = vi.fn(async () => {});
    stubDesktop({ authorize, cancel });
    const native = nativeAuthorization(serverUrl);
    expect(native?.clientId).toBe(DESKTOP_CLIENT_ID);
    expect(native?.callback).toBe(DESKTOP_CALLBACK);
    await expect(
      native?.authorize('https://chat.example/oauth/authorize', 'current')
    ).resolves.toMatchObject({ code: 'code' });
    expect(authorize).toHaveBeenCalledWith('https://chat.example/oauth/authorize', 'current');
    await expect(
      native?.authorize('https://chat.example/oauth/authorize', 'other')
    ).rejects.toThrow();
    await native?.cancel?.('current');
    expect(cancel).toHaveBeenCalledWith('current');
  });

  it('maps host cancellation to a cancelled popup error', async () => {
    stubDesktop({ authorize: async () => ({ status: 'cancelled' }), cancel: vi.fn() });
    await expect(nativeAuthorization(serverUrl)?.authorize('u', 'a')).rejects.toMatchObject({
      reason: 'cancelled'
    });
  });

  it.each([{ status: 'failed' }, { status: 'ok' }, { status: 'ok', url: 3 }, undefined, 'url'])(
    'treats host result %j as a failed sign-in',
    async (result) => {
      stubDesktop({ authorize: async () => result, cancel: vi.fn() });
      await expect(nativeAuthorization(serverUrl)?.authorize('u', 'a')).rejects.toThrow(
        'Sign-in failed.'
      );
    }
  );
});
