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
      ).code
    ).toBe('code');
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
    'eu.chattocorp.chatto.mobile:/other?state=current&code=code',
    'eu.chattocorp.chatto.mobile://attacker/oauth/callback?state=current&code=code',
    'https://attacker/oauth/callback?state=current&code=code',
    `${MOBILE_CALLBACK}?state=old&code=code`,
    `${MOBILE_CALLBACK}?state=current&state=other&code=code`,
    `${MOBILE_CALLBACK}?state=current&code=one&code=two`,
    `${MOBILE_CALLBACK}?state=current&code=code&error=access_denied`,
    `${MOBILE_CALLBACK}?state=current`,
    `${MOBILE_CALLBACK}?state=current&code=code#fragment`
  ])('rejects an unrelated or ambiguous mobile callback: %s', (callback) => {
    expect(() => validateNativeCallback(callback, MOBILE_CALLBACK, 'current')).toThrow();
  });

  it.each([
    'chatto://desktop/servers/callback?state=current&code=code',
    'chatto://desktop/servers/callback?mode=provider&state=current',
    'chatto://desktop/servers/callback?mode=popup&mode=popup&state=current&code=code',
    'chatto://attacker/servers/callback?mode=popup&state=current&code=code',
    'chatto://desktop/servers/authorize?mode=popup&state=current&code=code',
    `${DESKTOP_CALLBACK}&state=old&code=code`
  ])('rejects a desktop callback outside the popup contract: %s', (callback) => {
    expect(() => validateNativeCallback(callback, DESKTOP_CALLBACK, 'current')).toThrow();
  });
});

describe('native authorization hosts', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('is absent in an ordinary browser', () => {
    vi.stubGlobal('window', {});
    expect(nativeAuthorization()).toBeNull();
  });

  it('uses the desktop client and validates the callback the host returns', async () => {
    const authorize = vi.fn(async () => `${DESKTOP_CALLBACK}&state=current&code=code`);
    vi.stubGlobal('window', { chattoDesktop: { authorization: { authorize } } });
    const native = nativeAuthorization();
    expect(native?.clientId).toBe(DESKTOP_CLIENT_ID);
    expect(native?.callback).toBe(DESKTOP_CALLBACK);
    await expect(
      native?.authorize('https://chat.example/oauth/authorize', 'current')
    ).resolves.toMatchObject({ code: 'code' });
    expect(authorize).toHaveBeenCalledWith('https://chat.example/oauth/authorize');
    await expect(
      native?.authorize('https://chat.example/oauth/authorize', 'other')
    ).rejects.toThrow();
  });
});
