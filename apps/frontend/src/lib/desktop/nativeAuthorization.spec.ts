import { afterEach, describe, expect, it, vi } from 'vitest';
import {
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
});

describe('native authorization hosts', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('is absent in an ordinary browser', () => {
    vi.stubGlobal('window', {});
    expect(nativeAuthorization()).toBeNull();
  });
});
