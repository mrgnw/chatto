import assert from 'node:assert/strict';
import test, { mock } from 'node:test';
import {
  AUTHORIZATION_TTL_MS,
  MAX_PENDING_AUTHORIZATIONS,
  PendingAuthorizations,
  authorizationCallbackFromArgv,
  authorizationCallbackState
} from './authorization.mjs';

const callback = (state) =>
  `chatto://desktop/servers/callback?mode=popup&code=cht_AC1&state=${state}`;

test('reads the state only from the exact desktop callback', () => {
  assert.equal(authorizationCallbackState(callback('s1')), 's1');
  assert.equal(authorizationCallbackState('chatto://desktop/servers/callback?code=x'), null);
  assert.equal(
    authorizationCallbackState('chatto://desktop/servers/callback?state=a&state=b'),
    null
  );
  assert.equal(authorizationCallbackState('chatto://desktop/servers/authorize?state=s1'), null);
  assert.equal(authorizationCallbackState('chatto://desktop.evil/servers/callback?state=s1'), null);
  assert.equal(authorizationCallbackState('https://desktop/servers/callback?state=s1'), null);
  assert.equal(
    authorizationCallbackState(`chatto://desktop/servers/callback?state=${'x'.repeat(257)}`),
    null
  );
  assert.equal(authorizationCallbackState('not a url'), null);
});

test('finds the callback in a command line', () => {
  assert.equal(
    authorizationCallbackFromArgv(['chatto-desktop', '--flag', callback('s1')]),
    callback('s1')
  );
  assert.equal(authorizationCallbackFromArgv(['chatto-desktop', 'chatto://desktop/chat']), null);
});

test('completes only the waiting sign-in that the callback names', async () => {
  const pending = new PendingAuthorizations();
  const wait = pending.begin('s1');
  assert.equal(pending.complete(callback('other')), false);
  assert.equal(pending.complete('https://attacker/servers/callback?state=s1'), false);
  assert.equal(pending.size, 1);
  assert.equal(pending.complete(callback('s1')), true);
  assert.equal(await wait, callback('s1'));
  assert.equal(pending.size, 0);
});

test('drops a duplicate callback', async () => {
  const pending = new PendingAuthorizations();
  const wait = pending.begin('s1');
  assert.equal(pending.complete(callback('s1')), true);
  assert.equal(pending.complete(callback('s1')), false);
  await wait;
});

test('drops a callback after the sign-in expired', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  try {
    const pending = new PendingAuthorizations();
    const wait = pending.begin('s1');
    mock.timers.tick(AUTHORIZATION_TTL_MS);
    await assert.rejects(wait, /timed out/);
    assert.equal(pending.complete(callback('s1')), false);
  } finally {
    mock.timers.reset();
  }
});

test('cancel rejects the waiting sign-in once', async () => {
  const pending = new PendingAuthorizations();
  const wait = pending.begin('s1');
  assert.equal(pending.cancel('s1'), true);
  await assert.rejects(wait, /cancelled/);
  assert.equal(pending.cancel('s1'), false);
  assert.equal(pending.complete(callback('s1')), false);
});

test('rejects invalid, duplicate, and excess sign-ins', async () => {
  const pending = new PendingAuthorizations();
  assert.throws(() => pending.begin(''), /Invalid/);
  assert.throws(() => pending.begin(42), /Invalid/);
  const waits = [];
  for (let index = 0; index < MAX_PENDING_AUTHORIZATIONS; index++) {
    waits.push(pending.begin(`s${index}`));
  }
  assert.throws(() => pending.begin('s0'), /Duplicate/);
  assert.throws(() => pending.begin('overflow'), /Too many/);
  pending.cancelAll('closed');
  for (const wait of waits) await assert.rejects(wait, /closed/);
  assert.equal(pending.size, 0);
});
