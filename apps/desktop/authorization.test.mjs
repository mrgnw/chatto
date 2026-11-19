// SPDX-FileCopyrightText: 2026 ChattoCorp GmbH
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { createMacOSAuthorization } from './authorization.mjs';

function setupAuthorization() {
  const child = new EventEmitter();
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  const signals = [];
  child.kill = (signal = 'SIGTERM') => signals.push(signal);
  return {
    child,
    signals,
    session: createMacOSAuthorization(() => child)
  };
}

test('reads the complete callback after the helper closes its output', async () => {
  const { child, session } = setupAuthorization();
  const result = session.authorize('helper', 'https://chat.example/oauth/authorize', 'attempt');
  child.emit('exit', 0);
  child.stdout.end('chatto://desktop/servers/callback?mode=popup&state=attempt&code=code\n');
  child.emit('close', 0);
  assert.deepEqual(await result, {
    status: 'ok',
    url: 'chatto://desktop/servers/callback?mode=popup&state=attempt&code=code'
  });
});

test('cancels only the matching attempt and waits for the helper before allowing retry', async () => {
  const { child, signals, session } = setupAuthorization();
  const url = 'https://chat.example/oauth/authorize';
  const result = session.authorize('helper', url, 'current');
  await session.cancel('old');
  assert.deepEqual(signals, []);
  const closing = session.cancel('current');
  assert.deepEqual(signals, ['SIGTERM']);
  assert.deepEqual(await session.authorize('helper', url, 'next'), { status: 'failed' });
  child.emit('close', null);
  await closing;
  assert.deepEqual(await result, { status: 'cancelled' });
  const retry = session.authorize('helper', url, 'next');
  child.emit('close', 3);
  assert.deepEqual(await retry, { status: 'cancelled' });
});

test('rejects oversized helper output even if the helper exits successfully', async () => {
  const { child, signals, session } = setupAuthorization();
  const result = session.authorize('helper', 'https://chat.example/oauth/authorize', 'attempt');
  child.stdout.write(Buffer.alloc(8 * 1024 + 1));
  assert.deepEqual(signals, ['SIGTERM']);
  child.emit('close', 0);
  assert.deepEqual(await result, { status: 'failed' });
});
