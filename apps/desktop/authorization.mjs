// SPDX-FileCopyrightText: 2026 ChattoCorp GmbH
// SPDX-License-Identifier: Apache-2.0

import { spawn } from 'node:child_process';

export const authorizationStartChannel = 'chatto:authorization:authorize';
export const authorizationCancelChannel = 'chatto:authorization:cancel';
const maxUrlBytes = 8 * 1024;
const helperTimeoutMs = 305_000;
const terminationGraceMs = 3_000;

/** Own the single native sign-in attempt and its helper until the stdio streams close. */
export function createMacOSAuthorization(spawnHelper = spawn) {
  let active;

  function authorize(executable, url, attemptId) {
    if (
      active ||
      typeof attemptId !== 'string' ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(attemptId) ||
      typeof url !== 'string' ||
      Buffer.byteLength(url) > maxUrlBytes ||
      /[\r\n]/.test(url)
    ) {
      return Promise.resolve({ status: 'failed' });
    }

    const child = spawnHelper(executable, ['authorize'], { stdio: ['pipe', 'pipe', 'ignore'] });
    const { promise, resolve } = Promise.withResolvers();
    const output = Buffer.alloc(maxUrlBytes);
    let outputLength = 0;
    let stopped;
    let forceKill;
    const deadline = setTimeout(() => stop('failed'), helperTimeoutMs).unref();
    active = { attemptId, promise, stop };

    function stop(status) {
      if (stopped) return;
      stopped = status;
      child.kill();
      forceKill = setTimeout(() => child.kill('SIGKILL'), terminationGraceMs).unref();
    }

    child.stdout.on('data', (chunk) => {
      if (stopped) return;
      if (chunk.length > output.length - outputLength) {
        stop('failed');
        return;
      }
      outputLength += chunk.copy(output, outputLength);
    });
    child.stdin.once('error', () => stop('failed'));
    child.on('error', () => stop('failed'));
    child.once('close', (code) => {
      clearTimeout(deadline);
      clearTimeout(forceKill);
      active = undefined;
      if (stopped) resolve({ status: stopped });
      else if (code === 3) resolve({ status: 'cancelled' });
      else if (code === 0 && outputLength > 0)
        resolve({ status: 'ok', url: output.toString('utf8', 0, outputLength).trim() });
      else resolve({ status: 'failed' });
    });
    child.stdin.end(url + '\n');
    return promise;
  }

  async function cancel(attemptId = active?.attemptId) {
    if (!active || active.attemptId !== attemptId) return;
    active.stop('cancelled');
    await active.promise;
  }

  return { authorize, cancel };
}
