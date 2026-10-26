// SPDX-FileCopyrightText: 2026 ChattoCorp GmbH
// SPDX-License-Identifier: Apache-2.0

const { contextBridge, ipcRenderer } = require('electron');

const gameCaptureListSourcesChannel = 'chatto:game-capture:list-sources';
const gameCaptureCancelListSourcesChannel = 'chatto:game-capture:cancel-list-sources';
const gameCaptureStartChannel = 'chatto:game-capture:start';
const gameCapturePublisherChannel = 'chatto:game-capture:publisher';
const gameCaptureFlag = '--chatto-game-capture';
const authorizationAuthorizeChannel = 'chatto:authorization:authorize';

ipcRenderer.on(gameCapturePublisherChannel, (event, message) => {
  if (typeof message?.requestId !== 'string' || event.ports.length !== 1) return;
  window.postMessage(
    { type: gameCapturePublisherChannel, requestId: message.requestId },
    window.origin,
    event.ports
  );
});

const screenShare = Object.freeze({
  listSources: () => {
    if (!navigator.userActivation?.isActive) {
      return Promise.reject(new Error('Native screen sharing requires a user gesture.'));
    }
    return ipcRenderer.invoke(gameCaptureListSourcesChannel);
  },
  cancelSourceList: () => ipcRenderer.send(gameCaptureCancelListSourcesChannel),
  startPublisher: (request) => {
    const requestId = crypto.randomUUID();
    ipcRenderer.send(gameCaptureStartChannel, {
      sourceId: request?.sourceId,
      livekitUrl: request?.livekitUrl,
      token: request?.token,
      e2eeKey: request?.e2eeKey,
      requestId
    });
    return requestId;
  }
});

/** Sign in through the system browser; resolves with the `chatto://` callback URL. */
const authorization = Object.freeze({
  authorize: (request) =>
    ipcRenderer.invoke(authorizationAuthorizeChannel, {
      url: request?.url,
      state: request?.state
    })
});

contextBridge.exposeInMainWorld(
  'chattoDesktop',
  Object.freeze({
    authorization,
    // The host adds the flag only when its native capture helper is available.
    ...(process.argv.includes(gameCaptureFlag) ? { screenShare } : {})
  })
);
