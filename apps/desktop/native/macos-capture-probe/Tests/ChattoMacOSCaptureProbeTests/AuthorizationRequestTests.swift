// SPDX-FileCopyrightText: 2026 ChattoCorp GmbH
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Testing

@testable import ChattoMacOSCaptureProbe

private let request =
  "https://chat.example/oauth/authorize?response_type=code&client_id=chatto%3A%2F%2Fdesktop"
  + "&redirect_uri=chatto%3A%2F%2Fdesktop%2Fservers%2Fcallback%3Fmode%3Dpopup"
  + "&code_challenge=abc&code_challenge_method=S256&state=xyz"

@Test
func authorizationRequestAcceptsTheDesktopClientOverHTTPS() {
  #expect(AuthorizationRequest.validate(request)?.host == "chat.example")
}

@Test(arguments: [
  request.replacingOccurrences(of: "https:", with: "http:"),
  request.replacingOccurrences(of: "https://", with: "https://user@"),
  request + "#fragment",
  request + "&client_id=chatto%3A%2F%2Fdesktop",
  request.replacingOccurrences(of: "client_id=chatto%3A%2F%2Fdesktop", with: "client_id=https%3A%2F%2Fother"),
  request.replacingOccurrences(of: "%3Fmode%3Dpopup", with: ""),
  "https://chat.example/oauth/authorize",
  "not a url",
])
func authorizationRequestRejectsOtherClientsAndTransports(raw: String) {
  #expect(AuthorizationRequest.validate(raw) == nil)
}

@Test
func authorizationCallbackMatchesOnlyTheDesktopCallbackPath() throws {
  let accepted = try #require(
    URL(string: "chatto://desktop/servers/callback?mode=popup&state=s&code=c"))
  #expect(AuthorizationRequest.isCallback(accepted))
  for raw in [
    "chatto://desktop/servers/other?state=s&code=c",
    "chatto://attacker/servers/callback?state=s&code=c",
    "https://desktop/servers/callback?state=s&code=c",
    "chatto://desktop/servers/callback?state=s&code=c#fragment",
  ] {
    #expect(!AuthorizationRequest.isCallback(try #require(URL(string: raw))))
  }
}
