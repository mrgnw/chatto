// SPDX-FileCopyrightText: 2026 ChattoCorp GmbH
// SPDX-License-Identifier: Apache-2.0

import AppKit
import AuthenticationServices
import Foundation

/// The `authorize` command. It reads one Chatto authorization URL from standard
/// input, signs in through the system browser with `ASWebAuthenticationSession`,
/// and prints the exact `chatto://desktop/servers/callback` URL to standard
/// output. Electron keeps the OAuth state and PKCE verifier; the helper never
/// sees a token. Standard error carries only fixed messages, never a URL.
enum AuthorizationRequest {
  static let clientID = "chatto://desktop"
  static let callback = "chatto://desktop/servers/callback?mode=popup"
  static let timeout: TimeInterval = 300

  /// Accept only an HTTPS request for the built-in desktop client and its exact callback.
  static func validate(_ raw: String) -> URL? {
    guard
      let url = URL(string: raw),
      let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
      components.scheme == "https", components.user == nil, components.password == nil,
      components.fragment == nil, let items = components.queryItems,
      items.filter({ $0.name == "client_id" }).map(\.value) == [clientID],
      items.filter({ $0.name == "redirect_uri" }).map(\.value) == [callback]
    else { return nil }
    return url
  }

  /// Accept only the desktop callback. Electron checks state, code, and issuer.
  static func isCallback(_ url: URL) -> Bool {
    url.scheme == "chatto" && url.host == "desktop" && url.path == "/servers/callback"
      && url.user == nil && url.fragment == nil
  }
}

@MainActor
final class AuthorizationSession: NSObject, NSApplicationDelegate, NSWindowDelegate,
  ASWebAuthenticationPresentationContextProviding
{
  private let url: URL
  private let window: NSWindow
  private var session: ASWebAuthenticationSession?

  /// Runs the complete command and exits the process.
  static func main() -> Never {
    guard let raw = readLine(), let url = AuthorizationRequest.validate(raw) else {
      fail("The sign-in request is not a Chatto Desktop authorization URL.", status: 2)
    }
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let delegate = AuthorizationSession(url: url)
    app.delegate = delegate
    app.run()
    fail("The sign-in session ended unexpectedly.", status: 1)
  }

  private init(url: URL) {
    self.url = url
    window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 360, height: 96),
      styleMask: [.titled, .closable], backing: .buffered, defer: false)
    super.init()
    window.title = "Chatto"
    window.isReleasedWhenClosed = false
    window.delegate = self
    let label = NSTextField(wrappingLabelWithString: "Finish signing in to Chatto in your browser.")
    let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancel))
    cancel.keyEquivalent = "\u{1b}"
    let stack = NSStackView(views: [label, cancel])
    stack.orientation = .vertical
    stack.alignment = .trailing
    stack.edgeInsets = NSEdgeInsets(top: 16, left: 20, bottom: 16, right: 20)
    window.contentView = stack
    window.center()
  }

  /// The session can only start once the application runs; it ends at once otherwise.
  func applicationDidFinishLaunching(_ notification: Notification) {
    let session = ASWebAuthenticationSession(
      url: url, callback: .customScheme("chatto"), completionHandler: Self.finish)
    session.presentationContextProvider = self
    self.session = session
    window.makeKeyAndOrderFront(nil)
    activateFromParent()
    guard session.start() else {
      Self.fail("The sign-in session could not be started.", status: 1)
    }
    Timer.scheduledTimer(withTimeInterval: AuthorizationRequest.timeout, repeats: false) { _ in
      Task { @MainActor in Self.fail("The sign-in attempt timed out.", status: 1) }
    }
  }

  /// Electron is frontmost when it starts this helper; take activation over from it.
  private func activateFromParent() {
    if let parent = NSRunningApplication(processIdentifier: getppid()) {
      NSRunningApplication.current.activate(from: parent, options: [])
    } else {
      NSApplication.shared.activate()
    }
  }

  /// AuthenticationServices calls this on a background queue.
  private nonisolated static func finish(_ callback: URL?, _ error: Error?) {
    guard let callback, AuthorizationRequest.isCallback(callback) else {
      fail("Sign-in was cancelled or could not be completed.", status: 1)
    }
    print(callback.absoluteString)
    fflush(stdout)
    exit(0)
  }

  @objc private func cancel() {
    Self.fail("Sign-in was cancelled.", status: 1)
  }

  func windowWillClose(_ notification: Notification) {
    Self.fail("Sign-in was cancelled.", status: 1)
  }

  func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    window
  }

  private nonisolated static func fail(_ message: String, status: Int32) -> Never {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    exit(status)
  }
}
