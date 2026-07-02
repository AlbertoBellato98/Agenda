// Agenda — native macOS application.
//
// This is a real, compiled Cocoa app: an NSWindow hosting a WKWebView.
// There is no browser and no browser chrome — just an app window with its
// own Dock icon and native menu bar. WKWebView is Apple's native web
// component; embedding it is how many native Mac apps render their UI.
//
// Why a WKWebView pointed at http://127.0.0.1 (and not local files):
// the interface encrypts everything with the Web Crypto API, which only
// runs in a "secure context". 127.0.0.1 qualifies as secure; file:// does
// not. So the app launches the bundled Python server (server.py, standard
// library only) on loopback and points the window at it. The server never
// sees the password or the plaintext — it only stores an encrypted blob.
//
// Lifecycle: the app owns the server subprocess. Closing the window flushes
// any unsaved note to disk (an awaited save, no size limit), then stops the
// server and quits. Nothing is left running in the background.

import Cocoa
import WebKit

// MARK: - Configuration

private enum Config {
    static let appName = "Agenda"
    static let host = "127.0.0.1"
    static let port = 8765
    static let url = URL(string: "http://127.0.0.1:8765/")!
    static let serverReadyTimeout: TimeInterval = 8.0   // wait for the server to come up
    static let flushTimeout: TimeInterval = 5.0          // wait for the final save on quit
}

// MARK: - Local server process

/// Owns the Python server subprocess and answers "is it ready yet?".
final class LocalServer {
    private var process: Process?

    /// Absolute paths, resolved from the app bundle at runtime.
    private let pythonPath: String
    private let serverScript: String
    private let workingDirectory: String
    private let dataDirectory: String

    init?(bundle: Bundle) {
        guard let resourcePath = bundle.resourcePath else { return nil }
        self.serverScript = (resourcePath as NSString).appendingPathComponent("server.py")
        self.workingDirectory = resourcePath

        // User data lives in ~/Documents/Agenda. This is always writable and
        // survives moving the app (e.g. into /Applications) — unlike a folder
        // next to the bundle, which would be read-only there. Documents keeps
        // it visible in Finder so a non-technical user can find their backups.
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        self.dataDirectory = documents.appendingPathComponent("Agenda").path

        guard let python = LocalServer.findPython() else { return nil }
        self.pythonPath = python
    }

    /// Search well-known locations for a python3 interpreter. GUI apps do not
    /// inherit the shell PATH, so we cannot rely on `python3` being resolvable;
    /// we probe concrete paths and prefer full installs over the CLT stub.
    private static func findPython() -> String? {
        let candidates = [
            "/Library/Frameworks/Python.framework/Versions/Current/bin/python3",
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
        ]
        let fm = FileManager.default
        for path in candidates where fm.isExecutableFile(atPath: path) {
            return path
        }
        return nil
    }

    /// Start the server. Only the stdlib is used, so any python3 works.
    func start() throws {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: pythonPath)
        task.arguments = [serverScript, "--embedded"]
        task.currentDirectoryURL = URL(fileURLWithPath: workingDirectory)

        var env = ProcessInfo.processInfo.environment
        env["AGENDA_DATA_DIR"] = dataDirectory
        task.environment = env

        try task.run()
        self.process = task
    }

    /// True if an Agenda server is already answering on the port — meaning
    /// another instance of the app is already running.
    func isAlreadyRunning() -> Bool {
        return pingSucceeds()
    }

    /// Block until the server answers /api/ping, or the timeout elapses.
    func waitUntilReady(timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if pingSucceeds() { return true }
            Thread.sleep(forTimeInterval: 0.1)
        }
        return false
    }

    private func pingSucceeds() -> Bool {
        guard let url = URL(string: "http://\(Config.host):\(Config.port)/api/ping") else {
            return false
        }
        let semaphore = DispatchSemaphore(value: 0)
        var ok = false
        var request = URLRequest(url: url)
        request.timeoutInterval = 1.0
        let task = URLSession.shared.dataTask(with: request) { data, response, _ in
            if let http = response as? HTTPURLResponse, http.statusCode == 200,
               let data = data, let body = String(data: data, encoding: .utf8),
               body.contains("\"app\":\"agenda\"") {
                ok = true
            }
            semaphore.signal()
        }
        task.resume()
        _ = semaphore.wait(timeout: .now() + 1.5)
        return ok
    }

    func stop() {
        process?.terminate()
        process = nil
    }
}

// MARK: - Application delegate

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate {
    private var window: NSWindow!
    private var webView: WKWebView!
    private var server: LocalServer!
    private var startedServer = false // did WE start it (vs. reuse an existing one)?
    private var isQuitting = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard let server = LocalServer(bundle: .main) else {
            presentFatalError("Impossibile individuare i file dell'app o Python 3. Reinstalla Agenda.")
            return
        }
        self.server = server

        // Start the server and wait for it OFF the main thread, so the app
        // never freezes during launch. Touch the UI only back on the main
        // thread in the completion.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            // Single-instance guard: if a server already answers, another copy
            // of Agenda is open. Two windows on one server would fight over the
            // data, so we bow out instead.
            if server.isAlreadyRunning() {
                DispatchQueue.main.async {
                    self.presentFatalError("Agenda è già aperta. Usa la finestra già in uso.")
                }
                return
            }
            do {
                try server.start()
                self.startedServer = true
            } catch {
                DispatchQueue.main.async {
                    self.presentFatalError("Agenda non è riuscita ad avviare il server locale.")
                }
                return
            }
            let ready = server.waitUntilReady(timeout: Config.serverReadyTimeout)
            DispatchQueue.main.async {
                guard ready else {
                    self.presentFatalError("Il server locale non ha risposto in tempo.")
                    return
                }
                self.buildMenu()
                self.buildWindow()
                // Load first, reveal on didFinish (below): the user never sees a
                // blank frame — the window appears already painted.
                self.webView.navigationDelegate = self
                self.webView.load(URLRequest(url: Config.url))
            }
        }
    }

    // Show the window only once the first page has rendered, so there is no
    // flash of an empty WebView before the dark UI paints.
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard !window.isVisible else { return }
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: Clean shutdown
    //
    // Both ways of leaving — the red close button and Cmd+Q — are funneled
    // through applicationShouldTerminate, so a pending note is ALWAYS flushed
    // before the app goes away, no matter how the user quits.

    // Closing the (single) window requests termination instead of just
    // vanishing, so the flush below runs while the window is still alive.
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        NSApp.terminate(nil)
        return false
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if isQuitting { return .terminateNow }
        isQuitting = true

        // Ask the page to persist any unsaved note. This is an awaited save
        // with no size limit — unlike a browser tab-close, nothing is lost.
        let flush = "window.flushAndReport ? window.flushAndReport() : 'clean'"
        webView.evaluateJavaScript(flush) { [weak self] _, _ in
            self?.completeTermination()
        }
        // Safety net: never let a stuck page block the quit forever.
        DispatchQueue.main.asyncAfter(deadline: .now() + Config.flushTimeout) { [weak self] in
            self?.completeTermination()
        }
        return .terminateLater
    }

    private var terminationCompleted = false
    private func completeTermination() {
        if terminationCompleted { return } // idempotent: flush + timeout may both fire
        terminationCompleted = true
        server?.stop()
        NSApp.reply(toApplicationShouldTerminate: true)
    }

    func applicationWillTerminate(_ notification: Notification) {
        server?.stop() // final safety net in case we terminate another way
    }

    // MARK: UI construction

    private func buildWindow() {
        let style: NSWindow.StyleMask = [.titled, .closable, .miniaturizable, .resizable]
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1040, height: 720),
            styleMask: style,
            backing: .buffered,
            defer: false)
        window.title = Config.appName
        window.minSize = NSSize(width: 560, height: 480)
        window.backgroundColor = .black
        window.delegate = self
        window.center()
        window.setFrameAutosaveName("AgendaMainWindow") // remember size/position

        let config = WKWebViewConfiguration()
        webView = WKWebView(frame: window.contentView!.bounds, configuration: config)
        webView.autoresizingMask = [.width, .height]
        window.contentView!.addSubview(webView)
    }

    /// A standard menu bar so the expected shortcuts work inside the WebView:
    /// Cmd+Q to quit, and Cmd+X/C/V/A/Z in the text fields.
    private func buildMenu() {
        let mainMenu = NSMenu()

        // Application menu
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        let appMenu = NSMenu()
        appMenuItem.submenu = appMenu
        appMenu.addItem(withTitle: "Nascondi \(Config.appName)",
                        action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Esci da \(Config.appName)",
                        action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        // Edit menu (enables copy/paste/select-all/undo in inputs)
        let editMenuItem = NSMenuItem()
        mainMenu.addItem(editMenuItem)
        let editMenu = NSMenu(title: "Modifica")
        editMenuItem.submenu = editMenu
        editMenu.addItem(withTitle: "Annulla", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Ripeti", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(.separator())
        editMenu.addItem(withTitle: "Taglia", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copia", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Incolla", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Seleziona tutto",
                         action: #selector(NSResponder.selectAll(_:)), keyEquivalent: "a")

        // Window menu (minimize / zoom)
        let windowMenuItem = NSMenuItem()
        mainMenu.addItem(windowMenuItem)
        let windowMenu = NSMenu(title: "Finestra")
        windowMenuItem.submenu = windowMenu
        windowMenu.addItem(withTitle: "Riduci a icona",
                           action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Ingrandisci",
                           action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        NSApp.windowsMenu = windowMenu

        NSApp.mainMenu = mainMenu
    }

    private func presentFatalError(_ message: String) {
        // Bring the app forward so the alert is actually visible — otherwise
        // a background instance (e.g. the "already open" guard) would block on
        // an unseen modal.
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = Config.appName
        alert.informativeText = message
        alert.alertStyle = .critical
        alert.runModal()
        // Only stop the server if WE started it — never kill another instance's.
        if startedServer { server?.stop() }
        NSApp.terminate(nil)
    }
}

// MARK: - Entry point

let app = NSApplication.shared
app.setActivationPolicy(.regular)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
