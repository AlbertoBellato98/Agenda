#!/usr/bin/env python3
"""Agenda — local server.

Serves the web interface and stores the encrypted data blob.
It never sees the password or the plaintext data: all encryption
happens in the browser (Web Crypto API). This process only reads
and writes an opaque, already-encrypted file.

Standard library only. Listens exclusively on 127.0.0.1.

Note: messages printed to the terminal are in Italian on purpose —
they are read by the (non-technical, Italian) end user.
"""

import hashlib
import json
import os
import shutil
import sys
import threading
import time
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8765
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(BASE_DIR, "app")

# The data directory can be relocated with AGENDA_DATA_DIR. The native app
# sets it to a folder NEXT TO the .app, so user data (and backups) stay
# visible even though the code lives inside the app bundle. When unset (e.g.
# running server.py directly for development), data lives in ./dati.
DATA_DIR = os.environ.get("AGENDA_DATA_DIR") or os.path.join(BASE_DIR, "dati")
DATA_FILE = os.path.join(DATA_DIR, "agenda.dat")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")

MAX_BACKUPS = 20
BACKUP_MIN_INTERVAL = 300          # seconds between two rolling backups
DAILY_BACKUPS_KEPT = 14            # one backup per day, kept two weeks
IDLE_EXIT_SECONDS = 600            # shut down after 10 minutes with no requests
MAX_BODY_BYTES = 50 * 1024 * 1024  # 50 MB safety cap

PING_RESPONSE = b'{"app":"agenda","ok":true}'

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

write_lock = threading.Lock()
last_request_time = time.monotonic()
backed_up_this_session = False


def file_etag(path):
    """The ETag is simply the SHA-256 of the file: same content, same tag."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return '"%s"' % digest.hexdigest()


def rolling_backup_names():
    """Rolling backups only ("agenda-<timestamp>.dat"), oldest first.
    Daily backups ("agenda-daily-*.dat") live in the same folder but are
    managed separately and must never be consumed by the fast rotation."""
    try:
        names = os.listdir(BACKUP_DIR)
    except FileNotFoundError:
        return []
    return sorted(n for n in names
                  if n.endswith(".dat") and not n.startswith("agenda-daily-"))


def newest_backup_age():
    """Age in seconds of the most recent rolling backup, or None if none."""
    names = rolling_backup_names()
    if not names:
        return None
    newest = os.path.join(BACKUP_DIR, names[-1])
    return time.time() - os.path.getmtime(newest)


def rotate_backups():
    """Keep only the newest MAX_BACKUPS rolling files (names sort chronologically)."""
    names = rolling_backup_names()
    for name in names[:-MAX_BACKUPS]:
        os.remove(os.path.join(BACKUP_DIR, name))


def daily_backup():
    """First save of the day: set aside one copy that the rolling rotation
    can never touch. Guarantees day-granularity restore points even if a
    burst of saves churns through all the rolling slots."""
    today = datetime.now().strftime("%Y%m%d")
    daily_path = os.path.join(BACKUP_DIR, "agenda-daily-%s.dat" % today)
    if os.path.exists(daily_path):
        return
    shutil.copy2(DATA_FILE, daily_path)
    dailies = sorted(n for n in os.listdir(BACKUP_DIR) if n.startswith("agenda-daily-"))
    for name in dailies[:-DAILY_BACKUPS_KEPT]:
        os.remove(os.path.join(BACKUP_DIR, name))


def save_blob(body):
    """Back up the current file, then write the new blob atomically.

    The backup is throttled (at most one every BACKUP_MIN_INTERVAL, but at
    least one per server session) so that a burst of saves cannot churn
    through all the backup slots with near-identical copies.

    The write itself is crash-safe: write to a temp file, fsync it, then
    os.replace() — which is atomic on APFS. A power cut mid-write leaves
    either the old file or the new one, never a corrupted mix.
    """
    global backed_up_this_session
    os.makedirs(BACKUP_DIR, exist_ok=True)

    if os.path.exists(DATA_FILE):
        daily_backup()
        age = newest_backup_age()
        if not backed_up_this_session or age is None or age > BACKUP_MIN_INTERVAL:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            shutil.copy2(DATA_FILE, os.path.join(BACKUP_DIR, "agenda-%s.dat" % stamp))
            backed_up_this_session = True
            rotate_backups()

    tmp = DATA_FILE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, DATA_FILE)
    dir_fd = os.open(DATA_DIR, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def valid_envelope(body):
    """Sanity check: the body must look like our encrypted envelope.

    The server cannot decrypt the data, but it can still refuse to
    overwrite good data with something that is clearly not an envelope.
    """
    try:
        envelope = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return (
        isinstance(envelope, dict)
        and envelope.get("format") == "agenda-v1"
        and isinstance(envelope.get("kdf"), dict)
        and isinstance(envelope.get("iv"), str)
        and isinstance(envelope.get("data"), str)
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Agenda/1"

    def log_message(self, *args):
        pass  # keep the terminal quiet

    def _touch(self):
        """Record activity so the idle watchdog knows the app is in use."""
        global last_request_time
        last_request_time = time.monotonic()

    def _send(self, code, body=b"", ctype="application/json", extra=None, close=False):
        # `close=True` ends the keep-alive connection after this response.
        # Used when we reply before consuming a request body: leaving unread
        # bytes on a reused HTTP/1.1 connection would desync the next request.
        if close:
            self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if close:
            self.send_header("Connection", "close")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        self._touch()
        path = self.path.split("?", 1)[0]

        if path == "/api/ping":
            self._send(200, PING_RESPONSE)
            return

        if path == "/api/data":
            with write_lock:
                if not os.path.exists(DATA_FILE):
                    # 404 tells the app this is the first run.
                    self._send(404, b'{"error":"no-data"}')
                    return
                etag = file_etag(DATA_FILE)
                with open(DATA_FILE, "rb") as f:
                    body = f.read()
            self._send(200, body, extra={"ETag": etag})
            return

        # Static files from app/ — with a path-traversal guard.
        # We resolve the final real path and require it to live inside
        # APP_DIR. os.path.realpath collapses every "..", so "/../etc/passwd"
        # style paths resolve OUTSIDE APP_DIR and are rejected. (A guard on
        # the un-normalized join would let leading ".." segments slip past.)
        if path == "/":
            path = "/index.html"
        requested = os.path.realpath(os.path.join(APP_DIR, path.lstrip("/")))
        app_root = os.path.realpath(APP_DIR)
        inside = requested == app_root or requested.startswith(app_root + os.sep)
        if not inside or not os.path.isfile(requested):
            self._send(404, b"Non trovato", "text/plain; charset=utf-8")
            return
        ctype = CONTENT_TYPES.get(os.path.splitext(requested)[1], "application/octet-stream")
        with open(requested, "rb") as f:
            self._send(200, f.read(), ctype)

    def do_PUT(self):
        self._touch()
        if self.path.split("?", 1)[0] != "/api/data":
            # Close: we are not reading the (possibly present) request body,
            # so the connection must not be reused.
            self._send(404, b'{"error":"not-found"}', close=True)
            return

        # A missing or oversized Content-Length means we cannot safely read
        # the body, so close the connection instead of guessing its length.
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send(413, b'{"error":"body-size"}', close=True)
            return
        body = self.rfile.read(length)
        if not valid_envelope(body):
            self._send(400, b'{"error":"bad-envelope"}')
            return

        # Optimistic concurrency: the client must prove it has seen the
        # current version (If-Match), or state that it is creating the
        # very first version (If-None-Match: *). This is what prevents
        # two open windows from silently overwriting each other.
        if_match = self.headers.get("If-Match")
        if_none_match = self.headers.get("If-None-Match")

        with write_lock:
            exists = os.path.exists(DATA_FILE)
            if exists:
                if if_match != file_etag(DATA_FILE):
                    self._send(409, b'{"error":"conflict"}')
                    return
            else:
                if if_none_match != "*":
                    self._send(428, b'{"error":"precondition-required"}')
                    return
            save_blob(body)
            new_etag = file_etag(DATA_FILE)
        self._send(200, b'{"ok":true}', extra={"ETag": new_etag})


def idle_watchdog(server):
    """Shut the server down after IDLE_EXIT_SECONDS with no requests."""
    while True:
        time.sleep(60)
        if time.monotonic() - last_request_time > IDLE_EXIT_SECONDS:
            threading.Thread(target=server.shutdown, daemon=True).start()
            return


def parent_watchdog(server):
    """Exit if our parent process (the native app) goes away.

    When the app is force-quit or crashes it cannot stop us, and in embedded
    mode the idle watchdog is off — so without this an orphaned server would
    keep holding the port forever. When the parent dies we are reparented to
    launchd (PID 1), which we detect and use as the signal to shut down.
    """
    while True:
        time.sleep(2)
        if os.getppid() == 1:
            threading.Thread(target=server.shutdown, daemon=True).start()
            return


def already_running():
    """True if another Agenda instance answers on our port."""
    try:
        with urllib.request.urlopen("http://%s:%d/api/ping" % (HOST, PORT), timeout=2) as r:
            return r.read().strip() == PING_RESPONSE
    except OSError:
        return False


def create_server():
    """Prepare the data directory and bind the server socket.

    Returns the server object (not yet serving); raises OSError if the port
    is already taken, or if the data directory cannot be created. main()
    serves it in the foreground; the only difference between the standalone
    and --embedded modes is which shutdown watchdog runs (idle vs. parent).
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    return ThreadingHTTPServer((HOST, PORT), Handler)


def main():
    # In embedded mode (spawned by the native app) the window's lifetime
    # controls shutdown, so the idle watchdog is replaced by a parent-process
    # watchdog — it must not exit while a window is open-but-idle, but it must
    # exit if the app that owns it dies.
    embedded = "--embedded" in sys.argv

    # Create the data directory first, so a "folder not writable" problem is
    # reported clearly instead of being mistaken for "port occupied" below.
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)
    except OSError as e:
        print("Errore: impossibile creare la cartella dati '%s': %s" % (DATA_DIR, e))
        sys.exit(1)

    try:
        server = create_server()
    except OSError:
        if already_running():
            sys.exit(0)  # another Agenda instance is already up: nothing to do
        print("Errore: la porta %d è occupata da un altro programma." % PORT)
        print("Chiudi quel programma e riprova ad avviare Agenda.")
        sys.exit(1)

    watchdog = parent_watchdog if embedded else idle_watchdog
    threading.Thread(target=watchdog, args=(server,), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
