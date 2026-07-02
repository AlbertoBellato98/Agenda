# Agenda

A small, private, **local‑only** desktop app for keeping client records and a
dated diary of notes for each one — with instant search across everything.

It is a real native macOS application (an `NSWindow` hosting a `WKWebView`,
compiled from Swift), **not** a browser tab. All data is encrypted on disk;
nothing ever leaves your Mac.

> The user interface is in Italian by design (it was built for an Italian
> user). The code and comments are in English.

## Highlights

- **Encrypted at rest.** Every client and note is encrypted in the browser
  engine with AES‑256‑GCM, using a key derived from your password via
  PBKDF2 (600,000 iterations). The local server only ever stores an opaque
  blob — it never sees your password or your data in clear text.
- **Password‑gated.** A password is set on first launch and required on every
  open. Forgetting it means the data is unrecoverable — that is the security
  property, not a bug.
- **Search‑first.** Type a client code, first name, last name, or any word
  from a note; a live dropdown narrows results as you type. Open with the
  arrow keys + Enter, a click, or the search button.
- **Auto‑lock** after 10 minutes idle, wiping the key and plaintext from memory.
- **Crash‑safe saves.** Atomic writes (temp file + `fsync` + `os.replace`) plus
  rolling and daily backups, so a bad write can never destroy your data.
- **Zero third‑party dependencies.** The backend is the Python standard library;
  the UI is plain HTML/CSS/JS using the browser‑native Web Crypto API; the app
  shell is a compiled Swift binary. No `pip`, no `npm`, no build frameworks.

## Architecture

```
Agenda.app  (native Swift binary)
   │  spawns
   ▼
server.py   (Python stdlib HTTP server on 127.0.0.1:8765)
   │  serves
   ▼
app/        (index.html + style.css + app.js)
   │  encrypts in the browser engine, then GET/PUT an opaque blob
   ▼
dati/       (agenda.dat + rolling/daily backups) — encrypted
```

The Swift app loads `http://127.0.0.1` because the Web Crypto API requires a
*secure context*, which `127.0.0.1` provides and `file://` does not. Closing
the window flushes any unsaved note to disk (an awaited save, no size cap),
then stops the server and quits — nothing is left running.

## Requirements

- macOS 11 or later
- The Swift compiler (`swiftc`, from the Xcode Command Line Tools) — to build
- Python 3 (standard library only) — to run

## Build & run

```sh
./build.sh          # compiles the Swift app and assembles Agenda.app
open Agenda.app     # or just double‑click it in Finder
```

`build.sh` produces a self‑contained `Agenda.app` (the compiled binary plus
`server.py` and `app/` in its Resources). Your data lives in
`~/Documents/Agenda/`, so it survives moving the app (e.g. into `/Applications`)
and the backups stay easy to find in Finder.

## Project layout

| Path            | What it is                                             |
|-----------------|--------------------------------------------------------|
| `src/AgendaApp.swift` | The native macOS app (window, menus, lifecycle) |
| `server.py`     | Local HTTP server: static files + encrypted‑blob store |
| `app/index.html`| The single‑page UI (three views + two dialogs)         |
| `app/style.css` | Dark, Notion‑like theme                                |
| `app/app.js`    | Crypto, state, search, saving — all client‑side        |
| `Info.plist`    | Bundle metadata                                        |
| `build.sh`      | Build script                                           |
| `LEGGIMI.txt`   | End‑user guide, in Italian                             |

## Data & backups

- `dati/agenda.dat` — your encrypted data.
- `dati/backups/` — automatic copies: up to 20 recent rolling backups (at most
  one every 5 minutes) plus one per day (`agenda-daily-*`), kept two weeks.

To restore a backup: quit the app, copy a file from `dati/backups/` over
`dati/agenda.dat`, and reopen. Backups open with the same password (except any
made *before* a password change, which use the old one).

## Security notes

- The password is never stored. A wrong password simply fails to decrypt.
- The server binds to `127.0.0.1` only (loopback), so it is not reachable from
  the network, and it validates every write is a well‑formed encrypted envelope.
- Two open windows cannot silently overwrite each other: writes use optimistic
  concurrency (ETag / `If-Match`), and a conflict blocks edits until reload.
