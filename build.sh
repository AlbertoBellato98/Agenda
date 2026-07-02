#!/bin/zsh
# Build Agenda.app — a native macOS application.
#
# Compiles the Swift GUI (src/AgendaApp.swift) into a real binary and
# assembles a self-contained .app bundle: the compiled binary plus the
# Python backend (server.py) and the web interface (app/) in Resources.
# User data lives in ~/Documents/Agenda, outside the bundle.
#
# Run from the project root:  ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

# --- Preflight: fail early with a clear message if a tool is missing. ---
if ! command -v swiftc >/dev/null 2>&1; then
    echo "✗ swiftc not found. Install the Xcode Command Line Tools:" >&2
    echo "    xcode-select --install" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "✗ python3 not found. Install Python 3 (python.org or Homebrew)." >&2
    exit 1
fi

APP="Agenda.app"
CONTENTS="$APP/Contents"

echo "› Compiling Swift…"
rm -rf build "$APP"
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources"

swiftc -O src/AgendaApp.swift -o "$CONTENTS/MacOS/Agenda" \
    -framework Cocoa -framework WebKit

echo "› Assembling bundle…"
cp Info.plist "$CONTENTS/Info.plist"
cp server.py "$CONTENTS/Resources/server.py"
cp -R app "$CONTENTS/Resources/app"
if [ -f Agenda.icns ]; then
    cp Agenda.icns "$CONTENTS/Resources/Agenda.icns"
else
    echo "  ⚠ Agenda.icns not found — the app will use the generic icon."
fi

# Ad-hoc code signature so the app has a stable local identity and launches
# without a Gatekeeper prompt. Single Mach-O, no nested code, so no --deep.
# Let stderr through: a signing failure should be visible, not swallowed.
echo "› Signing (ad-hoc)…"
if ! codesign --force --sign - "$APP"; then
    echo "  ⚠ Code signing failed; the app may prompt on first launch." >&2
fi

echo "✓ Built $APP"
echo "  Double-click Agenda.app, or run:  open $APP"
