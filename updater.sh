#!/usr/bin/env bash
#
# DiskFree updater -- Linux and macOS.
#
# A thin launcher: all the logic lives in diskfree/updater.py, which uses nothing
# but the standard library so that it can run even when DiskFree's dependencies
# are missing or broken. That also means this works on a fresh clone, before
# anything has been installed.
#
#   ./updater.sh                 fetch, fast-forward, refresh dependencies
#   ./updater.sh --check         report what would change, modify nothing
#   ./updater.sh --branch main   follow a specific branch
#   ./updater.sh --no-deps       update the code only
#   ./updater.sh --json          machine-readable report
#   ./updater.sh --help          every option
#
# Environment:
#   DISKFREE_PYTHON   interpreter to use (default: .venv/bin/python, then python3)
#
# Exit codes: 0 up to date or updated, 1 something failed, 2 bad usage,
#             127 no usable Python interpreter.
#
# This script never discards local changes, never deletes files, and never runs
# the cleaner. Updating DiskFree cannot become a way of running it.

set -euo pipefail

# --- where are we? ---------------------------------------------------------
# Resolve symlinks so the updater works from a link in ~/bin.
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
ROOT="$(cd -P "$(dirname "$SOURCE")" && pwd)"
UPDATER="$ROOT/diskfree/updater.py"

say() { printf '%s\n' "$*" >&2; }

if [ ! -f "$UPDATER" ]; then
    say "error: cannot find $UPDATER"
    say "       Run this script from the root of a DiskFree checkout."
    exit 2
fi

# --- which Python? ---------------------------------------------------------
pick_python() {
    if [ -n "${DISKFREE_PYTHON:-}" ]; then
        printf '%s' "$DISKFREE_PYTHON"
        return 0
    fi
    for candidate in "$ROOT/.venv/bin/python" "$ROOT/venv/bin/python"; do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    for name in python3 python3.13 python3.12 python3.11 python; do
        if command -v "$name" >/dev/null 2>&1; then
            printf '%s' "$(command -v "$name")"
            return 0
        fi
    done
    return 1
}

if ! PYTHON="$(pick_python)"; then
    say "error: no Python interpreter found."
    say "       DiskFree needs Python 3.11 or newer. On Debian/Ubuntu:"
    say "           sudo apt install python3 python3-venv python3-pip"
    say "       on macOS: brew install python@3.12"
    say "       Then re-run, optionally as: DISKFREE_PYTHON=/path/to/python3 ./updater.sh"
    exit 127
fi

if [ ! -x "$PYTHON" ] && ! command -v "$PYTHON" >/dev/null 2>&1; then
    say "error: DISKFREE_PYTHON='$PYTHON' is not executable."
    exit 127
fi

# --- run -------------------------------------------------------------------
# exec so signals and the exit code belong to the updater, not this wrapper.
exec "$PYTHON" "$UPDATER" --root "$ROOT" "$@"
