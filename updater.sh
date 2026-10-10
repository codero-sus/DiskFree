#!/usr/bin/env bash
#
# DiskFree updater -- Linux and macOS.
#
# A thin launcher: all the logic lives in diskfree/updater.py, which uses nothing
# but the standard library so that it can run even when DiskFree's dependencies
# are missing or broken. That also means this works on a fresh clone, before
# anything has been installed.
#
#   ./updater.sh                  fetch, fast-forward, refresh dependencies
#   ./updater.sh --check          fetch remote refs; leave checkout/dependencies untouched
#   ./updater.sh --show-python    which interpreter would be used, and why
#   ./updater.sh --branch X       follow a branch other than the default
#   ./updater.sh --no-deps        update the code only
#   ./updater.sh --json           machine-readable report
#   ./updater.sh --help           every option
#
# Which interpreter is used, first usable one wins:
#
#   1. $DISKFREE_PYTHON
#   2. python.env in the project root -- keys DISKFREE_PYTHON, PYTHON, 2PY2
#   3. $2PY2            "second python": portable / embeddable / pyenv builds
#   4. .venv/bin/python or venv/bin/python inside the project
#   5. python3 (then python3.13 … python3.11, python) from PATH
#   6. /opt/homebrew/bin/python3, /usr/local/bin/python3, /usr/bin/python3
#
# python.env is parsed, not sourced: `2PY2` is not a valid shell identifier, and
# the same file has to work for updater.bat on Windows. A relative path in it is
# taken relative to this project, so a portable Python can travel with the
# checkout (e.g. `2PY2=../python-runtime/bin/python3`). On Linux/macOS, `%ROOT%`,
# `$ROOT` and a leading `~` are also expanded.
#
# Updates are taken from origin/arena/0392f96c-diskfree (DiskFree's development
# branch) unless --branch says otherwise; diskfree/updater.py owns that decision.
#
# Exit codes: 0 up to date or updated, 1 something failed, 2 bad usage,
#             127 no usable Python interpreter.
#
# This script never discards local changes, never deletes files, and never runs
# the cleaner. Updating DiskFree cannot become a way of running it.
#
# Written for bash 3.2 (the version macOS ships): no associative arrays, no
# ${var,,}, no &>>.

set -euo pipefail

PYTHON_ENV_FILE="python.env"
TWO_PY_TWO="2PY2"
REQUIRED_PYTHON_CHECK='import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)'

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

# --- python.env ------------------------------------------------------------
# $1 = key name. Prints the value (empty when the key is absent). Keys are
# matched case-insensitively; comments, `export`/`set` prefixes, surrounding
# quotes and CRLF line endings are all tolerated.
python_env_value() {
    wanted="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
    envfile="$ROOT/$PYTHON_ENV_FILE"
    [ -f "$envfile" ] || return 0
    found=""

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        while [ "${line#[[:space:]]}" != "$line" ]; do line="${line#[[:space:]]}"; done
        while [ "${line%[[:space:]]}" != "$line" ]; do line="${line%[[:space:]]}"; done
        case "$line" in '' | '#'* | ';'* | '@'* | rem\ * | REM\ * | Rem\ *) continue ;; esac
        case "$line" in
            export\ * | Export\ * | EXPORT\ *) line="${line#* }" ;;
            set\ * | Set\ * | SET\ *) line="${line#* }" ;;
        esac
        # Also accept Windows-style `set "KEY=value"` / `export "KEY=value"`.
        case "$line" in
            '"'*'"' | "'"*"'")
                line="${line#?}"
                line="${line%?}"
                ;;
        esac
        case "$line" in
            *=*)
                key="${line%%=*}"
                value="${line#*=}"
                ;;
            *)
                # A one-line file containing only a path is the simple format;
                # treat it as the PYTHON key. Key=value lines remain supported.
                [ "$wanted" = "PYTHON" ] || continue
                key="PYTHON"
                value="$line"
                ;;
        esac
        while [ "${key%[[:space:]]}" != "$key" ]; do key="${key%[[:space:]]}"; done
        while [ "${value#[[:space:]]}" != "$value" ]; do value="${value#[[:space:]]}"; done
        while [ "${value%[[:space:]]}" != "$value" ]; do value="${value%[[:space:]]}"; done
        # one layer of surrounding quotes, either kind (a lone quote does not
        # match, so `"` alone is left as it is)
        case "$value" in
            '"'*'"' | "'"*"'")
                value="${value#?}"
                value="${value%?}"
                ;;
        esac

        upper="$(printf '%s' "$key" | tr '[:lower:]' '[:upper:]')"
        [ "$upper" = "$wanted" ] || continue
        [ -n "$value" ] || continue
        found="$value"
    done < "$envfile"
    printf '%s' "$found"
    return 0
}

# Turn a python.env value into something executable: %ROOT%/$ROOT/~ expansion,
# relative paths anchored at the project, bare names looked up on PATH.
resolve_interpreter() {
    value="$1"
    value="${value//%ROOT%/$ROOT}"
    value="${value//\$\{ROOT\}/$ROOT}"
    value="${value//\$ROOT/$ROOT}"
    case "$value" in
        '~') value="$HOME" ;;
        '~/'*) value="$HOME/${value#\~/}" ;;
    esac
    case "$value" in
        /*) printf '%s' "$value" ;;
        */*) printf '%s' "$ROOT/$value" ;;
        *)
            if [ -x "$ROOT/$value" ]; then
                printf '%s' "$ROOT/$value"
            else
                command -v "$value" 2>/dev/null || printf '%s' "$value"
            fi
            ;;
    esac
}

# --- which Python? ---------------------------------------------------------
PYTHON=""
PYTHON_SOURCE=""

# $1 = interpreter, $2 = where it came from. Records the first usable one and
# says out loud when a configured interpreter had to be skipped.
try_python() {
    interpreter="$1"
    origin="$2"
    [ -n "$interpreter" ] || return 1
    if "$interpreter" -c "$REQUIRED_PYTHON_CHECK" >/dev/null 2>&1; then
        PYTHON="$interpreter"
        PYTHON_SOURCE="$origin"
        return 0
    fi
    say "note: $origin ('$interpreter') is not a usable Python 3.11+; trying the next candidate."
    return 1
}

pick_python() {
    # 1. DISKFREE_PYTHON, the environment variable DiskFree documents everywhere
    if [ -n "${DISKFREE_PYTHON:-}" ]; then
        try_python "$(resolve_interpreter "$DISKFREE_PYTHON")" "DISKFREE_PYTHON (environment)" && return 0
    fi

    # 2. python.env next to this script
    for key in DISKFREE_PYTHON PYTHON "$TWO_PY_TWO"; do
        value="$(python_env_value "$key")"
        [ -n "$value" ] || continue
        try_python "$(resolve_interpreter "$value")" "$PYTHON_ENV_FILE ($key)" && return 0
    done

    # 3. $2PY2. bash cannot expand "$2PY2" (that is $2 followed by "PY2"), and
    #    `2PY2=...` is not a valid identifier, so printenv reads it. It can be
    #    set by `env 2PY2=... ./updater.sh`, a .desktop file, systemd or Windows.
    value="$(printenv "$TWO_PY_TWO" 2>/dev/null || true)"
    if [ -n "$value" ]; then
        try_python "$(resolve_interpreter "$value")" "$TWO_PY_TWO (environment)" && return 0
    fi

    # 4. a virtualenv inside the project
    for candidate in "$ROOT/.venv/bin/python" "$ROOT/venv/bin/python" \
                     "$ROOT/.venv/bin/python3" "$ROOT/venv/bin/python3"; do
        [ -x "$candidate" ] || continue
        try_python "$candidate" "virtualenv inside the project" && return 0
    done

    # 5. PATH
    for name in python3 python3.13 python3.12 python3.11 python; do
        found="$(command -v "$name" 2>/dev/null || true)"
        [ -n "$found" ] || continue
        try_python "$found" "PATH ($name)" && return 0
    done

    # 6. the usual absolute locations (Homebrew on both macOS architectures,
    #    then the system Python) for when PATH is minimal
    for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
        [ -x "$candidate" ] || continue
        try_python "$candidate" "$candidate" && return 0
    done

    return 1
}

if ! pick_python; then
    say "error: no usable Python 3.11+ interpreter found."
    say ""
    say "       Linux (Debian/Ubuntu):  sudo apt install python3 python3-venv python3-pip"
    say "       Linux (Fedora):         sudo dnf install python3 python3-pip"
    say "       macOS (Homebrew):       brew install python@3.12"
    say "       macOS (official):       https://www.python.org/downloads/macos/"
    say ""
    say "       Then point DiskFree at it in any of these ways:"
    say "         echo '2PY2=/path/to/python3' > $ROOT/$PYTHON_ENV_FILE"
    say "         DISKFREE_PYTHON=/path/to/python3 ./updater.sh"
    say "         env 2PY2=/path/to/python3 ./updater.sh"
    say "         ./updater.sh --python /path/to/python3"
    exit 127
fi

# --- run -------------------------------------------------------------------
# exec so signals and the exit code belong to the updater, not this wrapper.
# The updater resolves the interpreter again, by the same rules, and reports
# which one it chose -- so pip and the import check always target it.
if [ -n "${DISKFREE_DEBUG:-}" ]; then
    say "debug: launcher is using $PYTHON (from $PYTHON_SOURCE)"
fi
exec "$PYTHON" "$UPDATER" --root "$ROOT" "$@"
