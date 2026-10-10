#!/usr/bin/env python3
"""Launch the DiskFree WebUI with uvicorn.

    python run.py                        # http://127.0.0.1:8790
    python run.py --host 0.0.0.0 --port 8790
    DISKFREE_PROVIDER=ollama python run.py

Equivalent to ``python -m diskfree serve`` or the ``diskfree`` console script.
"""

from __future__ import annotations

import sys

from diskfree.cli import main

if __name__ == "__main__":
    argv = ["serve", *sys.argv[1:]]
    raise SystemExit(main(argv))
