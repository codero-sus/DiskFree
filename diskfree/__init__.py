"""DiskFree: an AI powered disk manager and cleaner. Safe and efficient.

The package is organised as a small pipeline:

``scanner``  -- read-only filesystem analysis that produces *findings*.
``safety``   -- policy guardrails plus a reversible trash/quarantine store.
``ai``       -- local LLM providers (Cortex LLMHoster, Ollama) and the advisor.
``actions``  -- the only code path that can modify the filesystem.
``api``      -- FastAPI routes and the bundled WebUI, served by uvicorn.

Nothing outside :mod:`diskfree.actions` is allowed to remove a file, and that
module only ever moves data into a journal-backed quarantine unless permanent
deletion has been explicitly enabled and confirmed.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
