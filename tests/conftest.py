"""Ensure the engine is bootstrapped before any tests run.

Importing src.server triggers module-level bootstrap_extensions(),
which populates the global LUA_ENGINE singleton with all core functions.
"""

import src.server  # noqa: F401
