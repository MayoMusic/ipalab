"""Entry point for the PyInstaller build.

Kept as a separate absolute-import shim so the frozen executable has a single,
unambiguous module to start from.
"""

from ipalab.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
