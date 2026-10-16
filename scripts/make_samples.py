"""Generate synthetic sample archives for a quick manual smoke test.

This is a development helper, not part of the package. Run it with:

    python -m pip install -e ".[dev]"
    python scripts/make_samples.py
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tests"))

from conftest import build_fat, build_ipa, build_macho, default_info  # noqa: E402


def main() -> int:
    out = os.path.join(os.path.dirname(HERE), "samples")
    os.makedirs(out, exist_ok=True)

    build_ipa(os.path.join(out, "Reader.ipa"))
    build_ipa(
        os.path.join(out, "Universal.ipa"),
        macho=build_fat([build_macho(), build_macho(cpu_type=0x01000007)]),
    )
    build_ipa(
        os.path.join(out, "Unsigned.ipa"),
        macho=build_macho(code_signed=False, pie=False),
    )
    build_ipa(os.path.join(out, "Encrypted.ipa"), macho=build_macho(encrypted=True))

    legacy = default_info(CFBundleIdentifier="com.example.legacy", DTSDKName="iphoneos12.1")
    legacy.pop("MinimumOSVersion")
    build_ipa(os.path.join(out, "Legacy.ipa"), info=legacy)

    for name in sorted(os.listdir(out)):
        print("built", os.path.join("samples", name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
