"""Shared fixtures.

Everything is generated in-memory so the suite carries no binary blobs and
stays readable and diffable.
"""

from __future__ import annotations

import plistlib
import struct
import zipfile

import pytest

CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64 = 0x0100000C

MH_MAGIC_64 = 0xFEEDFACF
LC_LOAD_DYLIB = 0x0C
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO_64 = 0x2C
MH_PIE = 0x200000
MH_EXECUTE = 2
FAT_MAGIC = 0xCAFEBABE


def _pad_eight(payload: bytes) -> bytes:
    return payload + b"\x00" * ((-len(payload)) % 8)


def build_macho(
    cpu_type: int = CPU_TYPE_ARM64,
    cpu_subtype: int = 0,
    filetype: int = MH_EXECUTE,
    dylibs=(),
    code_signed: bool = True,
    encrypted: bool = False,
    pie: bool = True,
    endian: str = "<",
) -> bytes:
    """Build a structurally valid 64-bit Mach-O image."""
    commands = []

    for name in dylibs:
        encoded = name.encode("utf-8") + b"\x00"
        body = _pad_eight(encoded)
        header = struct.pack(
            endian + "IIIIII", LC_LOAD_DYLIB, 24 + len(body), 24, 0, 0x10000, 0x10000
        )
        commands.append(header + body)

    if code_signed:
        commands.append(struct.pack(endian + "IIII", LC_CODE_SIGNATURE, 16, 0, 0))

    if encrypted:
        commands.append(
            struct.pack(endian + "IIIIII", LC_ENCRYPTION_INFO_64, 24, 0, 4096, 1, 0)
        )

    payload = b"".join(commands)
    flags = MH_PIE if pie else 0

    header = struct.pack(
        endian + "IiiIIIII",
        MH_MAGIC_64,
        cpu_type,
        cpu_subtype,
        filetype,
        len(commands),
        len(payload),
        flags,
        0,
    )
    return header + payload


def build_fat(slices, align: int = 2) -> bytes:
    """Wrap prebuilt Mach-O slices in a universal container."""
    entries = b""
    body = b""
    offset = 8 + 20 * len(slices)
    granularity = 1 << align

    for blob in slices:
        entries += struct.pack(">IIIII", 0, 3, offset, len(blob), align)
        body += b"\x00" * ((-offset) % granularity)
        body += blob
        offset = 8 + 20 * len(slices) + len(body)

    return struct.pack(">II", FAT_MAGIC, len(slices)) + entries + body


def build_profile(entitlements=None) -> bytes:
    """Build a CMS-ish wrapper around a binary property list."""
    profile = {
        "AppIDName": "Demo",
        "Entitlements": entitlements if entitlements is not None else {
            "application-identifier": "ABCDE12345.com.example.demo",
            "get-task-allow": False,
            "keychain-access-groups": ["ABCDE12345.*"],
        },
        "Name": "Demo Profile",
        "TeamIdentifier": ["ABCDE12345"],
    }
    payload = plistlib.dumps(profile, fmt=plistlib.FMT_BINARY)
    # A realistic file has opaque DER before the payload and a signature after.
    return b"\x30\x82\x0a\x60\x06\x09" + b"\xa5\x00" * 16 + payload + b"\x00" * 48 + bytes(range(256))


def default_info(**overrides) -> dict:
    info = {
        "CFBundleIdentifier": "com.example.demo",
        "CFBundleName": "Demo",
        "CFBundleDisplayName": "Demo App",
        "CFBundleShortVersionString": "1.4.2",
        "CFBundleVersion": "77",
        "CFBundleExecutable": "Demo",
        "MinimumOSVersion": "15.0",
        "DTSDKName": "iphoneos17.4",
        "DTPlatformName": "iphoneos",
        "UIDeviceFamily": [1, 2],
    }
    info.update(overrides)
    return info


def build_ipa(
    path,
    info=None,
    macho=None,
    profile=None,
    include_profile: bool = True,
    include_code_resources: bool = True,
) -> str:
    """Assemble a synthetic .ipa on disk and return its path."""
    bundle = "Demo.app"
    prefix = f"Payload/{bundle}"

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            f"{prefix}/Info.plist",
            plistlib.dumps(info if info is not None else default_info()),
        )
        archive.writestr(
            f"{prefix}/Demo",
            macho if macho is not None else build_macho(dylibs=["/usr/lib/libSystem.B.dylib"]),
        )
        if include_profile:
            archive.writestr(
                f"{prefix}/embedded.mobileprovision",
                profile if profile is not None else build_profile(),
            )
        if include_code_resources:
            archive.writestr(f"{prefix}/_CodeSignature/CodeResources", b"<plist/>")
        archive.writestr(f"{prefix}/PkgInfo", "APPL????")
    return str(path)


@pytest.fixture
def valid_ipa(tmp_path):
    """A well-formed archive with no findings."""
    return build_ipa(tmp_path / "demo.ipa")


@pytest.fixture
def unsigned_ipa(tmp_path):
    return build_ipa(tmp_path / "unsigned.ipa", macho=build_macho(code_signed=False, pie=False))


@pytest.fixture
def not_an_ipa(tmp_path):
    path = tmp_path / "broken.ipa"
    path.write_bytes(b"this is definitely not a zip file")
    return str(path)
