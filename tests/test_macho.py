"""Tests for Mach-O header parsing."""

from __future__ import annotations

import pytest

from conftest import (
    CPU_TYPE_X86_64,
    MH_EXECUTE,
    build_fat,
    build_macho,
)
from ipalab import macho


def test_single_slice_reports_architecture():
    binary = macho.parse(build_macho())

    assert not binary.is_fat
    assert binary.architectures == ("arm64",)
    assert binary.code_signed
    assert binary.pie
    assert not binary.encrypted
    assert binary.slices[0].filetype == "executable"
    assert binary.slices[0].is_64_bit


def test_arm64e_subtype_is_named():
    blob = build_macho(cpu_subtype=2)
    assert macho.parse(blob).architectures == ("arm64e",)


def test_x86_64_slice():
    blob = build_macho(cpu_type=CPU_TYPE_X86_64)
    assert macho.parse(blob).architectures == ("x86_64",)


def test_linked_libraries_are_decoded():
    blob = build_macho(dylibs=["/usr/lib/libSystem.B.dylib", "/usr/lib/libz.dylib"])
    assert list(macho.parse(blob).slices[0].linked_libraries) == [
        "/usr/lib/libSystem.B.dylib",
        "/usr/lib/libz.dylib",
    ]


def test_fat_container_lists_every_slice():
    blob = build_fat([build_macho(), build_macho(cpu_type=CPU_TYPE_X86_64)])
    binary = macho.parse(blob)

    assert binary.is_fat
    assert binary.architectures == ("arm64", "x86_64")
    assert binary.code_signed


def test_encryption_flag_is_read():
    assert macho.parse(build_macho(encrypted=True)).encrypted


def test_missing_pie_and_signature():
    binary = macho.parse(build_macho(code_signed=False, pie=False))

    assert not binary.code_signed
    assert not binary.pie


def test_empty_input_is_rejected():
    with pytest.raises(macho.MachOError):
        macho.parse(b"")


def test_random_bytes_are_rejected():
    with pytest.raises(macho.MachOError):
        macho.parse(b"\x01\x02\x03\x04\x05\x06\x07\x08" * 8)


def test_truncated_header_is_rejected():
    with pytest.raises(macho.MachOError):
        macho.parse(build_macho()[:12])


def test_dylib_filetype_is_named():
    blob = build_macho(filetype=6)
    assert macho.parse(blob).slices[0].filetype == "dylib"


def test_bundle_filetype_is_named():
    blob = build_macho(filetype=8)
    assert macho.parse(blob).slices[0].filetype == "bundle"


def test_macho_error_is_a_value_error():
    assert issubclass(macho.MachOError, ValueError)
    assert macho.MH_EXECUTE == MH_EXECUTE
