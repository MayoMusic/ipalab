"""A small, defensive Mach-O header reader.

Only as much of the format is decoded as is needed to describe an executable:
its architectures, whether it carries a code signature, whether its pages are
FairPlay encrypted, and whether it is position independent.

Malformed or truncated input raises :class:`MachOError` rather than yielding a
half-populated structure, so callers can report a problem instead of guessing.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

# Universal ("fat") container magics, read big-endian first.
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

# Per-slice magics.
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

MH_PIE = 0x200000

MH_EXECUTE = 2
MH_DYLIB = 6
MH_BUNDLE = 8

LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C

FILE_TYPES = {MH_EXECUTE: "executable", MH_DYLIB: "dylib", MH_BUNDLE: "bundle"}

_CPU_NAMES = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
    18: "ppc",
    0x01000012: "ppc64",
}

_ARM_SUBTYPES = {6: "armv6", 9: "armv7", 11: "armv7s"}
_ARM64_SUBTYPES = {0: "arm64", 1: "arm64v8", 2: "arm64e"}

_FAT_HEADER_SIZE = 8
_FAT_ENTRY_SIZE = 32
_FAT_ENTRY_SIZE_32 = 20
_SANE_FAT_SLICES = 64


class MachOError(ValueError):
    """Raised when a buffer cannot be interpreted as Mach-O."""


@dataclass(frozen=True)
class Slice:
    """One architecture within a possibly universal binary."""

    arch: str
    filetype: str
    is_64_bit: bool
    pie: bool
    encrypted: bool
    code_signed: bool
    linked_libraries: Tuple[str, ...]
    offset: int
    size: int


@dataclass(frozen=True)
class Binary:
    """A parsed Mach-O file, universal or single-architecture."""

    is_fat: bool
    slices: Tuple[Slice, ...]

    @property
    def architectures(self) -> Tuple[str, ...]:
        return tuple(s.arch for s in self.slices)

    @property
    def code_signed(self) -> bool:
        return any(s.code_signed for s in self.slices)

    @property
    def encrypted(self) -> bool:
        return any(s.encrypted for s in self.slices)

    @property
    def pie(self) -> bool:
        return bool(self.slices) and all(s.pie for s in self.slices)


def parse(data: bytes) -> Binary:
    """Parse ``data`` as a Mach-O image."""
    if len(data) < 4:
        raise MachOError("file is too small to contain a Mach-O header")
    (big_endian_magic,) = struct.unpack_from(">I", data, 0)
    if big_endian_magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64):
        return _parse_fat(data, big_endian_magic)
    return Binary(is_fat=False, slices=(_parse_slice(data, 0, len(data)),))


def _parse_fat(data: bytes, magic: int) -> Binary:
    big = magic in (FAT_MAGIC, FAT_MAGIC_64)
    is_64 = magic in (FAT_MAGIC_64, FAT_CIGAM_64)
    endian = ">" if big else "<"
    entry_size = _FAT_ENTRY_SIZE if is_64 else _FAT_ENTRY_SIZE_32

    (count,) = struct.unpack_from(endian + "I", data, 4)
    if count == 0 or count > _SANE_FAT_SLICES:
        raise MachOError(f"implausible fat architecture count: {count}")
    if len(data) < _FAT_HEADER_SIZE + count * entry_size:
        raise MachOError("fat header is truncated")

    slices = []
    for index in range(count):
        entry_at = _FAT_HEADER_SIZE + index * entry_size
        if is_64:
            _cpu, _sub, offset, size, _align, _res = struct.unpack_from(
                endian + "IIQQII", data, entry_at
            )
        else:
            _cpu, _sub, offset, size, _align = struct.unpack_from(
                endian + "IIIII", data, entry_at
            )
        if offset + size > len(data):
            raise MachOError(f"architecture {index} extends past the end of the file")
        slices.append(_parse_slice(data, offset, size))
    return Binary(is_fat=True, slices=tuple(slices))


def _parse_slice(data: bytes, offset: int, size: int) -> Slice:
    if size < 28 or offset + 28 > len(data):
        raise MachOError("architecture slice is truncated")

    (native_magic,) = struct.unpack_from("<I", data, offset)
    if native_magic in (MH_MAGIC, MH_MAGIC_64):
        endian, is_64 = "<", native_magic == MH_MAGIC_64
    elif native_magic in (MH_CIGAM, MH_CIGAM_64):
        endian, is_64 = ">", native_magic == MH_CIGAM_64
    else:
        raise MachOError(f"unrecognised Mach-O magic 0x{native_magic:08x}")

    if is_64:
        _m, cpu, sub, filetype, ncmds, sizeofcmds, flags, _res = struct.unpack_from(
            endian + "IiiIIIII", data, offset
        )
    else:
        _m, cpu, sub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            endian + "IiiIIII", data, offset
        )

    header_size = 32 if is_64 else 28
    pos = offset + header_size
    commands_end = pos + sizeofcmds
    if commands_end > offset + size:
        raise MachOError("load commands extend past the end of the slice")

    encrypted = False
    code_signed = False
    libraries = []

    for _ in range(ncmds):
        if pos + 8 > commands_end:
            raise MachOError("load command table is truncated")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, pos)
        if cmdsize < 8 or pos + cmdsize > commands_end:
            raise MachOError("load command declares an invalid size")

        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            if pos + 20 <= commands_end:
                (cryptid,) = struct.unpack_from(endian + "I", data, pos + 16)
                encrypted = encrypted or cryptid != 0
        elif cmd == LC_CODE_SIGNATURE:
            code_signed = True
        elif cmd in (LC_LOAD_DYLIB, LC_ID_DYLIB):
            if pos + 12 <= commands_end:
                (name_offset,) = struct.unpack_from(endian + "I", data, pos + 8)
                name = _read_cstring(data, pos + name_offset, pos + cmdsize)
                if name:
                    libraries.append(name)

        pos += cmdsize

    return Slice(
        arch=_arch_name(cpu, sub),
        filetype=FILE_TYPES.get(filetype, f"type-{filetype}"),
        is_64_bit=is_64,
        pie=bool(flags & MH_PIE),
        encrypted=encrypted,
        code_signed=code_signed,
        linked_libraries=tuple(libraries),
        offset=offset,
        size=size,
    )


def _read_cstring(data: bytes, start: int, end: int) -> Optional[str]:
    if start >= end or start >= len(data):
        return None
    limit = min(end, len(data))
    stop = data.find(b"\x00", start, limit)
    if stop == -1:
        stop = limit
    return data[start:stop].decode("utf-8", "replace")


def _arch_name(cpu_type: int, cpu_subtype: int) -> str:
    base = _CPU_NAMES.get(cpu_type & 0xFFFFFFFF, f"cpu-{cpu_type & 0xFFFFFFFF}")
    subtype = cpu_subtype & 0x00FFFFFF
    if base == "arm64":
        return _ARM64_SUBTYPES.get(subtype, "arm64")
    if base == "arm":
        return _ARM_SUBTYPES.get(subtype, "arm")
    return base
