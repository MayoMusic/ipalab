"""Extraction of property lists embedded inside larger binary blobs.

Apple's ``embedded.mobileprovision`` is a DER-encoded PKCS#7 ``SignedData``
structure whose encapsulated payload is a property list.  Decoding CMS
properly needs a full ASN.1 stack, but the property list is self-describing,
so we locate it directly and hand the bytes to the standard library.

Both the binary (``bplist00``) and XML representations are supported.
"""

from __future__ import annotations

import plistlib
from typing import Any, Optional

_BPLIST_MAGIC = b"bplist00"

# A binary property list ends with a fixed 32 byte trailer:
#   4 unused | 1 unused | 1 sortVersion | 1 offsetIntSize | 1 objectRefSize
#   | 8 numObjects | 8 topObject | 8 offsetTableOffset
_TRAILER_SIZE = 32
_MAX_SCAN = 1024 * 1024


def extract_plist(data: bytes) -> Optional[Any]:
    """Return the decoded property list embedded in ``data``.

    Returns ``None`` when no property list can be located or decoded.
    """
    parsed = _extract_binary(data)
    if parsed is not None:
        return parsed
    return _extract_xml(data)


def _extract_binary(data: bytes) -> Optional[Any]:
    start = data.find(_BPLIST_MAGIC)
    if start == -1:
        return None
    end = _binary_plist_end(data, start)
    if end is None:
        return None
    try:
        return plistlib.loads(data[start:end])
    except Exception:
        return None


def _binary_plist_end(data: bytes, start: int) -> Optional[int]:
    """Find the exact end offset of the binary plist beginning at ``start``.

    The plist is *not* assumed to be the final bytes of the blob - in a
    ``SignedData`` structure the signature follows it.  Instead we walk
    backwards looking for a 32 byte trailer that is self-consistent with the
    offset table sitting directly before it.
    """
    lowest = max(start + 8 + _TRAILER_SIZE, len(data) - _MAX_SCAN)
    for end in range(len(data), lowest, -1):
        trailer_at = end - _TRAILER_SIZE
        if trailer_at < start:
            break
        offset_int_size = data[trailer_at + 6]
        object_ref_size = data[trailer_at + 7]
        if not (1 <= offset_int_size <= 8 and 1 <= object_ref_size <= 8):
            continue
        num_objects = int.from_bytes(data[trailer_at + 8 : trailer_at + 16], "big")
        table_offset = int.from_bytes(data[trailer_at + 24 : trailer_at + 32], "big")
        if num_objects == 0 or num_objects > 1_000_000:
            continue
        # The offset table is the last thing before the 32 byte trailer.
        if start + table_offset + (num_objects * offset_int_size) == trailer_at:
            return end
    return None


def _extract_xml(data: bytes) -> Optional[Any]:
    start = data.find(b"<?xml")
    if start == -1:
        start = data.find(b"<plist")
    if start == -1:
        return None
    end = data.find(b"</plist>", start)
    if end == -1:
        return None
    try:
        return plistlib.loads(data[start : end + len(b"</plist>")])
    except Exception:
        return None
