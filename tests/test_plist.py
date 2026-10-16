"""Tests for embedded property list extraction."""

from __future__ import annotations

import plistlib

from ipalab import plist as plist_util


def test_binary_plist_at_end_of_blob():
    payload = plistlib.dumps({"a": 1}, fmt=plistlib.FMT_BINARY)
    assert plist_util.extract_plist(payload) == {"a": 1}


def test_binary_plist_followed_by_trailing_signature():
    """The realistic CMS case: the plist is *not* the final bytes."""
    payload = plistlib.dumps({"Entitlements": {"x": True}}, fmt=plistlib.FMT_BINARY)
    blob = b"\x30\x82\x0a\x60\x06\x09" + b"\xa5" * 24 + payload + b"\x00" * 32 + bytes(range(64))

    assert plist_util.extract_plist(blob) == {"Entitlements": {"x": True}}


def test_binary_plist_with_der_prefix():
    payload = plistlib.dumps({"k": [1, 2, 3]}, fmt=plistlib.FMT_BINARY)
    blob = b"\xde\xad\xbe\xef" * 8 + payload

    assert plist_util.extract_plist(blob) == {"k": [1, 2, 3]}


def test_large_object_table():
    payload = plistlib.dumps({f"key{i}": i for i in range(500)}, fmt=plistlib.FMT_BINARY)
    blob = b"\x00" * 16 + payload
    assert plist_util.extract_plist(blob)[ "key499"] == 499


def test_xml_plist():
    payload = plistlib.dumps({"a": "b"}, fmt=plistlib.FMT_XML)
    assert plist_util.extract_plist(payload) == {"a": "b"}


def test_xml_plist_with_surrounding_bytes():
    xml = b'<?xml version="1.0"?><plist version="1.0"><dict><key>z</key>'
    xml += b"<integer>9</integer></dict></plist>"
    assert plist_util.extract_plist(b"\x99" * 10 + xml + b"\x77" * 10) == {"z": 9}


def test_no_plist_present():
    assert plist_util.extract_plist(b"\x00" * 512) is None


def test_empty_input():
    assert plist_util.extract_plist(b"") is None


def test_corrupt_binary_plist_returns_none():
    """A magic marker with a nonsense trailer must not raise."""
    blob = b"bplist00" + b"\xff" * 128
    assert plist_util.extract_plist(blob) is None
