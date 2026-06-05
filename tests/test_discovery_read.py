"""Tests for the encoding-aware discovery read helpers (``_read``)."""

from __future__ import annotations

from pathlib import Path

import pytest

from licenseal.discovery._read import (
    ReadDiagnostic,
    collect_read_diagnostics,
    decode_text,
    load_json,
    load_toml,
    load_yaml,
    read_bytes,
    read_xml_bytes,
    record_parse_failure,
    record_walk_error,
)


class TestDecodeText:
    def test_plain_utf8(self, tmp_path: Path):
        # write_bytes (not write_text) to avoid Windows newline translation —
        # decode_text reads raw bytes and must not rewrite line endings.
        p = tmp_path / "f.txt"
        p.write_bytes(b"flask==3.0.0\n")
        assert decode_text(p) == "flask==3.0.0\n"

    def test_utf8_bom_stripped(self, tmp_path: Path):
        # A UTF-8 BOM must not survive into the first line (it would corrupt
        # the first token); utf-8-sig strips it.
        p = tmp_path / "f.txt"
        p.write_bytes("flask==3.0.0\n".encode("utf-8-sig"))
        decoded = decode_text(p)
        assert decoded == "flask==3.0.0\n"
        assert not decoded.startswith("﻿")

    def test_utf16_le_bom(self, tmp_path: Path):
        p = tmp_path / "f.txt"
        p.write_bytes(b"\xff\xfe" + "requests==2.28\n".encode("utf-16-le"))
        assert decode_text(p) == "requests==2.28\n"

    def test_utf16_be_bom(self, tmp_path: Path):
        p = tmp_path / "f.txt"
        p.write_bytes(b"\xfe\xff" + "requests==2.28\n".encode("utf-16-be"))
        assert decode_text(p) == "requests==2.28\n"

    def test_utf32_le_bom(self, tmp_path: Path):
        # UTF-32 LE BOM (ff fe 00 00) must be detected before UTF-16 LE
        # (ff fe), which it shares a prefix with.
        p = tmp_path / "f.txt"
        p.write_bytes("django==5.0\n".encode("utf-32"))  # codec writes the BOM
        assert decode_text(p) == "django==5.0\n"

    def test_latin1_fallback_recovers_ascii(self, tmp_path: Path):
        # Invalid UTF-8 (a stray Latin-1 byte) falls back to latin-1, which
        # never raises and preserves the ASCII content.
        p = tmp_path / "f.txt"
        p.write_bytes(b"# Jos\xe9\nflask==3.0.0\n")
        decoded = decode_text(p)
        assert "flask==3.0.0" in decoded

    def test_unreadable_returns_none(self, tmp_path: Path, monkeypatch):
        p = tmp_path / "f.txt"
        p.write_text("x\n", encoding="utf-8")

        def boom(self, *a, **k):
            raise OSError("denied")

        monkeypatch.setattr(Path, "read_bytes", boom)
        assert decode_text(p) is None


class TestReadXmlBytes:
    def test_returns_raw_bytes(self, tmp_path: Path):
        p = tmp_path / "pom.xml"
        p.write_bytes(b"<project/>")
        assert read_xml_bytes(p) == b"<project/>"

    def test_unreadable_returns_none(self, tmp_path: Path, monkeypatch):
        p = tmp_path / "pom.xml"
        p.write_bytes(b"<project/>")

        def boom(self, *a, **k):
            raise OSError("denied")

        monkeypatch.setattr(Path, "read_bytes", boom)
        assert read_xml_bytes(p) is None


class TestDiagnostics:
    def test_latin1_fallback_records_diagnostic(self, tmp_path: Path):
        p = tmp_path / "f.txt"
        p.write_bytes(b"# Jos\xe9\nflask==3.0.0\n")
        with collect_read_diagnostics() as diags:
            decode_text(p)
        assert len(diags) == 1
        assert diags[0].path == p
        assert "latin-1" in diags[0].reason
        # A latin-1 recovery keeps the ASCII deps — it is NOT a gap.
        assert diags[0].is_gap is False

    def test_unreadable_records_diagnostic(self, tmp_path: Path, monkeypatch):
        p = tmp_path / "f.txt"
        p.write_text("x\n", encoding="utf-8")

        def boom(self, *a, **k):
            raise OSError("denied")

        monkeypatch.setattr(Path, "read_bytes", boom)
        with collect_read_diagnostics() as diags:
            assert decode_text(p) is None
            assert read_xml_bytes(p) is None
        assert len(diags) == 2
        assert all("could not be read" in d.reason for d in diags)
        # An unreadable file is a gap (dependencies lost).
        assert all(d.is_gap for d in diags)

    def test_clean_utf8_records_nothing(self, tmp_path: Path):
        p = tmp_path / "f.txt"
        p.write_text("flask==3.0.0\n", encoding="utf-8")
        with collect_read_diagnostics() as diags:
            decode_text(p)
        assert diags == []

    def test_no_diagnostic_outside_active_context(self, tmp_path: Path):
        # ``_record`` is a no-op when no sink is active — decoding still works.
        p = tmp_path / "f.txt"
        p.write_bytes(b"# Jos\xe9\nflask==3.0.0\n")
        assert "flask==3.0.0" in decode_text(p)

    def test_reentrant_reuses_outer_sink(self, tmp_path: Path):
        # A nested ``collect_read_diagnostics`` must reuse the outer sink, so a
        # caller can wrap license detection and dependency discovery and drain
        # one combined list.
        p = tmp_path / "f.txt"
        p.write_bytes(b"# Jos\xe9\nflask==3.0.0\n")
        with collect_read_diagnostics() as outer:
            with collect_read_diagnostics() as inner:
                assert inner is outer
                decode_text(p)
            assert len(outer) == 1

    def test_read_diagnostic_is_frozen(self):
        d = ReadDiagnostic(path=Path("x"), reason="r", is_gap=True)
        with pytest.raises(AttributeError):
            d.reason = "other"  # type: ignore[misc]


class TestStructuredLoaders:
    def test_read_bytes_ok(self, tmp_path: Path):
        p = tmp_path / "f"
        p.write_bytes(b"abc")
        assert read_bytes(p) == b"abc"

    def test_load_json_ok(self, tmp_path: Path):
        p = tmp_path / "f.json"
        p.write_bytes(b'{"a": 1}')
        assert load_json(p) == {"a": 1}

    def test_load_json_parse_failure_is_gap(self, tmp_path: Path):
        p = tmp_path / "f.json"
        p.write_bytes(b"{not json")
        with collect_read_diagnostics() as diags:
            assert load_json(p) is None
        assert len(diags) == 1 and diags[0].is_gap and "JSON" in diags[0].reason

    def test_load_json_unreadable_is_gap(self, tmp_path: Path, monkeypatch):
        p = tmp_path / "f.json"
        p.write_bytes(b"{}")
        monkeypatch.setattr(Path, "read_bytes", lambda self: (_ for _ in ()).throw(OSError()))
        with collect_read_diagnostics() as diags:
            assert load_json(p) is None
        assert len(diags) == 1 and diags[0].is_gap

    def test_load_toml_ok(self, tmp_path: Path):
        p = tmp_path / "f.toml"
        p.write_bytes(b'a = "b"\n')
        assert load_toml(p) == {"a": "b"}

    def test_load_toml_parse_failure_is_gap(self, tmp_path: Path):
        p = tmp_path / "f.toml"
        p.write_bytes(b"this is = = not toml")
        with collect_read_diagnostics() as diags:
            assert load_toml(p) is None
        assert len(diags) == 1 and diags[0].is_gap and "TOML" in diags[0].reason

    def test_load_toml_unreadable_is_gap(self, tmp_path: Path, monkeypatch):
        p = tmp_path / "f.toml"
        p.write_bytes(b"a = 1\n")
        monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(OSError()))
        with collect_read_diagnostics() as diags:
            assert load_toml(p) is None
        assert len(diags) == 1 and diags[0].is_gap and "could not be read" in diags[0].reason

    def test_load_yaml_ok(self, tmp_path: Path):
        p = tmp_path / "f.yaml"
        p.write_bytes(b"a: b\n")
        assert load_yaml(p) == {"a": "b"}

    def test_load_yaml_parse_failure_is_gap(self, tmp_path: Path):
        p = tmp_path / "f.yaml"
        p.write_bytes(b"a: [unterminated\n")
        with collect_read_diagnostics() as diags:
            assert load_yaml(p) is None
        assert len(diags) == 1 and diags[0].is_gap and "YAML" in diags[0].reason

    def test_load_yaml_unreadable_returns_none(self, tmp_path: Path, monkeypatch):
        p = tmp_path / "f.yaml"
        p.write_bytes(b"a: b\n")
        monkeypatch.setattr(Path, "read_bytes", lambda self: (_ for _ in ()).throw(OSError()))
        assert load_yaml(p) is None


class TestManifestSizeCap:
    """Files past ``_MAX_MANIFEST_BYTES`` are stat-checked and skipped as a gap
    before being read into memory — the size-cap sibling of the http-layer
    decompression-bomb guard. Patched to a few bytes so the test needs only a
    tiny file.
    """

    def test_read_bytes_over_cap_is_gap(self, tmp_path: Path, monkeypatch):
        p = tmp_path / "big.lock"
        p.write_bytes(b"x" * 64)
        monkeypatch.setattr("licenseal.discovery._read._MAX_MANIFEST_BYTES", 16)
        with collect_read_diagnostics() as diags:
            assert read_bytes(p) is None
        assert len(diags) == 1 and diags[0].is_gap and "size cap" in diags[0].reason

    def test_load_toml_over_cap_is_gap(self, tmp_path: Path, monkeypatch):
        p = tmp_path / "big.toml"
        p.write_bytes(b'a = "b"\n' * 8)
        monkeypatch.setattr("licenseal.discovery._read._MAX_MANIFEST_BYTES", 4)
        with collect_read_diagnostics() as diags:
            assert load_toml(p) is None
        assert len(diags) == 1 and diags[0].is_gap and "size cap" in diags[0].reason


class TestRecordHelpers:
    def test_record_parse_failure(self, tmp_path: Path):
        with collect_read_diagnostics() as diags:
            record_parse_failure(tmp_path / "x.xml", "XML")
        assert len(diags) == 1
        assert diags[0].is_gap and "not valid XML" in diags[0].reason

    def test_record_walk_error_with_filename(self):
        exc = OSError("denied")
        exc.filename = "/some/dir"
        with collect_read_diagnostics() as diags:
            record_walk_error(exc)
        assert len(diags) == 1
        assert diags[0].is_gap
        assert "could not be traversed" in diags[0].reason

    def test_record_walk_error_without_filename(self):
        with collect_read_diagnostics() as diags:
            record_walk_error(OSError("no filename"))
        assert len(diags) == 1 and diags[0].is_gap
