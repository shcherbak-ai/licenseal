"""A lockfile the parser cannot use is a gap, not an empty result.

Three ways a lockfile parses and still tells the scan nothing: it declares a
format version the parser is known not to read, none of its entries is in a
form the parser reads, or it holds both sides of an unresolved merge. Each is
recorded and the lockfile is skipped, which leaves the direct dependencies to
the registry walk.

A version the parser merely does not know is not one of them. A newer
version, or any other value that is not on the parser's list, is read as it
stands and noted without being a gap; if nothing in it can be read, the
second rule says so.

The other half is what must stay clean: a lockfile with no entries, and one
that is read in full and then filters down to nothing (dev-only packages
without ``--dev``, the project's own packages, non-registry sources).
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import httpx
import pytest
import respx

from licenseal.discovery._read import ReadDiagnostic
from licenseal.models import DependencyGroup
from tests._helpers import (
    _assert_gap_fails_only_strict,
    _check_json,
    _gaps,
    _mock_npm,
    _resolve,
    _write,
)

PROD = DependencyGroup.PROD
DEV = DependencyGroup.DEV

_VERSION = "declares a lockfile version that is not supported; skipped"
_UNREAD = "holds no entry in a form that can be read; skipped"
_CONFLICT = "contains merge-conflict markers; skipped"
_WRONG_TYPE = "{} has an unexpected type; ignored"
# Recorded without being a gap: the lockfile is read all the same.
_NEWER = "declares a lockfile version newer than the parser knows; read on a best-effort basis"
_UNKNOWN = "declares a lockfile version the parser does not know; read on a best-effort basis"


def _notes(diags: list[ReadDiagnostic]) -> set[tuple[Path, str, bool]]:
    """Everything recorded, as ``(path, reason, is_gap)``."""
    return {(diag.path, diag.reason, diag.is_gap) for diag in diags}


_NPM_MANIFEST = {"name": "app", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^1.0.0"}}
# What a scan knows when the lockfile pins nothing: the manifest's constraints.
_NPM_UNPINNED = {("a", "^1.0.0", PROD), ("d", "^1.0.0", DEV)}
_NPM_PINNED = {("a", "==1.0.0", PROD), ("b", "==1.0.0", PROD), ("d", "==1.0.0", DEV)}


def _npm(tmp_path: Path, lockfile: str, content: str) -> Path:
    (tmp_path / "package.json").write_text(json.dumps(_NPM_MANIFEST))
    return _write(tmp_path / lockfile, content)


class TestPnpmLock:
    _V9 = """\
    lockfileVersion: {version}
    packages:
      a@1.0.0: {{resolution: {{integrity: sha512-x}}}}
      b@1.0.0: {{resolution: {{integrity: sha512-x}}}}
      d@1.0.0: {{resolution: {{integrity: sha512-x}}}}
    snapshots:
      a@1.0.0:
        dependencies:
          b: 1.0.0
      b@1.0.0: {{}}
      d@1.0.0: {{}}
    """
    # ``/name/version`` keys: the form lockfile version 5 uses.
    _V5_PACKAGES = textwrap.dedent(
        """\
        packages:
          /a/1.0.0:
            resolution: {integrity: sha512-x}
            dependencies:
              b: 1.0.0
            dev: false
          /b/1.0.0:
            resolution: {integrity: sha512-x}
            dev: false
          /d/1.0.0:
            resolution: {integrity: sha512-x}
            dev: true
        """
    )

    @pytest.mark.parametrize("version", ["5.4", "'5.3'", "5", "'4'", "3", "0"])
    def test_version_older_than_6_is_a_gap_whatever_the_file_holds(self, tmp_path: Path, version):
        # Known not to be read: those versions key packages as /name/version.
        # The version alone decides, even over entries that could be read.
        lock = _npm(tmp_path, "pnpm-lock.yaml", self._V9.format(version=version))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _VERSION)}

    @pytest.mark.parametrize("version", ["'6.0'", "'6.1'", "'9.0'", "9", "6.0"])
    def test_known_version_is_read(self, tmp_path: Path, version):
        _npm(tmp_path, "pnpm-lock.yaml", self._V9.format(version=version))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert diags == []

    @pytest.mark.parametrize("version", ["'10.0'", "'11.2'", "10", "42.0"])
    def test_newer_version_is_read_and_noted_without_a_gap(self, tmp_path: Path, version):
        lock = _npm(tmp_path, "pnpm-lock.yaml", self._V9.format(version=version))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert _notes(diags) == {(lock, _NEWER, False)}

    @pytest.mark.parametrize("version", ["'7.0'", "'8.0'", "latest", "true", "[9]"])
    def test_version_not_on_the_list_is_read_and_noted_without_a_gap(self, tmp_path: Path, version):
        # Between two known versions, or not a number at all: nothing says
        # the lockfile cannot be read, so it is.
        lock = _npm(tmp_path, "pnpm-lock.yaml", self._V9.format(version=version))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert _notes(diags) == {(lock, _UNKNOWN, False)}

    def test_newer_version_with_no_readable_entry_is_a_gap(self, tmp_path: Path):
        # The note says the version is unknown; the gap says what that cost.
        lock = _npm(tmp_path, "pnpm-lock.yaml", "lockfileVersion: '10.0'\n" + self._V5_PACKAGES)
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _notes(diags) == {(lock, _NEWER, False), (lock, _UNREAD, True)}

    def test_version_5_lockfile_is_a_gap_by_its_version(self, tmp_path: Path):
        lock = _npm(tmp_path, "pnpm-lock.yaml", "lockfileVersion: 5.4\n" + self._V5_PACKAGES)
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _VERSION)}

    @pytest.mark.parametrize("header", ["", "lockfileVersion: '6.0'\n"])
    def test_version_5_keys_are_a_gap_whatever_version_is_declared(self, tmp_path: Path, header):
        # Without a version, or under one that is read, the keys themselves
        # are what the parser cannot read.
        lock = _npm(tmp_path, "pnpm-lock.yaml", header + self._V5_PACKAGES)
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    def test_lockfile_of_a_project_with_no_dependencies_is_clean(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(json.dumps({"name": "app"}))
        _write(tmp_path / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n")
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert diags == []

    def test_empty_file_is_clean(self, tmp_path: Path):
        _npm(tmp_path, "pnpm-lock.yaml", "")
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert diags == []

    def test_only_non_registry_packages_is_clean(self, tmp_path: Path):
        _npm(
            tmp_path,
            "pnpm-lock.yaml",
            """\
            lockfileVersion: '9.0'
            packages:
              a@link:../a: {}
              d@file:local/d.tgz: {resolution: {tarball: file:local/d.tgz}}
            """,
        )
        # A linked package and an archive inside the scanned directory are the
        # project's own code: read, and no rows.
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert diags == []

    def test_only_dev_packages_without_dev_is_clean(self, tmp_path: Path):
        # Read in full, then filtered to nothing: not a gap.
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "devDependencies": {"d": "^1.0.0"}})
        )
        _write(
            tmp_path / "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages:\n  d@1.0.0: {}\nsnapshots:\n  d@1.0.0: {}\n",
        )
        rows, diags = _resolve(tmp_path, include_dev=False)
        assert rows == set()
        assert diags == []

    def test_orphans_dropped_is_clean(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "dependencies": {"a": "^1.0.0"}})
        )
        _write(
            tmp_path / "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages:\n  a@1.0.0: {}\n  stale@2.0.0: {}\n",
        )
        rows, diags = _resolve(tmp_path)
        assert rows == {("a", "==1.0.0", PROD)}
        assert diags == []


class TestPackageLock:
    _PACKAGES = {
        "": {"name": "app"},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1.0.0"}},
        "node_modules/b": {"version": "1.0.0"},
        "node_modules/d": {"version": "1.0.0", "dev": True},
    }

    @pytest.mark.parametrize(
        ("version", "note"),
        [
            (4, _NEWER),
            (5, _NEWER),
            ("4", _NEWER),
            (0, _UNKNOWN),
            ("x", _UNKNOWN),
            (True, _UNKNOWN),
            ([3], _UNKNOWN),
            # A run of digits no interpreter converts is not a version either.
            ("1" * 5000, _UNKNOWN),
        ],
        ids=["4", "5", "4-string", "0", "word", "boolean", "list", "5000-digits"],
    )
    def test_version_not_on_the_list_is_read_and_noted_without_a_gap(
        self, tmp_path: Path, version, note
    ):
        lock = _npm(
            tmp_path,
            "package-lock.json",
            json.dumps({"lockfileVersion": version, "packages": self._PACKAGES}),
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert _notes(diags) == {(lock, note, False)}

    def test_newer_version_with_no_readable_entry_is_a_gap(self, tmp_path: Path):
        packages = {"": {"name": "app"}, "node_modules/a": {}, "node_modules/b": {"resolved": "x"}}
        lock = _npm(
            tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 4, "packages": packages})
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _notes(diags) == {(lock, _NEWER, False), (lock, _UNREAD, True)}

    @pytest.mark.parametrize("document", [{"lockfileVersion": 2}, {"lockfileVersion": 3}, {}])
    def test_known_or_undeclared_version_is_read(self, tmp_path: Path, document):
        _npm(tmp_path, "package-lock.json", json.dumps({**document, "packages": self._PACKAGES}))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert diags == []

    def test_no_entry_with_a_version_is_a_gap(self, tmp_path: Path):
        packages = {"": {"name": "app"}, "node_modules/a": {}, "node_modules/b": {"resolved": "x"}}
        lock = _npm(
            tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": packages})
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "packages",
        [
            {},
            {"": {"name": "app"}},
            {
                "": {"name": "app"},
                "node_modules/link": {"resolved": "packages/link", "link": True},
                "packages/link": {"name": "link"},
            },
        ],
        ids=["empty", "own-project-only", "workspace-links-only"],
    )
    def test_lockfile_with_no_registry_package_is_clean(self, tmp_path: Path, packages):
        _npm(
            tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": packages})
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert diags == []

    def test_v1_tree_with_no_entry_that_has_a_version_is_a_gap(self, tmp_path: Path):
        tree = {"a": {}, "b": {"resolved": "x"}}
        lock = _npm(
            tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": tree})
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "document",
        [{"lockfileVersion": 1, "requires": True}, {"lockfileVersion": 1, "dependencies": {}}],
        ids=["no-tree", "empty-tree"],
    )
    def test_v1_lockfile_with_no_dependencies_is_clean(self, tmp_path: Path, document):
        _npm(tmp_path, "package-lock.json", json.dumps(document))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert diags == []


_YARN_V1 = """\
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


a@^1.0.0:
  version "1.0.0"
  dependencies:
    b "^1.0.0"

b@^1.0.0:
  version "1.0.0"

d@^1.0.0:
  version "1.0.0"
"""


class TestYarnClassicLock:
    def test_healthy_lockfile_is_read(self, tmp_path: Path):
        _npm(tmp_path, "yarn.lock", _YARN_V1)
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert diags == []

    @pytest.mark.parametrize(
        "content",
        [
            # Around whole entries: both sides would otherwise be reported.
            _YARN_V1.replace(
                'b@^1.0.0:\n  version "1.0.0"\n',
                '<<<<<<< HEAD\nb@^1.0.0:\n  version "1.0.0"\n=======\n'
                'b@^1.0.0:\n  version "1.0.1"\n>>>>>>> feature\n',
            ),
            # Inside one entry: the markers would otherwise be read as packages.
            _YARN_V1.replace(
                'b@^1.0.0:\n  version "1.0.0"\n',
                'b@^1.0.0:\n<<<<<<< HEAD\n  version "1.0.0"\n=======\n'
                '  version "1.0.1"\n>>>>>>> feature\n',
            ),
            # Above everything, where the format is decided.
            "<<<<<<< HEAD\n" + _YARN_V1 + "=======\n" + _YARN_V1 + ">>>>>>> feature\n",
            # A closing marker left behind on its own.
            _YARN_V1 + ">>>>>>> feature\n",
            # Windows line endings.
            ("<<<<<<< HEAD\n" + _YARN_V1 + "=======\n>>>>>>> feature\n").replace("\n", "\r\n"),
        ],
        ids=["around-entries", "inside-an-entry", "above-the-header", "stray-closer", "crlf"],
    )
    def test_merge_conflict_markers_are_a_gap(self, tmp_path: Path, content):
        (tmp_path / "package.json").write_text(json.dumps(_NPM_MANIFEST))
        lock = tmp_path / "yarn.lock"
        lock.write_bytes(content.encode("utf-8"))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _CONFLICT)}

    def test_berry_lockfile_with_markers_above_the_metadata_is_a_gap(self, tmp_path: Path):
        lock = _npm(
            tmp_path,
            "yarn.lock",
            "<<<<<<< HEAD\n__metadata:\n  version: 8\n=======\n>>>>>>> feature\n"
            '"a@npm:^1.0.0":\n  version: 1.0.0\n',
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _CONFLICT)}

    def test_marker_text_that_does_not_start_a_line_is_not_a_marker(self, tmp_path: Path):
        # Git writes a marker at the start of a line. The same text indented,
        # or inside a comment, is not one.
        content = _YARN_V1 + "  <<<<<<< HEAD\n# <<<<<<< HEAD\n# >>>>>>> feature\n"
        _npm(tmp_path, "yarn.lock", content)
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert diags == []

    @pytest.mark.parametrize(
        ("header", "note"),
        [("lockfile v2", _NEWER), ("lockfile v0", _UNKNOWN), ("lockfile vNext", _UNKNOWN)],
    )
    def test_header_version_not_on_the_list_is_read_and_noted_without_a_gap(
        self, tmp_path: Path, header, note
    ):
        lock = _npm(tmp_path, "yarn.lock", _YARN_V1.replace("lockfile v1", header))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert _notes(diags) == {(lock, note, False)}

    def test_newer_header_version_with_no_readable_entry_is_a_gap(self, tmp_path: Path):
        lock = _npm(tmp_path, "yarn.lock", '# yarn lockfile v2\n\n\na@^1.0.0:\n  resolved "x"\n')
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _notes(diags) == {(lock, _NEWER, False), (lock, _UNREAD, True)}

    def test_lockfile_without_the_header_comment_is_read(self, tmp_path: Path):
        _npm(tmp_path, "yarn.lock", _YARN_V1.split("\n\n\n", 1)[1])
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert diags == []

    @pytest.mark.parametrize(
        "body",
        [
            'a@^1.0.0:\n  resolved "https://example.invalid/a.tgz"\n',
            '{\n  "a": "1.0.0"\n}\n',
            "- a@1.0.0\n- b@1.0.0\n",
        ],
        ids=["entries-without-a-version", "json", "yaml-list"],
    )
    def test_no_entry_that_can_be_read_is_a_gap(self, tmp_path: Path, body):
        lock = _npm(tmp_path, "yarn.lock", "# yarn lockfile v1\n\n\n" + body)
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "content",
        ["", "# THIS IS AN AUTOGENERATED FILE.\n# yarn lockfile v1\n\n\n"],
        ids=["zero-bytes", "header-only"],
    )
    def test_lockfile_with_no_entries_is_clean(self, tmp_path: Path, content):
        _npm(tmp_path, "yarn.lock", content)
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert diags == []

    def test_only_dev_packages_without_dev_is_clean(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "devDependencies": {"d": "^1.0.0"}})
        )
        _write(tmp_path / "yarn.lock", '# yarn lockfile v1\n\n\nd@^1.0.0:\n  version "1.0.0"\n')
        rows, diags = _resolve(tmp_path, include_dev=False)
        assert rows == set()
        assert diags == []


class TestYarnBerryLock:
    _LOCK = """\
    __metadata:
      version: {version}

    "a@npm:^1.0.0":
      version: 1.0.0
      dependencies:
        b: "npm:^1.0.0"

    "b@npm:^1.0.0":
      version: 1.0.0

    "d@npm:^1.0.0":
      version: 1.0.0

    "app@workspace:.":
      version: 0.0.0-use.local
      dependencies:
        a: "npm:^1.0.0"
    """

    @pytest.mark.parametrize(
        ("version", "note"),
        [
            ("11", _NEWER),
            ("12", _NEWER),
            ("3", _UNKNOWN),
            ("x", _UNKNOWN),
            ("true", _UNKNOWN),
            ("[8]", _UNKNOWN),
        ],
    )
    def test_version_not_on_the_list_is_read_and_noted_without_a_gap(
        self, tmp_path: Path, version, note
    ):
        lock = _npm(tmp_path, "yarn.lock", self._LOCK.format(version=version))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert _notes(diags) == {(lock, note, False)}

    def test_newer_version_with_no_readable_entry_is_a_gap(self, tmp_path: Path):
        lock = _npm(
            tmp_path,
            "yarn.lock",
            '__metadata:\n  version: 11\n\n"a@npm:^1.0.0":\n  resolution: "a@npm:1.0.0"\n',
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _notes(diags) == {(lock, _NEWER, False), (lock, _UNREAD, True)}

    @pytest.mark.parametrize("version", ["4", "5", "6", "7", "8", "9", "10"])
    def test_known_version_is_read(self, tmp_path: Path, version):
        _npm(tmp_path, "yarn.lock", self._LOCK.format(version=version))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert diags == []

    def test_metadata_without_a_version_is_read(self, tmp_path: Path):
        _npm(tmp_path, "yarn.lock", self._LOCK.replace("  version: {version}\n", "  cacheKey: 8\n"))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert diags == []

    def test_metadata_of_the_wrong_type_is_a_gap_and_the_entries_are_read(self, tmp_path: Path):
        content = self._LOCK.replace("__metadata:\n      version: {version}\n", "__metadata: 8\n")
        lock = _npm(tmp_path, "yarn.lock", content)
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert _gaps(diags) == {(lock, _WRONG_TYPE.format("__metadata"))}

    def test_no_entry_with_a_version_is_a_gap(self, tmp_path: Path):
        lock = _npm(
            tmp_path,
            "yarn.lock",
            '__metadata:\n  version: 8\n\n"a@npm:^1.0.0":\n  resolution: "a@npm:1.0.0"\n',
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "entries",
        ["", '\n"app@workspace:.":\n  version: 0.0.0-use.local\n'],
        ids=["metadata-only", "own-project-only"],
    )
    def test_lockfile_with_no_registry_package_is_clean(self, tmp_path: Path, entries):
        _npm(tmp_path, "yarn.lock", "__metadata:\n  version: 8\n" + entries)
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert diags == []


class TestBunLock:
    _PACKAGES = {
        "a": ["a@1.0.0", "", {"dependencies": {"b": "^1.0.0"}}, "sha512-x"],
        "b": ["b@1.0.0", "", {}, "sha512-x"],
        "d": ["d@1.0.0", "", {}, "sha512-x"],
    }

    @pytest.mark.parametrize(
        ("version", "note"), [(2, _NEWER), (3, _NEWER), ("x", _UNKNOWN), (True, _UNKNOWN)]
    )
    def test_version_not_on_the_list_is_read_and_noted_without_a_gap(
        self, tmp_path: Path, version, note
    ):
        lock = _npm(
            tmp_path,
            "bun.lock",
            json.dumps({"lockfileVersion": version, "packages": self._PACKAGES}),
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert _notes(diags) == {(lock, note, False)}

    def test_newer_version_with_no_readable_entry_is_a_gap(self, tmp_path: Path):
        packages = {"a": ["a", "", {}], "b": ["b", "", {}]}
        lock = _npm(tmp_path, "bun.lock", json.dumps({"lockfileVersion": 2, "packages": packages}))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _notes(diags) == {(lock, _NEWER, False), (lock, _UNREAD, True)}

    @pytest.mark.parametrize("document", [{"lockfileVersion": 0}, {"lockfileVersion": 1}, {}])
    def test_known_or_undeclared_version_is_read(self, tmp_path: Path, document):
        _npm(tmp_path, "bun.lock", json.dumps({**document, "packages": self._PACKAGES}))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_PINNED
        assert diags == []

    def test_no_entry_with_a_version_is_a_gap(self, tmp_path: Path):
        packages = {"a": ["a", "", {}], "b": ["b", "", {}]}
        lock = _npm(tmp_path, "bun.lock", json.dumps({"lockfileVersion": 1, "packages": packages}))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "packages", [{}, {"app": ["app@workspace:."]}], ids=["empty", "own-project-only"]
    )
    def test_lockfile_with_no_registry_package_is_clean(self, tmp_path: Path, packages):
        _npm(tmp_path, "bun.lock", json.dumps({"lockfileVersion": 1, "packages": packages}))
        rows, diags = _resolve(tmp_path)
        assert rows == _NPM_UNPINNED
        assert diags == []


_PY_MANIFEST = """\
[project]
name = "app"
dependencies = ["flask"]

[dependency-groups]
dev = ["pytest"]
"""
_PY_UNPINNED = {("flask", "", PROD), ("pytest", "", DEV)}
_PY_PINNED = {("flask", "==3.0.0", PROD), ("werkzeug", "==3.0.1", PROD), ("pytest", "==8.0.0", DEV)}


def _py(tmp_path: Path, lockfile: str, content: str) -> Path:
    _write(tmp_path / "pyproject.toml", _PY_MANIFEST)
    return _write(tmp_path / lockfile, content)


class TestUvLock:
    _PACKAGES = """\

    [[package]]
    name = "app"
    version = "0.1.0"
    source = { virtual = "." }
    dependencies = [{ name = "flask" }]

    [[package]]
    name = "flask"
    version = "3.0.0"
    dependencies = [{ name = "werkzeug" }]

    [[package]]
    name = "werkzeug"
    version = "3.0.1"

    [[package]]
    name = "pytest"
    version = "8.0.0"
    """

    @pytest.mark.parametrize(
        ("version", "note"),
        [
            ("2", _NEWER),
            ("3", _NEWER),
            ("0", _UNKNOWN),
            ('"x"', _UNKNOWN),
            ("true", _UNKNOWN),
            ("[1]", _UNKNOWN),
        ],
    )
    def test_version_not_on_the_list_is_read_and_noted_without_a_gap(
        self, tmp_path: Path, version, note
    ):
        lock = _py(tmp_path, "uv.lock", f"version = {version}\n" + self._PACKAGES)
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_PINNED
        assert _notes(diags) == {(lock, note, False)}

    def test_newer_version_with_no_readable_entry_is_a_gap(self, tmp_path: Path):
        lock = _py(
            tmp_path,
            "uv.lock",
            'version = 2\n\n[[package]]\nname = "flask"\n\n[[package]]\nname = "pytest"\n',
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_UNPINNED
        assert _notes(diags) == {(lock, _NEWER, False), (lock, _UNREAD, True)}

    @pytest.mark.parametrize("header", ["version = 1\nrevision = 3\n", ""])
    def test_known_or_undeclared_version_is_read(self, tmp_path: Path, header):
        _py(tmp_path, "uv.lock", header + self._PACKAGES)
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_PINNED
        assert diags == []

    def test_no_package_with_a_version_is_a_gap(self, tmp_path: Path):
        lock = _py(
            tmp_path,
            "uv.lock",
            'version = 1\n\n[[package]]\nname = "flask"\n\n[[package]]\nname = "pytest"\n',
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "packages",
        ["", '\n[[package]]\nname = "app"\nsource = { editable = "." }\n'],
        ids=["no-packages", "own-project-only"],
    )
    def test_lockfile_of_a_project_with_no_dependencies_is_clean(self, tmp_path: Path, packages):
        _write(tmp_path / "pyproject.toml", '[project]\nname = "app"\n')
        _write(tmp_path / "uv.lock", "version = 1\n" + packages)
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert diags == []

    def test_only_dev_packages_without_dev_is_clean(self, tmp_path: Path):
        _write(tmp_path / "pyproject.toml", '[dependency-groups]\ndev = ["pytest"]\n')
        _write(tmp_path / "uv.lock", 'version = 1\n\n[[package]]\nname = "pytest"\nversion = "8"\n')
        rows, diags = _resolve(tmp_path, include_dev=False)
        assert rows == set()
        assert diags == []


class TestPoetryLock:
    _PACKAGES = """\
    [[package]]
    name = "flask"
    version = "3.0.0"

    [package.dependencies]
    werkzeug = ">=3"

    [[package]]
    name = "werkzeug"
    version = "3.0.1"

    [[package]]
    name = "pytest"
    version = "8.0.0"
    """

    @pytest.mark.parametrize(
        ("version", "note"),
        [('"3.0"', _NEWER), ("3", _NEWER), ('"0.9"', _UNKNOWN), ("true", _UNKNOWN)],
    )
    def test_version_not_on_the_list_is_read_and_noted_without_a_gap(
        self, tmp_path: Path, version, note
    ):
        lock = _py(
            tmp_path, "poetry.lock", self._PACKAGES + f"\n[metadata]\nlock-version = {version}\n"
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_PINNED
        assert _notes(diags) == {(lock, note, False)}

    def test_newer_version_with_no_readable_entry_is_a_gap(self, tmp_path: Path):
        lock = _py(
            tmp_path,
            "poetry.lock",
            '[[package]]\nname = "flask"\n\n[metadata]\nlock-version = "3.0"\n',
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_UNPINNED
        assert _notes(diags) == {(lock, _NEWER, False), (lock, _UNREAD, True)}

    @pytest.mark.parametrize(
        "metadata",
        [
            '\n[metadata]\nlock-version = "1.1"\n',
            '\n[metadata]\nlock-version = "2.0"\n',
            '\n[metadata]\nlock-version = "2.1"\n',
            '\n[metadata]\npython-versions = "^3.10"\n',
            "",
        ],
        ids=["1.1", "2.0", "2.1", "no-lock-version", "no-metadata"],
    )
    def test_known_or_undeclared_version_is_read(self, tmp_path: Path, metadata):
        _py(tmp_path, "poetry.lock", self._PACKAGES + metadata)
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_PINNED
        assert diags == []

    def test_metadata_of_the_wrong_type_is_a_gap_and_the_packages_are_read(self, tmp_path: Path):
        lock = _py(tmp_path, "poetry.lock", 'metadata = "2.0"\n\n' + self._PACKAGES)
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_PINNED
        assert _gaps(diags) == {(lock, _WRONG_TYPE.format("metadata"))}

    def test_no_package_with_a_version_is_a_gap(self, tmp_path: Path):
        lock = _py(tmp_path, "poetry.lock", '[[package]]\nname = "flask"\n')
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "content", ['package = []\n\n[metadata]\nlock-version = "2.0"\n', ""], ids=["empty", "zero"]
    )
    def test_lockfile_with_no_packages_is_clean(self, tmp_path: Path, content):
        _py(tmp_path, "poetry.lock", content)
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_UNPINNED
        assert diags == []


class TestPipfileLock:
    @staticmethod
    def _project(tmp_path: Path, document: object) -> Path:
        _write(tmp_path / "Pipfile", '[packages]\nflask = "*"\n\n[dev-packages]\npytest = "*"\n')
        lock = tmp_path / "Pipfile.lock"
        lock.write_text(json.dumps(document))
        return lock

    _SECTIONS = {
        "default": {"flask": {"version": "==3.0.0"}},
        "develop": {"pytest": {"version": "==8.0.0"}},
    }
    _PINNED = {("flask", "==3.0.0", PROD), ("pytest", "==8.0.0", DEV)}

    @pytest.mark.parametrize(
        ("spec", "note"),
        [(7, _NEWER), (8, _NEWER), (5, _UNKNOWN), ("x", _UNKNOWN), (True, _UNKNOWN)],
    )
    def test_spec_version_not_on_the_list_is_read_and_noted_without_a_gap(
        self, tmp_path: Path, spec, note
    ):
        lock = self._project(tmp_path, {"_meta": {"pipfile-spec": spec}, **self._SECTIONS})
        rows, diags = _resolve(tmp_path)
        assert rows == self._PINNED
        assert _notes(diags) == {(lock, note, False)}

    def test_newer_spec_version_with_no_readable_entry_is_a_gap(self, tmp_path: Path):
        lock = self._project(
            tmp_path, {"_meta": {"pipfile-spec": 7}, "default": {"flask": {"hashes": []}}}
        )
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_UNPINNED
        assert _notes(diags) == {(lock, _NEWER, False), (lock, _UNREAD, True)}

    @pytest.mark.parametrize("meta", [{"_meta": {"pipfile-spec": 6}}, {"_meta": {}}, {}])
    def test_known_or_undeclared_spec_version_is_read(self, tmp_path: Path, meta):
        self._project(tmp_path, {**meta, **self._SECTIONS})
        rows, diags = _resolve(tmp_path)
        assert rows == self._PINNED
        assert diags == []

    def test_meta_of_the_wrong_type_is_a_gap_and_the_sections_are_read(self, tmp_path: Path):
        lock = self._project(tmp_path, {"_meta": 6, **self._SECTIONS})
        rows, diags = _resolve(tmp_path)
        assert rows == self._PINNED
        assert _gaps(diags) == {(lock, _WRONG_TYPE.format('"_meta"'))}

    @pytest.mark.parametrize("include_dev", [True, False])
    def test_no_entry_with_a_version_is_a_gap(self, tmp_path: Path, include_dev):
        lock = self._project(
            tmp_path, {"default": {"flask": {"hashes": []}}, "develop": {"pytest": {}}}
        )
        rows, diags = _resolve(tmp_path, include_dev=include_dev)
        assert rows == (_PY_UNPINNED if include_dev else {("flask", "", PROD)})
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        ("document", "off_registry"),
        [
            ({"default": {}, "develop": {}}, set()),
            ({"default": {"local": {"path": ".", "editable": True}}}, set()),
            (
                {"default": {"fork": {"git": "https://example.invalid/fork.git", "ref": "abc"}}},
                {("fork", "", PROD)},
            ),
        ],
        ids=["empty", "path-only", "git-only"],
    )
    def test_lockfile_with_no_registry_package_is_clean(
        self, tmp_path: Path, document, off_registry
    ):
        # The git package is a row of its own, with no version to pin.
        self._project(tmp_path, document)
        rows, diags = _resolve(tmp_path)
        assert rows == _PY_UNPINNED | off_registry
        assert diags == []

    def test_only_develop_entries_without_dev_is_clean(self, tmp_path: Path):
        # The develop section is counted before the dev filter, so a lockfile
        # that pins only dev packages is not mistaken for an unreadable one.
        _write(tmp_path / "Pipfile", '[dev-packages]\npytest = "*"\n')
        (tmp_path / "Pipfile.lock").write_text(
            json.dumps({"default": {}, "develop": {"pytest": {"version": "==8.0.0"}}})
        )
        rows, diags = _resolve(tmp_path, include_dev=False)
        assert rows == set()
        assert diags == []


class TestComposerLock:
    @staticmethod
    def _project(tmp_path: Path, document: object) -> Path:
        (tmp_path / "composer.json").write_text(
            json.dumps({"require": {"a/a": "^1"}, "require-dev": {"d/d": "^1"}})
        )
        lock = tmp_path / "composer.lock"
        lock.write_text(json.dumps(document))
        return lock

    _UNPINNED = {("a/a", "^1", PROD), ("d/d", "^1", DEV)}

    def test_no_entry_with_a_version_is_a_gap(self, tmp_path: Path):
        lock = self._project(
            tmp_path, {"packages": [{"name": "a/a"}], "packages-dev": [{"version": "1.0.0"}]}
        )
        rows, diags = _resolve(tmp_path)
        assert rows == self._UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "document",
        [
            {"packages": [], "packages-dev": []},
            {"packages": [], "packages-dev": None},
            {"content-hash": "x"},
        ],
        ids=["empty-lists", "null-dev-section", "no-sections"],
    )
    def test_lockfile_with_no_packages_is_clean(self, tmp_path: Path, document):
        self._project(tmp_path, document)
        rows, diags = _resolve(tmp_path)
        assert rows == self._UNPINNED
        assert diags == []

    def test_only_local_path_packages_is_clean(self, tmp_path: Path):
        self._project(
            tmp_path,
            {"packages": [{"name": "a/a", "version": "dev-main", "dist": {"type": "path"}}]},
        )
        rows, diags = _resolve(tmp_path)
        assert rows == self._UNPINNED
        assert diags == []

    def test_only_dev_packages_without_dev_is_clean(self, tmp_path: Path):
        (tmp_path / "composer.json").write_text(json.dumps({"require-dev": {"d/d": "^1"}}))
        (tmp_path / "composer.lock").write_text(
            json.dumps({"packages": [], "packages-dev": [{"name": "d/d", "version": "1.0.0"}]})
        )
        rows, diags = _resolve(tmp_path, include_dev=False)
        assert rows == set()
        assert diags == []


_GEMFILE_LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)
    rails (7.1.3)
      rack (~> 2.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.5.3
"""


class TestGemfileLock:
    @staticmethod
    def _project(tmp_path: Path, content: str) -> Path:
        _write(tmp_path / "Gemfile", 'source "https://rubygems.org"\ngem "rails"\n')
        lock = tmp_path / "Gemfile.lock"
        lock.write_text(content, encoding="utf-8", newline="\n")
        return lock

    _PINNED = {("rails", "==7.1.3", PROD), ("rack", "==2.2.8", PROD)}
    _UNPINNED = {("rails", "", PROD)}

    def test_healthy_lockfile_is_read(self, tmp_path: Path):
        self._project(tmp_path, _GEMFILE_LOCK)
        rows, diags = _resolve(tmp_path)
        assert rows == self._PINNED
        assert diags == []

    def test_merge_conflict_markers_are_a_gap(self, tmp_path: Path):
        content = _GEMFILE_LOCK.replace(
            "    rack (2.2.8)\n",
            "<<<<<<< HEAD\n    rack (2.2.8)\n=======\n    rack (2.2.9)\n>>>>>>> feature\n",
        )
        lock = self._project(tmp_path, content)
        rows, diags = _resolve(tmp_path)
        assert rows == self._UNPINNED
        assert _gaps(diags) == {(lock, _CONFLICT)}

    @pytest.mark.parametrize(
        "content",
        [
            # Specs indented with tabs, which the indent contract does not read.
            _GEMFILE_LOCK.replace("    rack (2.2.8)\n", "\track (2.2.8)\n")
            .replace("    rails (7.1.3)\n", "\trails (7.1.3)\n")
            .replace("      rack (~> 2.0)\n", "\t\track (~> 2.0)\n"),
            # Dependencies listed, and no spec for any of them.
            "GEM\n  remote: https://rubygems.org/\n  specs:\n\nDEPENDENCIES\n  rails\n",
        ],
        ids=["specs-indented-with-tabs", "dependencies-without-specs"],
    )
    def test_no_spec_that_can_be_read_is_a_gap(self, tmp_path: Path, content):
        lock = self._project(tmp_path, content)
        rows, diags = _resolve(tmp_path)
        assert rows == self._UNPINNED
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "content",
        [
            "GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\n"
            "DEPENDENCIES\n\nBUNDLED WITH\n   2.5.3\n",
            "",
        ],
        ids=["no-gems", "zero-bytes"],
    )
    def test_lockfile_of_a_project_with_no_gems_is_clean(self, tmp_path: Path, content):
        lock = tmp_path / "Gemfile.lock"
        lock.write_text(content, encoding="utf-8", newline="\n")
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert diags == []


_MIX_LOCK = """\
%{
  "jason": {:hex, :jason, "1.4.4", "in", [:mix], [], "hexpm", "out"},
  "plug": {:hex, :plug, "1.15.0", "in", [:mix], [{:jason, "~> 1.0", []}], "hexpm", "out"},
}
"""


class TestMixLock:
    _PINNED = {("jason", "==1.4.4", PROD), ("plug", "==1.15.0", PROD)}

    @staticmethod
    def _lock(tmp_path: Path, content: str) -> Path:
        lock = tmp_path / "mix.lock"
        lock.write_text(content, encoding="utf-8", newline="\n")
        return lock

    def test_healthy_lockfile_is_read(self, tmp_path: Path):
        self._lock(tmp_path, _MIX_LOCK)
        rows, diags = _resolve(tmp_path)
        assert rows == self._PINNED
        assert diags == []

    def test_merge_conflict_markers_are_a_gap(self, tmp_path: Path):
        jason = _MIX_LOCK.splitlines()[1]
        content = _MIX_LOCK.replace(
            jason, f"<<<<<<< HEAD\n{jason}\n=======\n{jason.replace('1.4.4', '1.4.5')}\n>>>>>>> x"
        )
        lock = self._lock(tmp_path, content)
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert _gaps(diags) == {(lock, _CONFLICT)}

    def test_no_entry_that_can_be_read_is_a_gap(self, tmp_path: Path):
        # Each entry broken over two lines, which the one-line pattern skips.
        content = (
            '%{\n  "jason": {:hex, :jason, "1.4.4", "inner", [:mix],\n'
            '    [], "hexpm", "outer"},\n}\n'
        )
        lock = self._lock(tmp_path, content)
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize("content", ["%{}\n", "%{\n}\n", ""], ids=["inline", "open", "zero"])
    def test_empty_lockfile_is_clean(self, tmp_path: Path, content):
        self._lock(tmp_path, content)
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert diags == []


_GRADLE_LOCK = """\
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
com.example:core:1.2.3=compileClasspath,runtimeClasspath
com.example:testkit:4.5.6=testCompileClasspath,testRuntimeClasspath
empty=annotationProcessor
"""


class TestGradleLockfile:
    @staticmethod
    def _lock(tmp_path: Path, content: str) -> Path:
        lock = tmp_path / "gradle.lockfile"
        lock.write_text(content, encoding="utf-8", newline="\n")
        return lock

    def test_healthy_lockfile_is_read(self, tmp_path: Path):
        self._lock(tmp_path, _GRADLE_LOCK)
        rows, diags = _resolve(tmp_path)
        assert rows == {
            ("com.example:core", "==1.2.3", PROD),
            ("com.example:testkit", "==4.5.6", DEV),
        }
        assert diags == []

    def test_merge_conflict_markers_are_a_gap(self, tmp_path: Path):
        content = _GRADLE_LOCK.replace(
            "com.example:core:1.2.3=compileClasspath,runtimeClasspath\n",
            "<<<<<<< HEAD\ncom.example:core:1.2.3=compileClasspath\n=======\n"
            "com.example:core:1.2.4=compileClasspath\n>>>>>>> feature\n",
        )
        lock = self._lock(tmp_path, content)
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert _gaps(diags) == {(lock, _CONFLICT)}

    @pytest.mark.parametrize(
        "body",
        [
            "com.example:core=compileClasspath\n",
            "com.example:core:1.2.3\n",
            "com.example:core:1.2.3=\n",
        ],
        ids=["no-version", "no-classpaths", "empty-classpaths"],
    )
    def test_no_line_that_can_be_read_is_a_gap(self, tmp_path: Path, body):
        lock = self._lock(tmp_path, "# This is a Gradle generated file.\n" + body)
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "content",
        ["# This is a Gradle generated file.\nempty=compileClasspath,runtimeClasspath\n", ""],
        ids=["empty-classpaths-only", "zero-bytes"],
    )
    def test_lockfile_with_no_dependencies_is_clean(self, tmp_path: Path, content):
        self._lock(tmp_path, content)
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert diags == []

    def test_only_test_dependencies_without_dev_is_clean(self, tmp_path: Path):
        self._lock(tmp_path, "com.example:testkit:4.5.6=testCompileClasspath\n")
        rows, diags = _resolve(tmp_path, include_dev=False)
        assert rows == set()
        assert diags == []


_PACKRAT_LOCK = """\
PackratFormat: {fmt}
PackratVersion: 0.5.0
RVersion: 4.3.1
Repos: CRAN=https://cran.example.invalid

Package: ggplot2
Source: CRAN
Version: 3.4.0
Hash: abc
Requires: rlang

Package: rlang
Source: CRAN
Version: 1.1.0
Hash: def
"""


class TestPackratLock:
    _PINNED = {("ggplot2", "==3.4.0", PROD), ("rlang", "==1.1.0", PROD)}

    @staticmethod
    def _lock(tmp_path: Path, content: str) -> Path:
        lock = tmp_path / "packrat" / "packrat.lock"
        lock.parent.mkdir()
        lock.write_text(content, encoding="utf-8", newline="\n")
        return lock

    @pytest.mark.parametrize("fmt", ["1.4", "1.1"])
    def test_known_format_is_read(self, tmp_path: Path, fmt):
        self._lock(tmp_path, _PACKRAT_LOCK.format(fmt=fmt))
        rows, diags = _resolve(tmp_path)
        assert rows == self._PINNED
        assert diags == []

    def test_lockfile_without_a_header_record_is_read(self, tmp_path: Path):
        self._lock(tmp_path, _PACKRAT_LOCK.split("\n\n", 1)[1])
        rows, diags = _resolve(tmp_path)
        assert rows == self._PINNED
        assert diags == []

    @pytest.mark.parametrize(
        ("fmt", "note"), [("2.0", _NEWER), ("3", _NEWER), ("0.9", _UNKNOWN), ("x", _UNKNOWN)]
    )
    def test_format_not_on_the_list_is_read_and_noted_without_a_gap(
        self, tmp_path: Path, fmt, note
    ):
        lock = self._lock(tmp_path, _PACKRAT_LOCK.format(fmt=fmt))
        rows, diags = _resolve(tmp_path)
        assert rows == self._PINNED
        assert _notes(diags) == {(lock, note, False)}

    def test_newer_format_with_no_readable_record_is_a_gap(self, tmp_path: Path):
        lock = self._lock(tmp_path, "PackratFormat: 2.0\n\nSource: CRAN\nVersion: 3.4.0\n")
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert _notes(diags) == {(lock, _NEWER, False), (lock, _UNREAD, True)}

    def test_merge_conflict_markers_are_a_gap(self, tmp_path: Path):
        content = _PACKRAT_LOCK.format(fmt="1.4").replace(
            "Version: 3.4.0\n", "<<<<<<< HEAD\nVersion: 3.4.0\n=======\nVersion: 3.4.1\n>>>>>>> x\n"
        )
        lock = self._lock(tmp_path, content)
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert _gaps(diags) == {(lock, _CONFLICT)}

    def test_no_record_that_names_a_package_is_a_gap(self, tmp_path: Path):
        lock = self._lock(
            tmp_path, "PackratFormat: 1.4\n\nSource: CRAN\nVersion: 3.4.0\n\nVersion: 1.1.0\n"
        )
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert _gaps(diags) == {(lock, _UNREAD)}

    @pytest.mark.parametrize(
        "content", ["PackratFormat: 1.4\nRVersion: 4.3.1\n", ""], ids=["header-only", "zero-bytes"]
    )
    def test_lockfile_with_no_packages_is_clean(self, tmp_path: Path, content):
        self._lock(tmp_path, content)
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert diags == []


class TestRenvLock:
    def test_no_entry_that_can_be_read_is_a_gap(self, tmp_path: Path):
        lock = tmp_path / "renv.lock"
        lock.write_text(json.dumps({"Packages": {"ggplot2": "3.4.0", "rlang": "1.1.0"}}))
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert _gaps(diags) == {
            (lock, _UNREAD),
            (lock, _WRONG_TYPE.format('an entry of "Packages"')),
        }

    @pytest.mark.parametrize("document", [{"R": {"Version": "4.3.1"}}, {"Packages": {}}])
    def test_lockfile_with_no_packages_is_clean(self, tmp_path: Path, document):
        (tmp_path / "renv.lock").write_text(json.dumps(document))
        rows, diags = _resolve(tmp_path)
        assert rows == set()
        assert diags == []


class TestCheckCommand:
    """A lockfile the parser cannot use, beside the manifest it belongs to.

    The direct dependency is still resolved, through the registry; the
    lockfile is a gap on stderr and in the JSON report; only ``--strict``
    fails on it; and without the lockfile the same scan passes ``--strict``.
    """

    @respx.mock
    @pytest.mark.parametrize(
        ("lockfile", "content", "reason"),
        [
            pytest.param(
                "pnpm-lock.yaml",
                "lockfileVersion: 5.4\n\npackages:\n\n  /left-pad/1.0.0:\n"
                "    resolution: {integrity: sha512-x}\n    dev: false\n",
                _VERSION,
                id="pnpm-version-5",
            ),
            pytest.param(
                "pnpm-lock.yaml",
                "packages:\n\n  /left-pad/1.0.0:\n    resolution: {integrity: sha512-x}\n",
                _UNREAD,
                id="pnpm-keys-in-a-form-not-read",
            ),
            pytest.param(
                "yarn.lock",
                "# yarn lockfile v1\n\n\n<<<<<<< HEAD\nleft-pad@1.0.0:\n"
                '  version "1.0.0"\n=======\nleft-pad@1.0.0:\n  version "1.0.1"\n>>>>>>> feature\n',
                _CONFLICT,
                id="yarn-merge-conflict",
            ),
        ],
    )
    def test_unusable_lockfile_beside_its_manifest(self, tmp_path: Path, lockfile, content, reason):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT", "dependencies": {"left-pad": "1.0.0"}})
        )
        bad = tmp_path / lockfile
        bad.write_text(content, encoding="utf-8", newline="\n")
        _mock_npm("left-pad", "MIT")

        _assert_gap_fails_only_strict(
            tmp_path, bad, reason, [("left-pad", "MIT")], repair=bad.unlink
        )

    @respx.mock
    def test_lockfile_that_filters_to_nothing_passes_strict(self, tmp_path: Path):
        # Only a dev package is locked and dev is not requested: the lockfile
        # is read in full, nothing is reported, and that is not a gap.
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT", "devDependencies": {"left-pad": "1.0.0"}})
        )
        _write(
            tmp_path / "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages:\n  left-pad@1.0.0: {}\n"
            "snapshots:\n  left-pad@1.0.0: {}\n",
        )
        result, data = _check_json(tmp_path, "--strict", "--no-dev")
        assert result.exit_code == 0
        assert data["dependencies"] == []
        assert data["summary"]["gaps"] == 0
        assert data["diagnostics"] == []

    @respx.mock
    @pytest.mark.parametrize(
        ("lockfile", "content"),
        [
            pytest.param(
                "yarn.lock",
                '__metadata:\n  version: 11\n\n"left-pad@npm:^1.0.0":\n  version: 1.0.7\n',
                id="yarn-berry",
            ),
            pytest.param(
                "pnpm-lock.yaml",
                "lockfileVersion: '10.0'\npackages:\n  left-pad@1.0.7: {}\n"
                "snapshots:\n  left-pad@1.0.7: {}\n",
                id="pnpm",
            ),
            pytest.param(
                "package-lock.json",
                json.dumps(
                    {
                        "lockfileVersion": 4,
                        "packages": {"node_modules/left-pad": {"version": "1.0.7"}},
                    }
                ),
                id="package-lock",
            ),
        ],
    )
    def test_lockfile_in_a_newer_version_is_read_and_passes_strict(
        self, tmp_path: Path, lockfile, content
    ):
        # The locked version is what is reported, not what the registry would
        # pick: the registry also has 1.3.0, which is what a walk from the
        # manifest's ``^1.0.0`` selects. The unknown version is a warning on
        # stderr and a ``recovered`` entry in the report, and it fails nothing.
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "license": "MIT", "dependencies": {"left-pad": "^1.0.0"}})
        )
        (tmp_path / lockfile).write_text(content, encoding="utf-8", newline="\n")
        versions = {v: {"license": "MIT", "version": v} for v in ("1.0.7", "1.3.0")}
        registry = "https://registry.npmjs.org/left-pad"
        respx.get(registry).mock(return_value=httpx.Response(200, json={"versions": versions}))
        respx.get(f"{registry}/latest").mock(
            return_value=httpx.Response(200, json=versions["1.3.0"])
        )
        for version, meta in versions.items():
            respx.get(f"{registry}/{version}").mock(return_value=httpx.Response(200, json=meta))

        result, data = _check_json(tmp_path, "--strict")

        assert result.exit_code == 0
        assert f"Warning: {lockfile}: {_NEWER}" in result.output
        assert "could not be fully analyzed" not in result.output
        assert [(d["name"], d["resolved_version"]) for d in data["dependencies"]] == [
            ("left-pad", "1.0.7")
        ]
        assert data["summary"]["gaps"] == 0
        assert data["diagnostics"] == [
            {"path": lockfile, "reason": _NEWER, "severity": "recovered"}
        ]
