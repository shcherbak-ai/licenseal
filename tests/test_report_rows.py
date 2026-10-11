"""A report holds one row per package, resolved version, and origin.

Every declared constraint is resolved and walked on its own, but what two of
them resolve to can be the same thing: one version, or no version at all.
Rows that agree on ecosystem, name, resolved version, and origin are one row
in every scan mode, so that tuple is a key of the JSON ``dependencies`` array
and the table never shows one line twice.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import _merge_duplicate_rows, main
from licenseal.models import Dependency, DependencyGroup, Ecosystem, LicenseInfo
from licenseal.review import REVIEW_FILE_NAME, flagged_entries_from_json_report
from tests._helpers import _check_json, _write

_PROD, _DEV = DependencyGroup.PROD, DependencyGroup.DEV

_NOT_SCAFFOLDED = (
    "Note: 1 flagged dependency could not be scaffolded (no resolved version, usually a "
    "manifest typo / yanked release / registry miss): npm:unpublished."
)


def _row_keys(data: dict) -> list[tuple[str, str, str, str]]:
    return [
        (dep["ecosystem"], dep["name"], dep["resolved_version"], dep["origin"])
        for dep in data["dependencies"]
    ]


def _assert_one_row_per_key(data: dict) -> None:
    keys = _row_keys(data)
    assert len(set(keys)) == len(keys)


# --------------------------------------------------------------- in a scan


def _project(root: Path, *, first_section: str = "dependencies") -> None:
    """Two manifests that declare one unpublished package, with different constraints."""
    _write(
        root / "apps" / "one" / "package.json",
        json.dumps({"name": "one", first_section: {"unpublished": "^1.0.0"}}),
    )
    _write(
        root / "apps" / "two" / "package.json",
        json.dumps(
            {"name": "two", "dependencies": {"unpublished": "^2.0.0", "published": "1.0.0"}}
        ),
    )
    meta = {"name": "published", "version": "1.0.0", "license": "MIT"}
    respx.get("https://registry.npmjs.org/published").mock(
        return_value=httpx.Response(200, json={"versions": {"1.0.0": meta}})
    )
    respx.get("https://registry.npmjs.org/published/1.0.0").mock(
        return_value=httpx.Response(200, json=meta)
    )
    # The registry does not know the other package: neither range resolves.
    respx.route(url__regex=r"https://.*").mock(return_value=httpx.Response(404))


def _requests_for(name: str) -> list[str]:
    return [str(call.request.url) for call in respx.calls if f"/{name}" in str(call.request.url)]


class TestTwoDeclarationsThatDoNotResolve:
    @respx.mock
    @pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
    def test_check_reports_one_row(self, tmp_path, mode):
        _project(tmp_path)

        result, data = _check_json(tmp_path, mode, "--no-strict", "--no-require-lockfile")

        assert result.exit_code == 0
        _assert_one_row_per_key(data)
        assert _row_keys(data) == [
            ("npm", "published", "1.0.0", ""),
            ("npm", "unpublished", "", ""),
        ]
        row = data["dependencies"][1]
        # The row of the first declaration.
        assert (row["source"], row["depth"], row["group"]) == ("apps/one/package.json", 0, "prod")
        assert (row["license"], row["verdict"]) == ("UNKNOWN", "unknown")
        assert data["summary"]["total"] == 2
        assert data["summary"]["unknown"] == 1
        # Both declarations were looked up; the merge is of what they came to.
        assert _requests_for("unpublished")

    @respx.mock
    @pytest.mark.parametrize("mode", ["--transitive", "--no-transitive"])
    def test_row_ships_when_either_declaration_does(self, tmp_path, mode):
        _project(tmp_path, first_section="devDependencies")
        flags = (mode, "--no-strict", "--no-require-lockfile")

        _, with_dev = _check_json(tmp_path, "--dev", *flags)
        _, without_dev = _check_json(tmp_path, "--no-dev", *flags)

        for data in (with_dev, without_dev):
            _assert_one_row_per_key(data)
            (row,) = [dep for dep in data["dependencies"] if dep["name"] == "unpublished"]
            assert row["group"] == "prod"
        # With --dev the dev manifest's declaration comes first, and the row
        # is production because the other declaration is.
        (row,) = [dep for dep in with_dev["dependencies"] if dep["name"] == "unpublished"]
        assert row["source"] == "apps/one/package.json"

    @respx.mock
    @pytest.mark.parametrize("output_format", ["markdown", "table"])
    def test_the_line_is_shown_once(self, tmp_path, output_format):
        _project(tmp_path)
        out = tmp_path / "report.txt"

        result = CliRunner().invoke(
            main,
            [
                "check",
                "--path",
                str(tmp_path),
                "--no-strict",
                "--no-require-lockfile",
                "-f",
                output_format,
                "-o",
                str(out),
            ],
        )

        assert result.exit_code == 0, result.output
        report = out.read_text(encoding="utf-8")
        # A row of the dependency table starts with the column separator; the
        # line under Details that explains the row does not.
        separator = "|" if output_format == "markdown" else "│"
        rows = [
            line
            for line in report.splitlines()
            if line.startswith(separator) and "unpublished" in line
        ]
        assert len(rows) == 1

    @respx.mock
    def test_init_review_file_names_it_once(self, tmp_path):
        _project(tmp_path)

        result = CliRunner().invoke(main, ["init-review-file", "--path", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert _NOT_SCAFFOLDED in result.output
        assert not (tmp_path / REVIEW_FILE_NAME).exists()

    @respx.mock
    def test_init_review_file_from_a_report_names_it_once(self, tmp_path):
        _project(tmp_path)
        _check_json(tmp_path, "--no-strict", "--no-require-lockfile")

        result = CliRunner().invoke(
            main,
            [
                "init-review-file",
                "--path",
                str(tmp_path),
                "--from-report",
                str(tmp_path / "report.json"),
            ],
        )

        assert result.exit_code == 0, result.output
        assert _NOT_SCAFFOLDED in result.output


class TestSavedReportThatRepeatsARow:
    """A report written before the rule held is read as one that obeys it."""

    @staticmethod
    def _report(tmp_path: Path, *rows: dict) -> Path:
        report = tmp_path / "report.json"
        report.write_text(json.dumps({"dependencies": list(rows)}), encoding="utf-8")
        return report

    @staticmethod
    def _row(name: str, version: str = "", origin: str = "", ecosystem: str = "npm") -> dict:
        return {
            "name": name,
            "ecosystem": ecosystem,
            "resolved_version": version,
            "origin": origin,
            "verdict": "unknown",
        }

    def test_unresolved_row_listed_twice_is_named_once(self, tmp_path):
        report = self._report(tmp_path, self._row("unpublished"), self._row("unpublished"))

        entries, unscaffoldable = flagged_entries_from_json_report(report)

        assert entries == []
        assert unscaffoldable == ["npm:unpublished"]

    def test_rows_that_differ_in_version_or_origin_are_each_read(self, tmp_path):
        report = self._report(
            tmp_path,
            self._row("pkg", "1.0.0"),
            self._row("pkg", "1.0.0"),
            self._row("pkg", "2.0.0"),
            self._row("pkg"),
            self._row("pkg", origin="git+https://git.example.org/pkg.git@abc"),
            # Another package in npm; the same package in NuGet.
            self._row("Pkg", "1.0.0"),
            self._row("pkg", "1.0.0", ecosystem="dotnet"),
            self._row("Pkg", "1.0.0", ecosystem="dotnet"),
        )

        entries, unscaffoldable = flagged_entries_from_json_report(report)

        assert [(e.ecosystem, e.name, e.version, e.origin) for e in entries] == [
            ("npm", "pkg", "1.0.0", ""),
            ("npm", "pkg", "2.0.0", ""),
            ("npm", "pkg", "", "git+https://git.example.org/pkg.git@abc"),
            ("npm", "Pkg", "1.0.0", ""),
            ("dotnet", "pkg", "1.0.0", ""),
        ]
        assert unscaffoldable == ["npm:pkg"]


# ------------------------------------------------------------- the merge


def _info(
    name: str,
    constraint: str,
    resolved: str,
    group: DependencyGroup = _PROD,
    *,
    ecosystem: Ecosystem = Ecosystem.PYTHON,
    **fields,
) -> LicenseInfo:
    dep = Dependency(
        name=name, version_constraint=constraint, ecosystem=ecosystem, group=group, **fields
    )
    return LicenseInfo(
        dependency=dep, license_id="MIT", license_raw="MIT", resolved_version=resolved
    )


def _shape(infos: list[LicenseInfo]) -> list[tuple[str, str, DependencyGroup]]:
    return [(info.dependency.name, info.resolved_version, info.dependency.group) for info in infos]


class TestMergeDuplicateRows:
    def test_one_row_per_package_and_resolved_version(self):
        merged = _merge_duplicate_rows(
            [
                _info("shared", ">=1.0", "2.0.0", _DEV, source="a"),
                _info("other", "==1.0", "1.0.0"),
                # The same package under PEP 503, shipped: the row is production.
                _info("Shared", ">=1.5", "2.0.0", _PROD, source="b"),
                _info("shared", ">=1.9", "2.0.0", _DEV, source="c"),
                # Another version is another row.
                _info("shared", "==1.0.0", "1.0.0", _DEV),
            ]
        )

        assert _shape(merged) == [
            ("shared", "2.0.0", _PROD),
            ("other", "1.0.0", _PROD),
            ("shared", "1.0.0", _DEV),
        ]
        # The first declaration is the one reported.
        first = merged[0].dependency
        assert (first.version_constraint, first.source) == (">=1.0", "a")

    def test_declarations_that_resolve_to_no_version_are_one_row(self):
        merged = _merge_duplicate_rows(
            [
                _info("shared", ">=1.0", "", _DEV, source="a"),
                _info("shared", ">=2.0", "", _DEV, source="b"),
                _info("other", ">=1.0", ""),
            ]
        )

        assert _shape(merged) == [("shared", "", _DEV), ("other", "", _PROD)]
        assert merged[0].dependency.source == "a"

    def test_name_is_compared_by_the_ecosystem_s_rule(self):
        def rows(ecosystem: Ecosystem) -> list[str]:
            infos = [
                _info("Widget", "^1", "", ecosystem=ecosystem),
                _info("widget", "^2", "", ecosystem=ecosystem),
            ]
            return [info.dependency.name for info in _merge_duplicate_rows(infos)]

        assert rows(Ecosystem.DOTNET) == ["Widget"]
        assert rows(Ecosystem.NPM) == ["Widget", "widget"]

    def test_origin_is_part_of_the_row(self):
        commit_a = "git+https://git.example.org/f.git@a"
        commit_b = "git+https://git.example.org/f.git@b"
        infos = [
            _info("forked", "", "1.0.0", origin=commit_a),
            _info("forked", "", "1.0.0", origin=commit_b),
            _info("forked", "", "1.0.0"),
            _info("forked", "", "", origin=commit_a),
        ]

        assert _merge_duplicate_rows(infos) == infos
        # The same commit at the same version, declared twice, is one row.
        again = [*infos, _info("forked", "==1.0.0", "1.0.0", origin=commit_b)]
        assert _merge_duplicate_rows(again) == infos

    def test_direct_declaration_wins_over_a_transitive_requirement(self):
        merged = _merge_duplicate_rows(
            [
                _info("shared", ">=3", "", _DEV, depth=2, direct_ancestors=("host",)),
                _info("shared", ">=1", "", _DEV, source="first-manifest"),
                _info("shared", ">=2", "", _PROD, source="second-manifest"),
            ]
        )

        (row,) = merged
        dep = row.dependency
        # The lowest depth, and the first declaration at it.
        assert (dep.depth, dep.source, dep.version_constraint) == (0, "first-manifest", ">=1")
        assert dep.group == _PROD
        # A direct dependency lists no ancestors.
        assert dep.direct_ancestors == ()

    def test_merged_transitive_lists_the_ancestors_and_extras_of_all(self):
        merged = _merge_duplicate_rows(
            [
                _info(
                    "shared",
                    ">=1",
                    "",
                    _DEV,
                    depth=2,
                    direct_ancestors=("b", "c"),
                    extras=frozenset({"x"}),
                    version_estimated=True,
                ),
                _info(
                    "shared",
                    ">=2",
                    "",
                    _DEV,
                    depth=1,
                    direct_ancestors=("a", "b"),
                    extras=frozenset({"y"}),
                    version_estimated=True,
                ),
            ]
        )

        (row,) = merged
        dep = row.dependency
        assert (dep.depth, dep.version_constraint, dep.group) == (1, ">=2", _DEV)
        assert dep.direct_ancestors == ("a", "b", "c")
        assert dep.extras == frozenset({"x", "y"})
        assert dep.version_estimated is True

    def test_version_is_an_estimate_only_when_every_declaration_s_is(self):
        merged = _merge_duplicate_rows(
            [
                _info("shared", ">=1.0", "2.0.0", version_estimated=True),
                _info("shared", "==2.0.0", "2.0.0"),
            ]
        )

        (row,) = merged
        assert row.dependency.version_estimated is False
        assert row.dependency.version_constraint == ">=1.0"
