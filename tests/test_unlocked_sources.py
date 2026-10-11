"""An off-registry dependency that no lockfile records leaves a hole in the report.

Nothing is fetched for a git repository, a URL, or a path, so the registry
packages such a dependency requires are listed only by a lockfile. A manifest
that declares one for which no lockfile holds a row is recorded as lacking a
lockfile: an analysis gap by default, an estimate under
``--no-require-lockfile``. The row itself is the UNKNOWN row it always was.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from tests._helpers import _check_json, _write
from tests.test_source_coverage import (
    _FORMATS,
    _GIT,
    _MANIFESTS,
    _MISSING,
    _UNRECORDED,
    _mock_registries,
    _review,
    _rows,
)


def _diagnostics(data: dict) -> list[tuple[str, str, str]]:
    """Each diagnostic as ``(path, reason, severity)``, sorted."""
    return sorted((d["path"], d["reason"], d["severity"]) for d in data["diagnostics"])


class TestOffRegistryDependencyNoLockfileRecords:
    @respx.mock
    @pytest.mark.parametrize("layout", _MANIFESTS)
    def test_manifest_is_a_gap_that_a_review_of_the_row_does_not_clear(self, tmp_path, layout):
        fmt = _FORMATS[layout]
        _write(tmp_path / fmt.manifest, fmt.sourced("team", "v9"))
        _mock_registries()
        origin = fmt.declared("team", "v9")
        _review(tmp_path, fmt, origin)

        result, data = _check_json(tmp_path)

        assert result.exit_code == 1
        assert _rows(data) == [(fmt.name, origin, "", "UNKNOWN", fmt.manifest)]
        (row,) = data["dependencies"]
        # The row is as it was: reviewed, and no estimate.
        assert (row["reviewed"], row["estimated"]) == (True, [])
        assert _diagnostics(data) == [(fmt.manifest, _UNRECORDED, "gap")]
        assert data["summary"]["gaps"] == 1
        assert f"Warning: {fmt.manifest}: {_UNRECORDED}" in result.output

        accepted, data = _check_json(tmp_path, "--no-require-lockfile")
        assert accepted.exit_code == 0
        assert _diagnostics(data) == [(fmt.manifest, _UNRECORDED, "estimate")]
        assert data["summary"]["gaps"] == 0

    @respx.mock
    @pytest.mark.parametrize("layout", sorted(_FORMATS))
    def test_lockfile_that_records_it_leaves_no_diagnostic(self, tmp_path, layout):
        fmt = _FORMATS[layout]
        _write(tmp_path / fmt.manifest, fmt.sourced("team", "v9"))
        _write(tmp_path / fmt.lockfile, fmt.sourced_lock)
        _mock_registries()
        _review(tmp_path, fmt, fmt.locked)

        result, data = _check_json(tmp_path)

        assert result.exit_code == 0
        assert _rows(data) == [(fmt.name, fmt.locked, fmt.locked_version, "UNKNOWN", fmt.manifest)]
        assert data["diagnostics"] == []

    @respx.mock
    def test_registry_and_off_registry_dependencies_are_one_gap_with_two_reasons(self, tmp_path):
        _write(
            tmp_path / "package.json",
            json.dumps(
                {"name": "app", "dependencies": {"shared": "1.0.0", "forked": "github:team/forked"}}
            ),
        )
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert _diagnostics(data) == [
            ("package.json", _MISSING, "gap"),
            ("package.json", _UNRECORDED, "gap"),
        ]
        assert data["summary"]["gaps"] == 1


class TestNoLockfileIsAskedFor:
    """What is exempt from the missing-lockfile diagnostic stays exempt."""

    @respx.mock
    def test_direct_only_scan_consults_no_lockfile(self, tmp_path):
        fmt = _FORMATS["package-lock"]
        _write(tmp_path / fmt.manifest, fmt.sourced("team", "v9"))
        _mock_registries()
        _review(tmp_path, fmt, fmt.declared("team", "v9"))

        result, data = _check_json(tmp_path, "--no-transitive")

        assert result.exit_code == 0
        assert data["diagnostics"] == []

    @respx.mock
    def test_dev_only_dependency_follows_the_dev_flag(self, tmp_path):
        _write(
            tmp_path / "package.json",
            json.dumps({"name": "app", "devDependencies": {"shared": "github:team/shared#v9"}}),
        )
        _mock_registries()

        result, data = _check_json(tmp_path)
        assert result.exit_code == 0
        assert (data["dependencies"], data["diagnostics"]) == ([], [])

        _, data = _check_json(tmp_path, "--dev")
        assert _diagnostics(data) == [("package.json", _UNRECORDED, "gap")]

    @respx.mock
    @pytest.mark.parametrize(
        ("manifest", "content", "flags"),
        [
            pytest.param(
                "go.mod",
                "module example.com/app\n\ngo 1.22\n\nrequire example.org/shared v1.0.0\n\n"
                "replace example.org/shared => ../outside/shared\n",
                (),
                id="go",
            ),
            pytest.param(
                "pom.xml",
                '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
                "  <modelVersion>4.0.0</modelVersion>\n"
                "  <groupId>org.example</groupId><artifactId>app</artifactId>"
                "<version>1.0.0</version>\n"
                "  <dependencies><dependency>\n"
                "    <groupId>com.vendor</groupId><artifactId>shared</artifactId>"
                "<version>1.0</version>\n"
                "    <scope>system</scope><systemPath>${basedir}/lib/shared.jar</systemPath>\n"
                "  </dependency></dependencies>\n</project>\n",
                ("--dev",),
                id="maven",
            ),
            pytest.param(
                "Makefile",
                "PROJECT = app\nDEPS = shared\n"
                "dep_shared = git https://git.example.org/team/shared v9\ninclude erlang.mk\n",
                (),
                id="erlang-mk",
            ),
        ],
    )
    def test_tool_with_no_lockfile_to_ask_for(self, tmp_path, manifest, content, flags):
        _write(tmp_path / manifest, content)
        _mock_registries()

        result, data = _check_json(tmp_path, *flags)

        assert result.exit_code == 1
        (row,) = data["dependencies"]
        assert (row["license"], bool(row["origin"])) == ("UNKNOWN", True)
        assert data["diagnostics"] == []


_MIX_APP = (
    "defmodule Web.MixProject do\n  use Mix.Project\n\n"
    '  def project do\n    [app: :web, version: "0.1.0", deps: deps()]\n  end\n\n'
    "  defp deps do\n    [{0}]\n  end\nend\n"
)
_MIX_LOCK = '%{\n  "shared": {:hex, :shared, "1.0.0", "h", [:mix], [], "hexpm", "h2"},\n}\n'
_CSPROJ = (
    '<Project Sdk="Microsoft.NET.Sdk">\n  <ItemGroup>\n'
    '    <PackageReference Include="Shared" Version="1.0.0" />\n'
    '    <ProjectReference Include="..\\..\\..\\outside\\Lib\\Lib.csproj" />\n'
    "  </ItemGroup>\n</Project>\n"
)
_PACKAGES_LOCK = json.dumps(
    {
        "version": 1,
        "dependencies": {"net8.0": {"Shared": {"type": "Direct", "resolved": "1.0.0"}}},
    }
)
_PROJECT_ASSETS = json.dumps(
    {
        "version": 3,
        "targets": {"net8.0": {"Shared/1.0.0": {"type": "package"}}},
        "project": {
            "frameworks": {"net8.0": {"dependencies": {"Shared": {"version": "[1.0.0, )"}}}}
        },
    }
)


def _mock_nuget() -> None:
    """Publish ``Shared`` 1.0.0 on NuGet; registered before the catch-all refusal."""
    respx.get("https://api.nuget.org/v3-flatcontainer/shared/1.0.0/shared.nuspec").mock(
        return_value=httpx.Response(
            200,
            text=(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
                "<metadata><id>Shared</id><version>1.0.0</version>"
                '<license type="expression">MIT</license></metadata></package>'
            ),
        )
    )


class TestPathDependencyALockfileNeverLists:
    """Two lockfile formats hold no row for a path dependency.

    ``mix.lock`` has no entry for a Mix ``path:`` dependency, and the NuGet
    lockfiles list a ``<ProjectReference>`` with no version. Both record the
    packages such a dependency requires, so nothing is missing from the
    report, and no diagnostic is asked of the manifest, when a lockfile sits
    where the tool writes it for that manifest.
    """

    @staticmethod
    def _mix(root: Path, lock_at: str, other: str = '{:outside, path: "../../../outside"}') -> None:
        deps = f'{{:shared, "1.0.0"}}, {other}'
        _write(root / "apps" / "web" / "mix.exs", _MIX_APP.replace("{0}", deps))
        if lock_at:
            _write(root / lock_at, _MIX_LOCK)

    @respx.mock
    @pytest.mark.parametrize("lock_at", ["apps/web/mix.lock", "mix.lock"])
    def test_mix_lock_beside_the_mix_exs_or_above_it(self, tmp_path, lock_at):
        self._mix(tmp_path, lock_at)
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert sorted((d["name"], d["origin"]) for d in data["dependencies"]) == [
            ("outside", "../../../outside"),
            ("shared", ""),
        ]
        assert data["diagnostics"] == []

    @respx.mock
    def test_mix_exs_with_no_mix_lock(self, tmp_path):
        self._mix(tmp_path, "")
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert _diagnostics(data) == [
            ("apps/web/mix.exs", _MISSING, "gap"),
            ("apps/web/mix.exs", _UNRECORDED, "gap"),
        ]

    @respx.mock
    def test_mix_lock_of_another_project_is_not_this_one_s(self, tmp_path):
        # It still covers the registry package, as any lockfile of the scan
        # does; it says nothing of what this project's path dependency needs.
        self._mix(tmp_path, "apps/other/mix.lock")
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert _diagnostics(data) == [("apps/web/mix.exs", _UNRECORDED, "gap")]

    @respx.mock
    def test_repository_missing_from_the_mix_lock_is_still_reported(self, tmp_path):
        # A mix.lock does hold a row for a git dependency: without one it is stale.
        self._mix(tmp_path, "mix.lock", f'{{:forked, git: "{_GIT}/team/forked.git"}}')
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert _diagnostics(data) == [("apps/web/mix.exs", _UNRECORDED, "gap")]

    @respx.mock
    @pytest.mark.parametrize(
        ("lock_at", "content"),
        [
            ("src/App/packages.lock.json", _PACKAGES_LOCK),
            ("src/App/obj/project.assets.json", _PROJECT_ASSETS),
        ],
        ids=["packages.lock.json", "project.assets.json"],
    )
    def test_nuget_lockfile_of_the_project(self, tmp_path, lock_at, content):
        _write(tmp_path / "src" / "App" / "App.csproj", _CSPROJ)
        _write(tmp_path / lock_at, content)
        _mock_nuget()
        _mock_registries()

        _, data = _check_json(tmp_path)

        assert sorted((d["name"], d["origin"]) for d in data["dependencies"]) == [
            ("Lib", "..\\..\\..\\outside\\Lib\\Lib.csproj"),
            ("Shared", ""),
        ]
        assert data["diagnostics"] == []

    @respx.mock
    @pytest.mark.parametrize("lock_at", ["", "src/Other/packages.lock.json"])
    def test_project_file_with_no_nuget_lockfile_of_its_own(self, tmp_path, lock_at):
        _write(tmp_path / "src" / "App" / "App.csproj", _CSPROJ)
        if lock_at:
            _write(tmp_path / lock_at, _PACKAGES_LOCK)
        _mock_nuget()
        _mock_registries()

        _, data = _check_json(tmp_path)

        expected = [("src/App/App.csproj", _UNRECORDED, "gap")]
        if not lock_at:
            expected.insert(0, ("src/App/App.csproj", _MISSING, "gap"))
        assert _diagnostics(data) == expected
