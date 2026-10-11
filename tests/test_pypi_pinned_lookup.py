"""What a pinned PyPI release gets when its own endpoint gives no metadata.

The answer depends on why. A 404 says PyPI has no such release (a build
from another index, a ``+local`` version): another release then stands in
for its license, which is reported as an estimate under the pinned version.
A lookup that failed says nothing about the release, so nothing is borrowed
and the dependency is UNKNOWN unless deps.dev has that exact version.

A release that a range selects from the project's release list is answered the
same way as a pinned one, with the dependency walk and without it.

The same holds one step on, for a release whose own JSON declares no license.
Its wheel metadata is read next. A 404 says the wheel has no metadata sidecar,
and the license of the latest release is then borrowed as an estimate; a
sidecar lookup that failed leaves the release's license undetermined.

The resolver tests read through ``RegistryCache``, which is where a 404 is
told from a failed lookup; the others scan files on disk.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import CliRunner

from licenseal.cli import main
from licenseal.models import Dependency, Ecosystem, LicenseInfo
from licenseal.resolvers.http import RegistryCache, fetch_pep658_metadata, fetch_registry_json
from licenseal.resolvers.pypi import resolve_python_license
from tests._helpers import _check_json, _write

_PYPI = "https://pypi.org/pypi"
_DEPS_DEV = "https://api.deps.dev/v3/systems/PYPI/packages"
_WHEEL = "https://files.pythonhosted.org/packages/aa/bb/pkg_a-1.2.3-py3-none-any.whl"
_SIDECAR = _WHEEL + ".metadata"

# Each way a lookup can end without the registry saying "no such release": a
# response served on every attempt, or an error raised on every attempt.
_FAILURES: dict[str, Callable[[], httpx.Response | Exception]] = {
    "500": lambda: httpx.Response(500),
    "502": lambda: httpx.Response(502),
    "503": lambda: httpx.Response(503),
    "504": lambda: httpx.Response(504),
    "429": lambda: httpx.Response(429),
    "403": lambda: httpx.Response(403),
    "410": lambda: httpx.Response(410),
    "json-array": lambda: httpx.Response(200, json=["not", "an", "object"]),
    "not-json": lambda: httpx.Response(200, text="<html>maintenance</html>"),
    "connection-error": lambda: httpx.ConnectError("connection refused"),
    "connect-timeout": lambda: httpx.ConnectTimeout("timed out"),
    "read-timeout": lambda: httpx.ReadTimeout("timed out"),
}

# The ways a sidecar lookup can fail. An answer with a body is not one of
# them: the wheel then has metadata, whatever it holds.
_SIDECAR_FAILURES = [name for name in _FAILURES if name not in {"json-array", "not-json"}]


def _fail(url: str, failure: str) -> respx.Route:
    """Make every request to ``url`` end the way ``failure`` names."""
    outcome = _FAILURES[failure]()
    if isinstance(outcome, Exception):
        return respx.get(url).mock(side_effect=outcome)
    return respx.get(url).mock(return_value=outcome)


def _serve(url: str, status: int = 404, body: dict | None = None) -> respx.Route:
    return respx.get(url).mock(return_value=httpx.Response(status, json=body))


def _release(version: str, license_expression: str | None = None, **extra: object) -> dict:
    """A release's JSON: its version, a license when given, no dependencies."""
    info: dict[str, object] = {"version": version, "requires_dist": []}
    if license_expression is not None:
        info["license_expression"] = license_expression
    return {"info": info, **extra}


def _release_with_a_wheel(version: str) -> dict:
    """A release's JSON that declares no license and names a wheel."""
    return _release(version, urls=[{"packagetype": "bdist_wheel", "url": _WHEEL}])


def _resolve(spec: str) -> LicenseInfo:
    """Resolve ``pkg-a`` at ``spec`` through a per-scan cache, as the CLI does."""
    cache = RegistryCache()
    dep = Dependency(name="pkg-a", version_constraint=spec, ecosystem=Ecosystem.PYTHON)
    with httpx.Client() as client:
        return resolve_python_license(
            dep,
            client,
            fetcher=cache.fetch,
            pep658_fetcher=cache.fetch_pep658,
            not_found=cache.not_found,
        )


def _summary(info: LicenseInfo) -> tuple[str, str, bool, bool]:
    """``(license, reported version, license is an estimate, registry answered)``."""
    return info.license_id, info.resolved_version, info.license_estimated, info.from_registry


class TestReleaseMissingFromPyPI:
    """A 404 for the pinned release: another release stands in for its license."""

    @respx.mock
    def test_latest_release_license_is_an_estimate_under_the_pinned_version(self):
        _serve(f"{_PYPI}/pkg-a/1.0.0/json")
        _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        info = _resolve("==1.0.0")
        assert _summary(info) == ("MIT", "1.0.0", True, True)
        # The pin is the version reported, so the version is no estimate.
        assert info.dependency.version_estimated is False

    @respx.mock
    def test_local_version_reads_the_public_release_before_the_latest_one(self):
        # The project changed its license after 1.2.3: the public release the
        # local build was made from says GPL, the latest release says MIT.
        _serve(f"{_PYPI}/pkg-a/1.2.3+internal/json")
        _serve(f"{_PYPI}/pkg-a/1.2.3/json", 200, _release("1.2.3", "GPL-3.0-only"))
        latest = _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        info = _resolve("==1.2.3+internal")
        # Still an estimate: a local build is not the public release.
        assert _summary(info) == ("GPL-3.0-only", "1.2.3+internal", True, True)
        assert not latest.called

    @respx.mock
    def test_local_version_reads_the_wheel_metadata_of_the_public_release(self):
        _serve(f"{_PYPI}/pkg-a/1.2.3+internal/json")
        _serve(
            f"{_PYPI}/pkg-a/1.2.3/json",
            200,
            _release("1.2.3", urls=[{"packagetype": "bdist_wheel", "url": _WHEEL}]),
        )
        respx.get(_WHEEL + ".metadata").mock(
            return_value=httpx.Response(
                200, text="Metadata-Version: 2.4\nLicense-Expression: GPL-3.0-only\n\n"
            )
        )
        latest = _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        info = _resolve("==1.2.3+internal")
        assert _summary(info) == ("GPL-3.0-only", "1.2.3+internal", True, True)
        assert not latest.called

    @respx.mock
    def test_local_version_of_a_public_release_without_a_license_takes_the_latest_one(self):
        _serve(f"{_PYPI}/pkg-a/1.2.3+internal/json")
        _serve(f"{_PYPI}/pkg-a/1.2.3/json", 200, _release("1.2.3"))
        _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        assert _summary(_resolve("==1.2.3+internal")) == ("MIT", "1.2.3+internal", True, True)

    @respx.mock
    def test_local_version_without_a_public_release_takes_the_latest_license(self):
        _serve(f"{_PYPI}/pkg-a/1.2.3+internal/json")
        public = _serve(f"{_PYPI}/pkg-a/1.2.3/json")
        _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        assert _summary(_resolve("==1.2.3+internal")) == ("MIT", "1.2.3+internal", True, True)
        assert public.called

    @pytest.mark.parametrize("failure", _FAILURES)
    @respx.mock
    def test_failed_lookup_of_the_public_release_borrows_nothing(
        self, failure, fake_registry_clock
    ):
        _serve(f"{_PYPI}/pkg-a/1.2.3+internal/json")
        _fail(f"{_PYPI}/pkg-a/1.2.3/json", failure)
        latest = _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        _serve(f"{_DEPS_DEV}/pkg-a/versions/1.2.3%2Binternal")
        info = _resolve("==1.2.3+internal")
        assert _summary(info) == ("UNKNOWN", "1.2.3+internal", False, False)
        assert not latest.called

    @respx.mock
    def test_project_pypi_does_not_have_at_all_is_unknown(self):
        _serve(f"{_PYPI}/pkg-a/1.0.0/json")
        _serve(f"{_PYPI}/pkg-a/json")
        _serve(f"{_DEPS_DEV}/pkg-a/versions/1.0.0")
        assert _summary(_resolve("==1.0.0")) == ("UNKNOWN", "1.0.0", False, False)

    @respx.mock
    def test_stand_in_release_without_a_license_is_unknown_under_the_pinned_version(self):
        _serve(f"{_PYPI}/pkg-a/1.0.0/json")
        _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0"))
        info = _resolve("==1.0.0")
        assert (info.license_id, info.resolved_version, info.from_registry) == (
            "UNKNOWN",
            "1.0.0",
            True,
        )


class TestFailedLookup:
    """A lookup that failed is not a missing release: nothing is borrowed."""

    @pytest.mark.parametrize("failure", _FAILURES)
    @respx.mock
    def test_pinned_release_is_unknown_and_the_latest_release_is_not_read(
        self, failure, fake_registry_clock
    ):
        _fail(f"{_PYPI}/pkg-a/1.0.0/json", failure)
        latest = _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        _serve(f"{_DEPS_DEV}/pkg-a/versions/1.0.0")
        info = _resolve("==1.0.0")
        assert _summary(info) == ("UNKNOWN", "1.0.0", False, False)
        assert info.dependency.version_estimated is False
        assert not latest.called

    @respx.mock
    def test_deps_dev_answer_for_that_exact_version_is_not_an_estimate(self, fake_registry_clock):
        _fail(f"{_PYPI}/pkg-a/1.0.0/json", "503")
        latest = _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        _serve(
            f"{_DEPS_DEV}/pkg-a/versions/1.0.0",
            200,
            {
                "versionKey": {"system": "PYPI", "name": "pkg-a", "version": "1.0.0"},
                "licenses": ["GPL-3.0-only"],
                "links": [],
            },
        )
        assert _summary(_resolve("==1.0.0")) == ("GPL-3.0-only", "1.0.0", False, True)
        assert not latest.called

    @respx.mock
    def test_lookup_that_recovers_within_its_retries_is_read_normally(self, fake_registry_clock):
        respx.get(f"{_PYPI}/pkg-a/1.0.0/json").mock(
            side_effect=[
                httpx.Response(503),
                httpx.ConnectError("reset"),
                httpx.Response(200, json=_release("1.0.0", "Apache-2.0")),
            ]
        )
        assert _summary(_resolve("==1.0.0")) == ("Apache-2.0", "1.0.0", False, True)

    @respx.mock
    def test_404_after_a_failed_attempt_is_a_missing_release(self, fake_registry_clock):
        respx.get(f"{_PYPI}/pkg-a/1.0.0/json").mock(
            side_effect=[httpx.Response(503), httpx.Response(404)]
        )
        _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        assert _summary(_resolve("==1.0.0")) == ("MIT", "1.0.0", True, True)


def _releases(latest: str, license_expression: str, *older: str) -> dict:
    """The project-level JSON: the ``latest`` release's metadata and every release listed."""
    return {
        **_release(latest, license_expression),
        "releases": {version: [] for version in (*older, latest)},
    }


class TestReleaseARangeSelects:
    """A range resolves to a release the project-level response lists. What
    that release gets when its own endpoint gives no metadata is what a
    pinned release gets.
    """

    @respx.mock
    def test_release_pypi_does_not_have_takes_the_latest_license_as_an_estimate(self):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("2.0.0", "MIT", "1.5.0"))
        _serve(f"{_PYPI}/pkg-a/1.5.0/json")
        assert _summary(_resolve(">=1.0,<2.0")) == ("MIT", "1.5.0", True, True)

    @respx.mock
    def test_latest_release_standing_in_for_itself_is_no_estimate(self):
        # The range selects the latest release, whose endpoint answers 404
        # while the project-level response describes that very release.
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("1.0", "MIT"))
        _serve(f"{_PYPI}/pkg-a/1.0/json")
        assert _summary(_resolve(">=1.0")) == ("MIT", "1.0", False, True)

    @pytest.mark.parametrize("failure", _FAILURES)
    @respx.mock
    def test_failed_lookup_borrows_nothing(self, failure, fake_registry_clock):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("2.0.0", "MIT", "1.5.0"))
        _fail(f"{_PYPI}/pkg-a/1.5.0/json", failure)
        exact = _serve(f"{_DEPS_DEV}/pkg-a/versions/1.5.0")
        assert _summary(_resolve(">=1.0,<2.0")) == ("UNKNOWN", "1.5.0", False, False)
        assert exact.called

    @respx.mock
    def test_deps_dev_answer_for_the_selected_version_is_not_an_estimate(self, fake_registry_clock):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("2.0.0", "MIT", "1.5.0"))
        _fail(f"{_PYPI}/pkg-a/1.5.0/json", "503")
        _serve(
            f"{_DEPS_DEV}/pkg-a/versions/1.5.0",
            200,
            {
                "versionKey": {"system": "PYPI", "name": "pkg-a", "version": "1.5.0"},
                "licenses": ["GPL-3.0-only"],
                "links": [],
            },
        )
        assert _summary(_resolve(">=1.0,<2.0")) == ("GPL-3.0-only", "1.5.0", False, True)

    @respx.mock
    def test_release_with_metadata_of_its_own_is_the_control(self):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("2.0.0", "MIT", "1.5.0"))
        _serve(f"{_PYPI}/pkg-a/1.5.0/json", 200, _release("1.5.0", "Apache-2.0"))
        assert _summary(_resolve(">=1.0,<2.0")) == ("Apache-2.0", "1.5.0", False, True)

    @respx.mock
    def test_range_no_release_satisfies_is_unknown_with_no_version(self):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("2.0.0", "MIT", "1.5.0"))
        assert _summary(_resolve(">=3.0")) == ("UNKNOWN", "", False, False)

    @respx.mock
    def test_plain_fetcher_borrows_nothing_for_a_404(self):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("2.0.0", "MIT", "1.5.0"))
        _serve(f"{_PYPI}/pkg-a/1.5.0/json")
        _serve(f"{_DEPS_DEV}/pkg-a/versions/1.5.0")
        dep = Dependency(name="pkg-a", version_constraint=">=1.0,<2.0", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert _summary(info) == ("UNKNOWN", "1.5.0", False, False)


class TestWheelMetadataLookup:
    """A release whose JSON declares no license and names a wheel: the wheel's
    metadata sidecar is read next, and what follows depends on why it gave
    nothing.
    """

    @staticmethod
    def _registry() -> respx.Route:
        """Release 1.0.0 declares nothing and has a wheel; the latest release is MIT.

        Returns the route of the project-level endpoint, which describes 2.0.0.
        """
        _serve(f"{_PYPI}/pkg-a/1.0.0/json", 200, _release_with_a_wheel("1.0.0"))
        latest = {**_release("2.0.0", "MIT"), "releases": {"1.0.0": [], "2.0.0": []}}
        return _serve(f"{_PYPI}/pkg-a/json", 200, latest)

    @pytest.mark.parametrize("failure", _SIDECAR_FAILURES)
    @respx.mock
    def test_failed_lookup_borrows_nothing(self, failure, fake_registry_clock):
        latest = self._registry()
        _fail(_SIDECAR, failure)
        exact = _serve(f"{_DEPS_DEV}/pkg-a/versions/1.0.0")
        assert _summary(_resolve("==1.0.0")) == ("UNKNOWN", "1.0.0", False, False)
        assert not latest.called
        assert exact.called

    @respx.mock
    def test_deps_dev_answer_for_that_exact_version_is_not_an_estimate(self, fake_registry_clock):
        latest = self._registry()
        _fail(_SIDECAR, "503")
        _serve(
            f"{_DEPS_DEV}/pkg-a/versions/1.0.0",
            200,
            {
                "versionKey": {"system": "PYPI", "name": "pkg-a", "version": "1.0.0"},
                "licenses": ["GPL-3.0-only"],
                "links": [],
            },
        )
        assert _summary(_resolve("==1.0.0")) == ("GPL-3.0-only", "1.0.0", False, True)
        assert not latest.called

    @respx.mock
    def test_wheel_with_no_sidecar_takes_the_latest_license_as_an_estimate(self):
        self._registry()
        _serve(_SIDECAR)
        assert _summary(_resolve("==1.0.0")) == ("MIT", "1.0.0", True, True)

    @pytest.mark.parametrize(
        "body",
        [
            pytest.param("Metadata-Version: 2.4\nName: pkg-a\n\n", id="no-license-header"),
            pytest.param("\x00\x01 not a metadata file", id="not-metadata"),
            pytest.param("", id="empty"),
        ],
    )
    @respx.mock
    def test_sidecar_with_no_license_takes_the_latest_license_as_an_estimate(self, body):
        self._registry()
        respx.get(_SIDECAR).mock(return_value=httpx.Response(200, text=body))
        assert _summary(_resolve("==1.0.0")) == ("MIT", "1.0.0", True, True)

    @respx.mock
    def test_lookup_that_recovers_within_its_retries_is_read_normally(self, fake_registry_clock):
        latest = self._registry()
        respx.get(_SIDECAR).mock(
            side_effect=[
                httpx.Response(503),
                httpx.ConnectError("reset"),
                httpx.Response(200, text="License-Expression: GPL-3.0-only\n\n"),
            ]
        )
        assert _summary(_resolve("==1.0.0")) == ("GPL-3.0-only", "1.0.0", False, True)
        assert not latest.called

    @respx.mock
    def test_404_after_a_failed_attempt_is_a_wheel_with_no_sidecar(self, fake_registry_clock):
        self._registry()
        respx.get(_SIDECAR).mock(side_effect=[httpx.Response(503), httpx.Response(404)])
        assert _summary(_resolve("==1.0.0")) == ("MIT", "1.0.0", True, True)

    @respx.mock
    def test_release_a_range_selects_borrows_nothing_either(self, fake_registry_clock):
        # The project-level response is already in hand, read for its release
        # list. It still does not answer for the release the range selected.
        self._registry()
        _fail(_SIDECAR, "503")
        exact = _serve(f"{_DEPS_DEV}/pkg-a/versions/1.0.0")
        assert _summary(_resolve(">=1.0,<2.0")) == ("UNKNOWN", "1.0.0", False, False)
        assert exact.called

    @respx.mock
    def test_stand_in_release_whose_sidecar_lookup_failed_answers_nothing(
        self, fake_registry_clock
    ):
        # PyPI does not have the pinned build, so its public release stands in,
        # and that release's license could not be determined. deps.dev is
        # asked for the pinned build, not for the stand-in.
        _serve(f"{_PYPI}/pkg-a/1.0.0+internal/json")
        latest = self._registry()
        _fail(_SIDECAR, "503")
        exact = _serve(f"{_DEPS_DEV}/pkg-a/versions/1.0.0%2Binternal")
        assert _summary(_resolve("==1.0.0+internal")) == (
            "UNKNOWN",
            "1.0.0+internal",
            False,
            False,
        )
        assert not latest.called
        assert exact.called


class TestWithoutLookupOutcomes:
    """With a fetcher that cannot tell a 404 from a failure, every miss is a failure."""

    @respx.mock
    def test_plain_fetcher_borrows_nothing_for_a_404(self):
        _serve(f"{_PYPI}/pkg-a/1.0.0/json")
        latest = _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        _serve(f"{_DEPS_DEV}/pkg-a/versions/1.0.0")
        dep = Dependency(name="pkg-a", version_constraint="==1.0.0", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert _summary(info) == ("UNKNOWN", "1.0.0", False, False)
        assert not latest.called

    @respx.mock
    def test_plain_fetchers_borrow_nothing_for_a_wheel_with_no_sidecar(self):
        _serve(f"{_PYPI}/pkg-a/1.0.0/json", 200, _release_with_a_wheel("1.0.0"))
        _serve(_SIDECAR)
        latest = _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        _serve(f"{_DEPS_DEV}/pkg-a/versions/1.0.0")
        dep = Dependency(name="pkg-a", version_constraint="==1.0.0", ecosystem=Ecosystem.PYTHON)
        with httpx.Client() as client:
            info = resolve_python_license(dep, client)
        assert _summary(info) == ("UNKNOWN", "1.0.0", False, False)
        assert not latest.called


class TestRegistryCacheNotFound:
    @respx.mock
    def test_only_a_404_is_recorded(self, fake_registry_clock):
        _serve(f"{_PYPI}/gone/1.0.0/json")
        _serve(f"{_PYPI}/down/1.0.0/json", 503)
        _serve(f"{_PYPI}/here/1.0.0/json", 200, _release("1.0.0", "MIT"))
        cache = RegistryCache()
        with httpx.Client() as client:
            for name in ("gone", "down", "here"):
                cache.fetch(f"{_PYPI}/{name}/1.0.0/json", client)
                # A second read is served from the cache and changes nothing.
                cache.fetch(f"{_PYPI}/{name}/1.0.0/json", client)
        assert cache.not_found(f"{_PYPI}/gone/1.0.0/json") is True
        assert cache.not_found(f"{_PYPI}/down/1.0.0/json") is False
        assert cache.not_found(f"{_PYPI}/here/1.0.0/json") is False
        assert cache.not_found(f"{_PYPI}/never-fetched/1.0.0/json") is False

    @respx.mock
    def test_direct_fetch_reports_a_404_to_the_set_it_is_given(self):
        _serve(f"{_PYPI}/gone/1.0.0/json")
        _serve(f"{_PYPI}/denied/1.0.0/json", 403)
        missing: set[str] = set()
        with httpx.Client() as client:
            for name in ("gone", "denied"):
                url = f"{_PYPI}/{name}/1.0.0/json"
                assert fetch_registry_json(url, client, not_found=missing) is None
            # With no set to report to, the fetch still just returns nothing.
            assert fetch_registry_json(f"{_PYPI}/gone/1.0.0/json", client) is None
        assert missing == {f"{_PYPI}/gone/1.0.0/json"}

    @respx.mock
    def test_only_a_404_is_recorded_for_a_sidecar(self, fake_registry_clock):
        sidecars = {name: f"{_WHEEL}.{name}.metadata" for name in ("gone", "down", "here")}
        _serve(sidecars["gone"])
        _serve(sidecars["down"], 503)
        respx.get(sidecars["here"]).mock(
            return_value=httpx.Response(200, text="License-Expression: MIT\n\n")
        )
        cache = RegistryCache()
        with httpx.Client() as client:
            assert cache.fetch_pep658(sidecars["gone"], client) is None
            assert cache.fetch_pep658(sidecars["down"], client) is None
            assert cache.fetch_pep658(sidecars["here"], client) == {"License-Expression": "MIT"}
        assert cache.not_found(sidecars["gone"]) is True
        assert cache.not_found(sidecars["down"]) is False
        assert cache.not_found(sidecars["here"]) is False

    @respx.mock
    def test_direct_sidecar_fetch_reports_a_404_to_the_set_it_is_given(self):
        _serve(_SIDECAR)
        _serve(_SIDECAR + ".denied", 403)
        missing: set[str] = set()
        with httpx.Client() as client:
            for url in (_SIDECAR, _SIDECAR + ".denied"):
                assert fetch_pep658_metadata(url, client, not_found=missing) is None
            assert fetch_pep658_metadata(_SIDECAR, client) is None
        assert missing == {_SIDECAR}


def _locked_project(tmp_path: Path, version: str = "1.0.0") -> Path:
    """A project whose ``uv.lock`` pins ``pkg-a`` at ``version`` beside ``steady`` 3.0.0."""
    _write(
        tmp_path / "pyproject.toml",
        """\
        [project]
        name = "app"
        version = "0.1.0"
        license = "MIT"
        dependencies = ["pkg-a", "steady"]
        """,
    )
    _write(
        tmp_path / "uv.lock",
        f"""\
        version = 1

        [[package]]
        name = "app"
        version = "0.1.0"
        source = {{ virtual = "." }}
        dependencies = [{{ name = "pkg-a" }}, {{ name = "steady" }}]

        [[package]]
        name = "pkg-a"
        version = "{version}"
        source = {{ registry = "https://pypi.org/simple" }}

        [[package]]
        name = "steady"
        version = "3.0.0"
        source = {{ registry = "https://pypi.org/simple" }}
        """,
    )
    _serve(f"{_PYPI}/steady/3.0.0/json", 200, _release("3.0.0", "MIT"))
    return tmp_path


def _rows(data: dict) -> dict[str, tuple[str, str, list[str]]]:
    return {
        dep["name"]: (dep["resolved_version"], dep["license"], dep["estimated"])
        for dep in data["dependencies"]
    }


_MODES = ("--transitive", "--no-transitive")


def _ranged_project(tmp_path: Path, requirement: str) -> Path:
    """A project with no lockfile: ``pkg-a`` under ``requirement``, beside ``steady`` 3.0.0."""
    _write(
        tmp_path / "pyproject.toml",
        """\
        [project]
        name = "app"
        version = "0.1.0"
        license = "MIT"
        """,
    )
    _write(tmp_path / "requirements.txt", f"pkg-a{requirement}\nsteady==3.0.0\n")
    _serve(f"{_PYPI}/steady/3.0.0/json", 200, _release("3.0.0", "MIT"))
    return tmp_path


def _scan_row(project: Path, mode: str) -> tuple[str, str, list[str]]:
    """Scan ``project`` in ``mode``; return ``pkg-a``'s ``(version, license, estimated)``."""
    _, data = _check_json(project, mode, "--no-require-lockfile", "--no-strict")
    rows = _rows(data)
    assert rows["steady"] == ("3.0.0", "MIT", [])
    return rows["pkg-a"]


class TestScanOfARange:
    """A direct dependency declared with a range is the same row with and
    without the dependency walk: one function resolves the declaration for
    both, and the release it selects is looked up the same way.
    """

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_selected_release_pypi_does_not_have_is_an_estimate_in_both_modes(self, tmp_path, mode):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("2.0.0", "MIT", "1.5.0"))
        _serve(f"{_PYPI}/pkg-a/1.5.0/json")
        row = _scan_row(_ranged_project(tmp_path, ">=1.0,<2.0"), mode)
        assert row == ("1.5.0", "MIT", ["license", "version"])

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_selected_release_that_is_the_latest_one_keeps_its_own_license(self, tmp_path, mode):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("1.0", "MIT"))
        _serve(f"{_PYPI}/pkg-a/1.0/json")
        assert _scan_row(_ranged_project(tmp_path, ">=1.0"), mode) == ("1.0", "MIT", ["version"])

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_failed_lookup_of_the_selected_release_is_unknown_in_both_modes(
        self, tmp_path, mode, fake_registry_clock
    ):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("2.0.0", "MIT", "1.5.0"))
        _fail(f"{_PYPI}/pkg-a/1.5.0/json", "503")
        _serve(f"{_DEPS_DEV}/pkg-a/versions/1.5.0")
        row = _scan_row(_ranged_project(tmp_path, ">=1.0,<2.0"), mode)
        assert row == ("1.5.0", "UNKNOWN", ["version"])

    @pytest.mark.parametrize("mode", _MODES)
    @respx.mock
    def test_selected_release_with_metadata_of_its_own_is_the_control(self, tmp_path, mode):
        _serve(f"{_PYPI}/pkg-a/json", 200, _releases("2.0.0", "MIT", "1.5.0"))
        _serve(f"{_PYPI}/pkg-a/1.5.0/json", 200, _release("1.5.0", "Apache-2.0"))
        row = _scan_row(_ranged_project(tmp_path, ">=1.0,<2.0"), mode)
        assert row == ("1.5.0", "Apache-2.0", ["version"])


class TestScan:
    """The same outcomes from a locked project, through ``check``."""

    @staticmethod
    def _outage(tmp_path: Path) -> tuple[Path, respx.Route]:
        """The pinned release's endpoint is down; the project endpoint answers MIT."""
        _fail(f"{_PYPI}/pkg-a/1.0.0/json", "503")
        latest = _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        _serve(f"{_DEPS_DEV}/pkg-a/versions/1.0.0")
        return _locked_project(tmp_path), latest

    @respx.mock
    def test_outage_on_a_pinned_release_does_not_report_the_latest_release(
        self, tmp_path, fake_registry_clock
    ):
        project, latest = self._outage(tmp_path)
        result, data = _check_json(project)
        assert result.exit_code == 1
        assert _rows(data) == {"pkg-a": ("1.0.0", "UNKNOWN", []), "steady": ("3.0.0", "MIT", [])}
        assert "Warning: 1 package(s) could not be resolved from registries." in result.output
        assert not latest.called

    @respx.mock
    def test_review_of_the_pinned_version_still_applies_during_an_outage(
        self, tmp_path, fake_registry_clock
    ):
        project, _ = self._outage(tmp_path)
        _write(
            project / "licenseal.review.toml",
            """\
            [[review]]
            ecosystem = "python"
            package = "pkg-a"
            version = "1.0.0"
            license = "BSD-3-Clause"
            note = "read from the 1.0.0 sdist"
            """,
        )
        result, data = _check_json(project)
        assert result.exit_code == 0
        assert _rows(data)["pkg-a"] == ("1.0.0", "BSD-3-Clause", [])
        assert data["summary"]["reviewed"] == 1

    @pytest.mark.parametrize("status", [500, 503, 429])
    @respx.mock
    def test_failed_sidecar_lookup_does_not_report_the_latest_release(
        self, tmp_path, fake_registry_clock, status
    ):
        _serve(f"{_PYPI}/pkg-a/1.0.0/json", 200, _release_with_a_wheel("1.0.0"))
        sidecar = _serve(_SIDECAR, status)
        latest = _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        _serve(f"{_DEPS_DEV}/pkg-a/versions/1.0.0")
        result, data = _check_json(_locked_project(tmp_path))
        assert result.exit_code == 1
        assert _rows(data) == {"pkg-a": ("1.0.0", "UNKNOWN", []), "steady": ("3.0.0", "MIT", [])}
        assert "Warning: 1 package(s) could not be resolved from registries." in result.output
        assert sidecar.call_count == 3
        assert not latest.called

    @respx.mock
    def test_wheel_with_no_sidecar_reports_the_latest_license_as_an_estimate(self, tmp_path):
        _serve(f"{_PYPI}/pkg-a/1.0.0/json", 200, _release_with_a_wheel("1.0.0"))
        _serve(_SIDECAR)
        _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        result, data = _check_json(_locked_project(tmp_path))
        assert result.exit_code == 0
        assert _rows(data)["pkg-a"] == ("1.0.0", "MIT", ["license"])

    @respx.mock
    def test_build_from_another_index_keeps_its_pinned_version(self, tmp_path):
        _serve(f"{_PYPI}/pkg-a/2.1.0+cu124/json")
        _serve(f"{_PYPI}/pkg-a/2.1.0/json", 200, _release("2.1.0", "BSD-3-Clause"))
        result, data = _check_json(_locked_project(tmp_path, "2.1.0+cu124"))
        assert result.exit_code == 0
        assert data["diagnostics"] == []
        assert _rows(data)["pkg-a"] == ("2.1.0+cu124", "BSD-3-Clause", ["license"])

    @respx.mock
    def test_markdown_shows_the_pinned_version_and_marks_the_license(self, tmp_path):
        _serve(f"{_PYPI}/pkg-a/1.0.0/json")
        _serve(f"{_PYPI}/pkg-a/json", 200, _release("2.0.0", "MIT"))
        project = _locked_project(tmp_path)
        out = project / "report.md"
        result = CliRunner().invoke(
            main, ["check", "--path", str(project), "-f", "markdown", "-o", str(out)]
        )
        assert result.exit_code == 0
        assert (
            "|[pkg-a (1.0.0)](https://pypi.org/project/pkg-a/)|python|prod|"
            "[pyproject.toml](pyproject.toml)|~[MIT](https://spdx.org/licenses/MIT.html)|"
        ) in out.read_text(encoding="utf-8")
