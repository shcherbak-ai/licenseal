"""``satisfies`` and ``select_version``: one table of cases per ecosystem.

Each row is ``(version, constraint, expected)``. ``None`` means the question
has no answer: the constraint is not one the ecosystem's grammar reads, or
the version is not a version of that ecosystem.
"""

from __future__ import annotations

import pytest

from licenseal.models import Ecosystem
from licenseal.resolvers.version_selection import (
    composer_version,
    parse_nuget_range,
    satisfies,
    select_version,
)

_PYTHON = [
    ("2.28.1", ">=2.0,<3", True),
    ("3.0.0", ">=2.0,<3", False),
    ("1.4.2", "~=1.4", True),
    ("2.0", "~=1.4", False),
    ("1.5", "!=1.5", False),
    ("1.0", "==1.*", True),
    # A bare version, and a lockfile entry, pin it.
    ("1.0", "1.0", True),
    ("1.1", "1.0", False),
    ("1.0.0", "==1.0", True),
    # A prerelease needs a specifier that names one.
    ("2.0rc1", ">=1.0", False),
    ("2.0rc2", ">=2.0rc1", True),
    ("2.0.dev1", ">=1.0", False),
    # A local version label is ignored unless the specifier has one.
    ("1.0+local", "==1.0", True),
    ("1.0+local", "==1.0+other", False),
    ("1.0", "^1.0", None),
    ("1.0", "pkg @ https://example.invalid/pkg.whl", None),
    ("1.0", "git+https://example.invalid/pkg", None),
    ("not-a-version", ">=1", None),
]

_NPM = [
    ("1.5.0", "^1.0.0", True),
    ("2.0.0", "^1.0.0", False),
    ("1.2.9", "~1.2.3", True),
    ("1.3.0", "~1.2.3", False),
    ("1.2.7", "1.2.x", True),
    ("2.5.0", "^1.0 || ^2.0", True),
    ("3.0.0", "^1.0 || ^2.0", False),
    ("1.5.0", "1.0.0 - 2.0.0", True),
    ("1.5.0", ">= 1.0.0   < 2.0.0", True),
    ("1.2.3", "1.2.3", True),
    ("1.2.4", "1.2.3", False),
    ("1.2.3", "==1.2.3", True),
    ("9.9.9", "*", True),
    # A leading ``v`` on a published version is decoration.
    ("v1.2.3", "^1.2.0", True),
    # A prerelease matches only a comparator on the same release that names one.
    ("1.5.0-rc.1", "^1.0.0", False),
    ("1.0.0-rc.2", "^1.0.0-rc.1", True),
    ("1.1.0-rc.2", "^1.0.0-rc.1", False),
    ("1.0.0-rc.1", "*", False),
    ("1.2.3+build.5", "1.2.3", True),
    ("1.2.3+build.5", "<=1.2.3", True),
    ("1.2.3", "latest", None),
    ("1.2.3", "workspace:*", None),
    ("1.2.3", "npm:other@^1", None),
    ("1.2.3", "https://example.invalid/pkg.tgz", None),
    ("1.2", "^1.0", None),
]

_RUST = [
    # A bare version is a caret requirement.
    ("1.4.0", "1.0", True),
    ("2.0.0", "1.0", False),
    ("1.9.9", "1", True),
    ("0.2.9", "0.2", True),
    ("0.3.0", "0.2", False),
    ("0.0.3", "0.0.3", True),
    ("0.0.4", "0.0.3", False),
    ("1.4.0", "^1.0", True),
    ("1.4.9", "~1.4", True),
    ("1.5.0", "~1.4", False),
    ("5.0.0", "*", True),
    ("1.9.0", "1.*", True),
    ("2.0.0", "1.*", False),
    ("1.9.0", ">=1, <2", True),
    ("2.0.0", ">=1, <2", False),
    ("1.9.0", ">= 1.0.0", True),
    ("1.2.3", "=1.2.3", True),
    ("1.2.4", "=1.2.3", False),
    ("1.2.3", "==1.2.3", True),
    ("1.0.0-beta.1", "1.0", False),
    ("1.0.0-beta.2", "1.0.0-beta.1", True),
    ("1.0.0", "1.0.0-beta.1", True),
    ("1.2.3+meta", "^1.2", True),
    # Cargo has no OR, no hyphen range, and no empty comparator.
    ("1.0.0", "^1 || ^2", None),
    ("1.0.0", "1.0 - 2.0", None),
    ("1.0.0", ">=1,", None),
    ("1.0.0", "garbage", None),
    ("1.0", "^1.0", None),
]

_RUBY = [
    ("1.9.3", "~> 1.0", True),
    ("2.0.0", "~> 1.0", False),
    ("1.2.9", "~> 1.2.3", True),
    ("1.3.0", "~> 1.2.3", False),
    ("5.9", "~> 5", True),
    ("6.0", "~> 5", False),
    ("1.9", "< 2", True),
    ("2.0", "< 2", False),
    ("2.0", "<= 2", True),
    ("2.1", "> 2", True),
    ("1.5", ">= 1.0, < 2", True),
    ("2.5", ">= 1.0, < 2", False),
    ("1.5", "!= 1.5", False),
    ("1.6", "!= 1.5", True),
    # A bare version, ``=``, and a lockfile entry all name one version.
    ("1.0", "= 1.0.0", True),
    ("1.0", "1.0", True),
    ("1.0.1", "1.0", False),
    ("1.0", "==1.0", True),
    # A prerelease is a candidate only when the requirement names one, and
    # ``~>`` stops at the release it leads to.
    ("2.0.0.rc1", ">= 1.0", False),
    ("2.0.0.rc2", ">= 2.0.0.rc1", True),
    ("1.0.0", ">= 1.0.0.rc1", True),
    ("2.0.0.rc1", "~> 1.0", False),
    ("2.0.0.rc1", "~> 1.9.rc1", False),
    ("1.9.5.rc1", "~> 1.9.rc1", True),
    # ``1.0-rc1`` is ``1.0.pre.rc1``, and trailing zeros do not order.
    ("1.0-rc1", ">= 1.0.0.a", True),
    ("1.0.b1", ">= 1.b1", True),
    ("1.0.b1", "<= 1.b1", True),
    ("1.0.a", "< 1.0.b", True),
    ("1.0", "~> x", None),
    ("1.0", ">= 1.0 < 2", None),
    ("1.0", ">=", None),
    ("one", ">= 1.0", None),
]

_HEX = [
    ("1.9.0", "~> 1.0", True),
    ("2.0.0", "~> 1.0", False),
    ("1.2.9", "~> 1.2.3", True),
    ("1.3.0", "~> 1.2.3", False),
    ("1.2.2", "~> 1.2.3", False),
    ("1.5.0", ">= 1.0.0 and < 2.0.0", True),
    ("2.5.0", ">= 1.0.0 and < 2.0.0", False),
    ("2.5.0", "~> 1.0 or ~> 2.0", True),
    ("3.0.0", "~> 1.0 or ~> 2.0", False),
    ("1.0.0", "> 0.9.0 and <= 1.0.0 or == 3.0.0", True),
    ("3.0.0", "> 0.9.0 and <= 1.0.0 or == 3.0.0", True),
    ("2.0.0", "> 0.9.0 and <= 1.0.0 or == 3.0.0", False),
    # A bare version means exactly that version.
    ("1.0.0", "1.0.0", True),
    ("1.0.1", "1.0.0", False),
    ("1.0.1", "== 1.0.0", False),
    ("1.0.1", "!= 1.0.0", True),
    ("1.0.0", "==1.0.0", True),
    ("2.0.0-rc.1", "~> 1.0", False),
    ("1.5.0-rc.1", "~> 1.0", False),
    ("1.5.0-rc.1", "~> 1.5.0-rc.0", True),
    ("1.5.0", "~> 1.5.0-rc.0", True),
    ("1.0.0+build", "== 1.0.0", True),
    ("1.0.0", "~> 1", None),
    ("1.0.0", ">= 1.0.0 && < 2", None),
    ("1.0.0", "~> 01.0", None),
    ("1.0", "~> 1.0", None),
]

_PHP = [
    ("1.9.0", "^1.0", True),
    ("2.0.0", "^1.0", False),
    ("0.3.9", "^0.3", True),
    ("0.4.0", "^0.3", False),
    ("0.0.3", "^0.0.3", True),
    ("0.0.4", "^0.0.3", False),
    ("0.0.9", "^0.0", True),
    ("0.1.0", "^0.0", False),
    ("0.9.0", "^0", True),
    ("1.9.0", "~1.2", True),
    ("2.0.0", "~1.2", False),
    ("1.2.9", "~1.2.3", True),
    ("1.3.0", "~1.2.3", False),
    ("1.9.0", "~1", True),
    ("1.2.3.4", "~1.2.3.0", True),
    ("1.2.4.0", "~1.2.3.0", False),
    ("1.2.9", "1.2.*", True),
    ("1.3.0", "1.2.*", False),
    ("1.9.0", "1.x", True),
    ("9.9.9", "*", True),
    # Space and comma are AND; one or two bars are OR.
    ("1.5.0", ">=1.0,<2.0", True),
    ("2.0.0", ">=1.0,<2.0", False),
    ("1.5.0", ">=1.0 <2.0", True),
    ("1.5.0", ">= 1.0, < 2.0", True),
    ("2.5.0", "^1.0|^2.0", True),
    ("2.5.0", "^1.0 || ^2.0", True),
    ("3.0.0", "^1.0 || ^2.0", False),
    ("1.0.0", ">1.0", False),
    ("1.0.1", ">1.0", True),
    ("2.0.0", "<=2.0", True),
    # Hyphen ranges: a partial upper bound covers everything it prefixes.
    ("1.5.0", "1.0 - 2.0", True),
    ("2.0.9", "1.0 - 2.0", True),
    ("2.1.0", "1.0 - 2.0", False),
    ("2.1.0", "1.0.0 - 2.1.0", True),
    ("2.1.1", "1.0.0 - 2.1.0", False),
    ("1.5.0", "1.0 - 2.0 !=1.5.0", False),
    # A bare version is exact; a ``v`` prefix is decoration on either side.
    ("1.2.3", "1.2.3", True),
    ("1.2.4", "1.2.3", False),
    ("1.2.0", "1.2", True),
    ("v1.9.0", "^v1.0", True),
    ("1.2.3", "==1.2.3", True),
    ("1.2.3", "=1.2.3", True),
    ("1.2.3", "!=1.2.3", False),
    ("1.2.3", "<>1.2.4", True),
    # Stability: a prerelease needs an ``@flag`` or a named prerelease that
    # reaches it, and never crosses the upper bound.
    ("1.5.0", "^1.0@stable", True),
    ("1.5.0-beta1", "^1.0", False),
    ("1.5.0-beta1", "^1.0@beta", True),
    ("1.5.0-alpha1", "^1.0@beta", False),
    ("1.5.0-RC1", "^1.0@dev", True),
    ("1.5.0-RC1", "^1.0@RC", True),
    ("2.0.0-beta1", "^1.0@beta", False),
    ("1.0.0-beta2", ">=1.0.0-beta1", True),
    ("1.0.0-beta2", "^1.0.0-beta1", True),
    ("1.0.0-alpha1", "^1.0.0-beta1", False),
    ("1.0.0-beta1", "<1.0.0-beta2 >=0.9", True),
    ("1.5.0-beta1", "1.0 - 2.0-beta", True),
    ("1.0.0", "@dev", True),
    ("1.0.0-p1", ">=1.0", True),
    ("1.0.0+build", "1.0.0", True),
    # A branch is not a range, and is not a version either.
    ("1.0.0", "dev-main", None),
    ("1.0.0", "1.x-dev", None),
    ("1.0.0", "dev-main as 1.0.0", None),
    ("1.0.0", "^1.0@nightly", None),
    ("1.0.0", "^1.0 |", None),
    ("1.0.0", "1.0 - dev-main", None),
    ("dev-main", "^1.0", None),
]

_DOTNET = [
    # A bare version is an inclusive minimum.
    ("1.5.0", "1.0.0", True),
    ("1.0.0", "1.0.0", True),
    ("0.9.0", "1.0.0", False),
    ("1.0.0", "[1.0.0]", True),
    ("1.0.1", "[1.0.0]", False),
    ("1.0.0", "==1.0.0", True),
    ("1.0.0", "(1.0.0,2.0.0]", False),
    ("1.0.1", "(1.0.0,2.0.0]", True),
    ("2.0.0", "(1.0.0,2.0.0]", True),
    ("2.0.0", "[1.0.0,2.0.0)", False),
    ("1.0", "[1.0.0, 2.0.0)", True),
    ("5.0.0", "(1.0.0,)", True),
    ("1.0.0", "(1.0.0,)", False),
    ("5.0.0", "[1.0.0,)", True),
    ("1.0.0", "(,1.0.0]", True),
    ("1.0.1", "(,1.0.0]", False),
    ("1.0.0", "(,1.0.0)", False),
    # Floating versions.
    ("1.9.0", "1.*", True),
    ("2.0.0", "1.*", False),
    ("1.2.9", "1.2.*", True),
    ("1.3.0", "1.2.*", False),
    ("9.0.0", "*", True),
    ("9.0.0-beta", "*", False),
    ("9.0.0-beta", "*-*", True),
    ("1.5.0-beta", "1.*-*", True),
    # A prerelease needs a bound that names one; labels compare without case,
    # numeric identifiers as numbers.
    ("1.5.0-beta.1", "1.0.0", False),
    ("1.5.0-beta.2", "1.5.0-beta.1", True),
    ("1.5.0-BETA.2", "[1.5.0-beta.10,2.0.0)", False),
    ("1.5.0-beta.10", "[1.5.0-BETA.2,2.0.0)", True),
    ("1.5.0-beta", "[1.5.0-1,2.0.0)", True),
    ("1.5.0", "[1.5.0-beta,2.0.0)", True),
    ("1.0.0+meta", "[1.0.0]", True),
    ("1.0.0.0", "[1.0]", True),
    ("1.0.0.1", "[1.0]", False),
    ("1.0.0", "(1.0.0)", None),
    ("1.0.0", "(,)", None),
    ("1.0.0", "$(Version)", None),
    ("1.0.0", "[1.0,x)", None),
    ("1.0.0", "[x,2.0)", None),
    ("1.0.0", "[x]", None),
    ("1.0.0", "1.0.0-*", None),
    ("one", "1.0.0", None),
]

_JAVA = [
    # A bare version is a minimum: conflict resolution may raise it.
    ("1.2", "1.0", True),
    ("1.0", "1.0", True),
    ("0.9", "1.0", False),
    ("1.0", "[1.0]", True),
    ("1.0.0", "[1.0]", True),
    ("1.1", "[1.0]", False),
    ("1.0", "==1.0", True),
    ("1.5", "[1.0,2.0)", True),
    ("2.0", "[1.0,2.0)", False),
    ("1.0", "(1.0,2.0]", False),
    ("2.0", "(1.0,2.0]", True),
    ("9.0", "[1.5,)", True),
    ("0.5", "(,1.0],[1.2,)", True),
    ("1.1", "(,1.0],[1.2,)", False),
    ("1.5", "(,1.0], [1.2,)", True),
    ("1.1", "[1.0],[1.1]", True),
    # A range is a plain comparison: it holds the prereleases of its bound.
    ("2.0-rc1", "[1.0,2.0)", True),
    # Qualifier order: alpha < beta < milestone < rc < snapshot < release < sp.
    ("1.0-alpha1", "1.0-a2", False),
    ("1.0-a2", "1.0-alpha1", True),
    ("1.0-beta1", "1.0-alpha9", True),
    ("1.0-m1", "1.0-b9", True),
    ("1.0-rc1", "1.0-milestone9", True),
    ("1.0-cr1", "[1.0-rc1]", True),
    ("1.0-SNAPSHOT", "1.0-rc9", True),
    ("1.0", "1.0-SNAPSHOT", True),
    ("1.0-SNAPSHOT", "1.0", False),
    ("1.0-sp1", "1.0", True),
    ("1.0.Final", "[1.0]", True),
    ("1.0-ga", "[1.0.0]", True),
    # An unknown qualifier sorts after a release; a number after any qualifier.
    ("33.0.0-jre", "33.0.0", True),
    ("33.0.0-android", "33.0.0-jre", False),
    ("1.0.1", "1.0-sp1", True),
    ("1.0.1", "1.0-jre", True),
    ("1.0-b", "1.0-a", True),
    # Gradle's dynamic forms.
    ("1.5.3", "1.+", True),
    ("2.0", "1.+", False),
    ("1.2.9", "1.2.+", True),
    ("1.0", "1.0.+", True),
    ("1.0.5", "1.0.+", True),
    ("1.1", "1.0.+", False),
    ("0", "[0,1)", True),
    ("9.9", "+", True),
    ("9.9", "latest.release", True),
    ("9.9", "latest.integration", True),
    ("1.0", "1.0!!", True),
    ("1.1", "1.0!!", False),
    ("1.0", "${revision}", None),
    ("1.0", "[1.0,2.0", None),
    ("1.0", "(1.0)", None),
    ("1.0", "(,)", None),
    ("1.0", "[$x,2.0)", None),
    ("1.0", "[---]", None),
    ("1.0", ".+", None),
    ("", "1.0", None),
    ("1.0 beta", "1.0", None),
]

_GO = [
    # A requirement is a minimum: minimal version selection may raise it.
    ("v1.2.3", "v1.2.3", True),
    ("v1.3.0", "v1.2.3", True),
    ("v1.2.2", "v1.2.3", False),
    ("v1.2.3", "==v1.2.3", True),
    ("v2.0.0+incompatible", "v1.9.0", True),
    ("v1.9.0", "v2.0.0+incompatible", False),
    ("v1.2.3-rc.1", "v1.2.3", False),
    ("v0.0.0-20240101000000-abcdef123456", "v0.0.0-20230101000000-abcdef123456", True),
    ("v0.0.0-20220101000000-abcdef123456", "v0.0.0-20230101000000-abcdef123456", False),
    ("1.2.3", "v1.2.3", None),
    ("v1.2.3", ">=v1.2.3", None),
    ("v1.2", "v1.2.3", None),
]

_R = [
    ("1.6-1", ">= 1.6", True),
    ("1.5.9", ">= 1.6", False),
    ("1.6", "> 1.6", False),
    ("1.6.0", "> 1.6", True),
    ("2.0", "< 2.0", False),
    ("2.0", "<= 2.0", True),
    ("1.6-1", "==1.6-1", True),
    ("1.6-2", "== 1.6-1", False),
    ("1.6", "!= 1.6", False),
    ("1.6", "*", None),
    ("1.6", ">= 1.x", None),
    ("1.6", "1.6", None),
    ("1.6a", ">= 1.0", None),
]

_TABLES = {
    Ecosystem.PYTHON: _PYTHON,
    Ecosystem.NPM: _NPM,
    Ecosystem.RUST: _RUST,
    Ecosystem.GO: _GO,
    Ecosystem.JAVA: _JAVA,
    Ecosystem.DOTNET: _DOTNET,
    Ecosystem.PHP: _PHP,
    Ecosystem.RUBY: _RUBY,
    Ecosystem.HEX: _HEX,
    Ecosystem.R: _R,
}


def _cases():
    for ecosystem, table in _TABLES.items():
        for version, constraint, expected in table:
            yield pytest.param(
                ecosystem,
                version,
                constraint,
                expected,
                id=f"{ecosystem.value}:{version}:{constraint}",
            )


class TestSatisfies:
    @pytest.mark.parametrize(("ecosystem", "version", "constraint", "expected"), _cases())
    def test_table(self, ecosystem, version, constraint, expected):
        assert satisfies(ecosystem, version, constraint) is expected

    def test_every_ecosystem_has_a_table(self):
        assert set(_TABLES) == set(Ecosystem)

    @pytest.mark.parametrize("ecosystem", list(Ecosystem))
    @pytest.mark.parametrize("constraint", ["", "   "])
    def test_no_constraint_is_satisfied_by_anything(self, ecosystem, constraint):
        assert satisfies(ecosystem, "1.0.0", constraint) is True
        assert satisfies(ecosystem, "not a version", constraint) is True

    @pytest.mark.parametrize(
        ("ecosystem", "version"),
        [
            (Ecosystem.PYTHON, "2.31.0"),
            (Ecosystem.NPM, "18.2.0"),
            (Ecosystem.RUST, "1.0.193"),
            (Ecosystem.GO, "v1.2.3"),
            (Ecosystem.JAVA, "33.0.0-jre"),
            (Ecosystem.DOTNET, "13.0.1"),
            (Ecosystem.PHP, "3.5.0"),
            (Ecosystem.RUBY, "7.1.3"),
            (Ecosystem.HEX, "1.7.10"),
            (Ecosystem.R, "1.6-1"),
        ],
    )
    def test_lockfile_entry_form_is_that_exact_version(self, ecosystem, version):
        # ``==X`` is how every lockfile parser writes a pinned version.
        assert satisfies(ecosystem, version, f"=={version}") is True


class TestSelectVersion:
    @pytest.mark.parametrize(
        ("ecosystem", "constraint", "published", "expected"),
        [
            # The highest version in range, not the latest one published.
            (Ecosystem.RUST, "^1.0", ["2.0.0", "1.4.0", "1.2.0"], "1.4.0"),
            (Ecosystem.RUBY, "~> 1.0", ["2.0.0", "1.9", "1.10", "1.2"], "1.10"),
            (Ecosystem.HEX, "~> 1.0", ["2.0.0", "1.9.0", "1.10.0"], "1.10.0"),
            (Ecosystem.PHP, "^1.0", ["2.0.0", "v1.9.0", "1.2.0"], "v1.9.0"),
            (Ecosystem.DOTNET, "(1.0.0,2.0.0]", ["1.0.0", "1.5.0", "2.0.0", "2.1.0"], "2.0.0"),
            (Ecosystem.JAVA, "[1.0,2.0)", ["2.0.1", "1.7.36", "1.7.4"], "1.7.36"),
            # A release before any prerelease the constraint admits.
            (Ecosystem.RUST, "^2.0.0-rc.1", ["2.0.0-rc.1", "2.0.0-rc.2", "2.1.0"], "2.1.0"),
            (Ecosystem.PHP, "^1.0@beta", ["v1.9.0", "1.10.0-beta1"], "v1.9.0"),
            # A prerelease when that is all the constraint leaves.
            (Ecosystem.RUST, "^2.0.0-rc.1", ["2.0.0-rc.1", "2.0.0-rc.2"], "2.0.0-rc.2"),
            (Ecosystem.PHP, "^1.10@beta", ["v1.9.0", "1.10.0-beta1"], "1.10.0-beta1"),
            (Ecosystem.RUBY, ">= 2.0.0.rc1", ["1.9", "2.0.0.rc1", "2.0.0.rc2"], "2.0.0.rc2"),
            # No constraint: the latest release, else the latest prerelease.
            (Ecosystem.RUST, "", ["2.0.0-rc.1", "1.4.0", "1.2.0"], "1.4.0"),
            (Ecosystem.RUST, "", ["2.0.0-rc.1", "2.0.0-rc.2"], "2.0.0-rc.2"),
            (Ecosystem.JAVA, "", ["2.1.0-alpha1", "2.0.9", "2.0.10", "1.7.36"], "2.0.10"),
            (Ecosystem.JAVA, "", ["2.0.0-preview1", "1.9.0"], "1.9.0"),
            (Ecosystem.DOTNET, "*", ["13.0.1", "14.0.1-beta2", "9.0.1"], "13.0.1"),
            # The same rule in the ecosystems that also have a selector of their own.
            (Ecosystem.PYTHON, ">=1.0", ["2.0rc1", "1.5", "1.2"], "1.5"),
            (Ecosystem.NPM, "^1.0.0", ["v1.4.0", "2.0.0", "1.2.0"], "v1.4.0"),
            (Ecosystem.GO, "v1.2.0", ["v1.2.0", "v1.3.0-rc.1", "v1.2.5"], "v1.2.5"),
            (Ecosystem.R, ">= 1.0", ["1.6-1", "1.5", "0.9"], "1.6-1"),
            # Entries that are not versions are passed over.
            (Ecosystem.RUST, "^1.0", ["junk", "1.4.0", "1"], "1.4.0"),
            # Nothing in range, or a constraint that is not read: no version,
            # never the latest.
            (Ecosystem.RUST, "^3", ["2.0.0", "1.4.0"], None),
            (Ecosystem.RUBY, "~> 3.0", ["2.0.0"], None),
            (Ecosystem.HEX, "~> 3.0", ["2.0.0"], None),
            (Ecosystem.PHP, "^3.0", ["2.0.0"], None),
            (Ecosystem.PHP, "dev-main", ["2.0.0"], None),
            (Ecosystem.DOTNET, "[3.0.0,)", ["2.0.0"], None),
            (Ecosystem.RUST, "nonsense", ["2.0.0"], None),
            (Ecosystem.RUST, "^1.0", [], None),
            (Ecosystem.RUST, "", [], None),
        ],
    )
    def test_highest_match(self, ecosystem, constraint, published, expected):
        assert select_version(ecosystem, constraint, published) == expected

    def test_lowest_match_for_a_registry_that_resolves_to_the_minimum(self):
        published = ["1.0.0", "1.0.1-beta", "1.0.1", "1.5.0", "2.0.0"]
        assert select_version(Ecosystem.DOTNET, "(1.0.0,2.0.0]", published, lowest=True) == "1.0.1"
        assert select_version(Ecosystem.DOTNET, "(,2.0.0)", published, lowest=True) == "1.0.0"
        assert select_version(Ecosystem.DOTNET, "(2.0.0,)", published, lowest=True) is None


class TestNugetRange:
    @pytest.mark.parametrize(
        ("constraint", "minimum", "exact", "floating"),
        [
            ("1.2.3", "1.2.3", True, False),
            (" 1.2.3 ", "1.2.3", True, False),
            ("[1.2.3]", "1.2.3", True, False),
            ("==1.2.3", "1.2.3", True, False),
            ("[1.0,2.0)", "1.0", False, False),
            ("[ 1.0 , 2.0 ]", "1.0", False, False),
            ("[1.0,)", "1.0", False, False),
            # No inclusive lower bound to restore.
            ("(1.0,2.0]", "", False, False),
            ("(1.0,)", "", False, False),
            ("(,2.0]", "", False, False),
            # A lower bound its own range excludes.
            ("[2.0,1.0]", "", False, False),
            ("[1.0,1.0)", "", False, False),
            ("1.*", "", False, True),
            ("*", "", False, True),
            ("*-*", "", False, True),
        ],
    )
    def test_what_the_range_names(self, constraint, minimum, exact, floating):
        parsed = parse_nuget_range(constraint)
        assert parsed is not None
        assert (parsed.minimum, parsed.exact, parsed.floating) == (minimum, exact, floating)

    @pytest.mark.parametrize(
        "constraint", ["", "(1.0)", "(,)", "[x]", "[1.0,x]", "$(Version)", "1.0.0-*", "^1.0"]
    )
    def test_not_a_range(self, constraint):
        assert parse_nuget_range(constraint) is None


class TestComposerVersion:
    @pytest.mark.parametrize(
        "text", ["1.2.3", "v1.2.3", "1.2", "1", "1.2.3.4", "1.0.0-beta1", "1.0.0RC2", "2.0.0-p1"]
    )
    def test_version(self, text):
        assert composer_version(text) is not None

    @pytest.mark.parametrize("text", ["dev-main", "1.x-dev", "^1.0", "1.0.*", "", "1.2.3.4.5"])
    def test_not_a_version(self, text):
        assert composer_version(text) is None

    def test_order(self):
        ordered = ["1.0.0-dev", "1.0.0-alpha1", "1.0.0-beta1", "1.0.0-beta2", "1.0.0-RC1", "1.0.0"]
        ordered += ["1.0.0-p1", "1.0.1", "1.1", "2"]
        keys = [composer_version(text) for text in ordered]
        assert keys == sorted(keys)
        assert composer_version("v1.0") == composer_version("1.0.0.0")
