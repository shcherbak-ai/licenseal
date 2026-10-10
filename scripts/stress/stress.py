"""Docker harness for the stress-test corpus.

Third-party repos are cloned into the Docker volume ``licenseal-corpus`` and
scanned inside an unprivileged Linux container. Nothing from a scan target is
written to the host: only licenseal's own output lands in ``licenseal-scans/``.

Run from the repository root::

    uv run python scripts/stress/stress.py build       # runner image
    uv run python scripts/stress/stress.py clone       # licenseal-scans/corpus.json
    uv run python scripts/stress/stress.py inventory   # manifests + lockfiles per clone
    uv run python scripts/stress/stress.py baseline    # <repo>.scan_baseline[_dev].json
    uv run python scripts/stress/stress.py fresh       # _fresh_<repo>[_dev].json
    uv run python scripts/stress/stress.py diff        # fresh vs baseline
    uv run python scripts/stress/stress.py report --label fresh
    uv run python scripts/stress/stress.py markdown    # _fresh_<repo>.md
    uv run python scripts/stress/stress.py gapfill     # review-file loop

One-off repos: ``clone --url <url> [--name <dir>]`` then ``scan --only <dir>``
(writes ``<dir>.scan.json``). ``find --only <dir> --pattern <glob>`` and
``show --only <dir> --path <file>`` read from a clone without copying it out.

Every action takes ``--only repo1,repo2``. Scans take ``--modes no-dev`` or
``--modes dev``; ``baseline --force`` retakes existing baselines. Remove the
corpus with ``docker volume rm licenseal-corpus``.
"""

from __future__ import annotations

import subprocess  # nosec B404
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SCANS = REPO / "licenseal-scans"
IMAGE = "licenseal-stress:latest"
VOLUME = "licenseal-corpus"

# Harness subcommand and extra arguments for each launcher action.
ACTIONS: dict[str, list[str]] = {
    "clone": ["clone"],
    "inventory": ["inventory"],
    "find": ["find"],
    "show": ["show"],
    "baseline": ["scan", "--label", "baseline"],
    "fresh": ["scan", "--label", "fresh"],
    "scan": ["scan", "--label", "scan"],
    "report": ["report"],
    "diff": ["diff"],
    "markdown": ["markdown"],
    "gapfill": ["gapfill"],
}
# Actions that write into the corpus volume; every other action mounts it read-only.
WRITES_CORPUS = frozenset({"clone", "gapfill"})
# Actions that run licenseal and therefore need the working tree's src/.
RUNS_LICENSEAL = frozenset({"baseline", "fresh", "scan", "markdown", "gapfill"})


def _run(cmd: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    """Run a fixed argv (never a shell string)."""
    return subprocess.run(cmd, capture_output=capture, text=True, check=False)  # noqa: S603  # nosec B603


def _source_state() -> list[str]:
    """Return ``-e`` flags recording which source revision a scan exercised."""
    rev = _run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture=True).stdout.strip()
    status = _run(["git", "-C", str(REPO), "status", "--porcelain", "--", "src"], capture=True)
    dirty = "yes" if status.stdout.strip() else ""
    return ["-e", f"STRESS_SRC_REV={rev}", "-e", f"STRESS_SRC_DIRTY={dirty}"]


def main() -> int:
    """Translate one launcher action into a ``docker`` invocation."""
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    action, rest = argv[0], argv[1:]
    if action == "build":
        dockerfile = str(HERE / "Dockerfile")
        return _run(["docker", "build", "-f", dockerfile, "-t", IMAGE, str(REPO)]).returncode
    if action not in ACTIONS:
        print(f"unknown action {action!r}; see --help", file=sys.stderr)
        return 2

    SCANS.mkdir(exist_ok=True)
    corpus_mode = "" if action in WRITES_CORPUS else ":ro"
    # Unprivileged user, read-only root filesystem, no capabilities.
    cmd = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--tmpfs",
        "/tmp",  # noqa: S108  # nosec B108
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "2048",
        "--memory",
        "8g",
        "-e",
        "HOME=/tmp",
        "-v",
        f"{HERE}:/harness:ro",
        "-v",
        f"{SCANS}:/out",
        "-v",
        f"{VOLUME}:/corpus{corpus_mode}",
    ]
    if action in RUNS_LICENSEAL:
        cmd += ["-v", f"{REPO / 'src'}:/src/src:ro", *_source_state()]
    cmd += [IMAGE, "python", "/harness/harness.py", *ACTIONS[action], *rest]
    return _run(cmd).returncode


if __name__ == "__main__":
    sys.exit(main())
