"""In-container half of the stress-test harness. Launched by ``stress.py``.

Scan targets are untrusted: this script only clones and reads them. It never
installs, builds, or executes anything from a clone.

Container layout: ``/corpus`` holds the clones (a Docker volume), ``/out`` is
the host's ``licenseal-scans/`` directory, and ``/src/src`` is the working
tree's ``src/`` mounted read-only.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess  # nosec B404
import sys
import time
from collections import Counter
from pathlib import Path

CORPUS = Path("/corpus")
OUT = Path("/out")
CORPUS_FILE = OUT / "corpus.json"
LOCK = OUT / "_corpus_lock.json"
MODES = ("no-dev", "dev")
LABELS = ("baseline", "fresh", "scan")
REVIEW_FILE = "licenseal.review.toml"
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

# Mirrors the walker's documented skip set (docs/ecosystems/index.md) so the inventory counts
# only manifests licenseal is expected to see.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".tox",
        ".nox",
        "__pycache__",
        "node_modules",
        "examples",
        "fixtures",
        "__fixtures__",
        "build",
        "dist",
        "target",
        ".eggs",
        "site-packages",
        "vendor",
        "__pypackages__",
        ".pdm-build",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".yarn",
        "bower_components",
        "jspm_packages",
    }
)

MANIFESTS: dict[str, tuple[str, ...]] = {
    "python": (
        "pyproject.toml",
        "requirements*.txt",
        "*-requirements.txt",
        "setup.py",
        "setup.cfg",
        "Pipfile",
    ),
    "npm": ("package.json",),
    "rust": ("Cargo.toml",),
    "go": ("go.mod", "go.work"),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "dotnet": (
        "*.csproj",
        "*.fsproj",
        "*.vbproj",
        "packages.config",
        "Directory.Packages.props",
        "Directory.Build.props",
        "Directory.Build.targets",
        "paket.dependencies",
    ),
    "php": ("composer.json",),
    "ruby": ("Gemfile", "*.gemspec"),
    "hex": ("mix.exs", "rebar.config"),
    "r": ("DESCRIPTION",),
}

LOCKFILES: dict[str, tuple[str, ...]] = {
    "python": ("uv.lock", "poetry.lock", "Pipfile.lock"),
    "npm": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
    "rust": ("Cargo.lock",),
    "go": ("go.sum",),
    "java": ("gradle.lockfile",),
    "dotnet": ("packages.lock.json", "project.assets.json", "paket.lock"),
    "php": ("composer.lock",),
    "ruby": ("Gemfile.lock",),
    "hex": ("mix.lock", "rebar.lock"),
    "r": ("renv.lock", "packrat.lock"),
}

DIFF_FIELDS = ("license", "detected_license", "risk", "verdict", "group", "depth", "estimated")
PROJECT_FIELDS = ("project_license", "project_license_source")


def run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    """Run a fixed argv (never a shell string) and capture its text output."""
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kwargs)  # noqa: S603  # nosec B603


def load_json(path: Path) -> dict:
    """Return the JSON object stored at ``path``, or ``{}`` when it is absent."""
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def write_json(path: Path, data: object) -> None:
    """Write ``data`` as stable, sorted JSON."""
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_corpus(only: str) -> list[dict]:
    """Return the repos to act on.

    Without ``only`` this is the corpus file. With ``only`` it may also name
    repos cloned ad hoc with ``clone --url`` (recorded in the lock file).
    """
    repos = load_json(CORPUS_FILE).get("repos", [])
    if not only:
        if not repos:
            sys.exit(f"no repos: {CORPUS_FILE.name} is missing or empty")
        return repos
    known = {r["name"]: r for r in repos}
    for name, entry in load_json(LOCK).items():
        known.setdefault(name, {"name": name, "url": entry.get("url", ""), "ecosystems": []})
    wanted = [n.strip() for n in only.split(",") if n.strip()]
    unknown = [n for n in wanted if n not in known]
    if unknown:
        sys.exit(f"unknown repo name(s): {', '.join(unknown)}")
    return [known[n] for n in wanted]


def git(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run git with submodule recursion disabled."""
    base = ["git", "-c", "advice.detachedHead=false", "-c", "submodule.recurse=false"]
    return run([*base, *args], cwd=cwd, timeout=1800)


# ---------------------------------------------------------------- clone


def _adhoc_repo(url: str, name: str) -> dict:
    derived = name or url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    if not NAME_RE.fullmatch(derived):
        sys.exit(f"cannot derive a safe directory name from {url!r}; pass --name")
    return {"name": derived, "url": url, "ecosystems": []}


def _clone_one(repo: dict, pinned: str) -> str:
    """Clone ``repo`` shallowly into the corpus; return an error message or ''."""
    dest = CORPUS / repo["name"]
    if pinned:
        dest.mkdir(parents=True)
        steps = (
            ("init", "-q"),
            ("remote", "add", "origin", repo["url"]),
            ("fetch", "-q", "--depth", "1", "--no-tags", "origin", pinned),
            ("checkout", "-q", "FETCH_HEAD"),
        )
        for step in steps:
            proc = git(*step, cwd=dest)
            if proc.returncode != 0:
                return proc.stderr.strip()
        return ""
    proc = git(
        "clone",
        "-q",
        "--depth",
        "1",
        "--no-tags",
        "--single-branch",
        "--no-recurse-submodules",
        repo["url"],
        str(dest),
    )
    return proc.stderr.strip() if proc.returncode != 0 else ""


def cmd_clone(args: argparse.Namespace) -> int:
    """Shallow-clone the corpus (or one ad hoc ``--url``) into the volume."""
    lock = load_json(LOCK)
    repos = [_adhoc_repo(args.url, args.name)] if args.url else load_corpus(args.only)
    failures = 0
    for repo in repos:
        name, url = repo["name"], repo["url"]
        dest = CORPUS / name
        started = time.monotonic()
        if (dest / ".git").exists():
            origin = git("remote", "get-url", "origin", cwd=dest).stdout.strip()
            if origin != url:
                failures += 1
                print(f"FAIL     {name}: already cloned from {origin}; pass --name", flush=True)
                continue
            status = "present"
        else:
            pinned = lock.get(name, {}).get("sha", "") if args.pinned else ""
            error = _clone_one(repo, pinned)
            if error:
                failures += 1
                print(f"FAIL     {name}: {error[:300]}", flush=True)
                continue
            status = "pinned" if pinned else "cloned"
        sha = git("rev-parse", "HEAD", cwd=dest).stdout.strip()
        lock[name] = {"url": url, "sha": sha}
        write_json(LOCK, lock)
        print(f"{status:8} {name:22} {sha[:12]}  {time.monotonic() - started:5.1f}s", flush=True)
    return 1 if failures else 0


# ---------------------------------------------------------------- inventory


def _matches(filename: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(filename, p) for p in patterns)


def _visible_dirs(here: Path, dirnames: list[str]) -> list[str]:
    return [
        d
        for d in dirnames
        if d not in SKIP_DIRS
        and not (here / d / "pyvenv.cfg").exists()
        and not (here / d / ".git").exists()
    ]


def inventory(root: Path) -> dict:
    """Count walker-visible manifests and lockfiles per ecosystem under ``root``."""
    manifests: Counter[str] = Counter()
    locks: Counter[str] = Counter()
    lock_kinds: Counter[str] = Counter()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = _visible_dirs(Path(dirpath), dirnames)
        for filename in filenames:
            for eco, patterns in MANIFESTS.items():
                if _matches(filename, patterns):
                    manifests[eco] += 1
            for eco, patterns in LOCKFILES.items():
                if _matches(filename, patterns):
                    locks[eco] += 1
                    lock_kinds[filename] += 1
    return {
        "manifests": dict(manifests),
        "lockfiles": dict(locks),
        "lock_kinds": dict(lock_kinds),
    }


def cmd_inventory(args: argparse.Namespace) -> int:
    """List the manifests and lockfiles each clone contains."""
    result = load_json(OUT / "_corpus_inventory.json")
    for repo in load_corpus(args.only):
        dest = CORPUS / repo["name"]
        if not dest.is_dir():
            print(f"{repo['name']:22} MISSING (run clone)")
            continue
        inv = inventory(dest)
        result[repo["name"]] = inv
        ecos = sorted(set(inv["manifests"]) | set(inv["lockfiles"]))
        parts = [f"{e}: {inv['manifests'].get(e, 0)}m/{inv['lockfiles'].get(e, 0)}l" for e in ecos]
        kinds = ", ".join(f"{k} x{v}" for k, v in sorted(inv["lock_kinds"].items()))
        print(f"{repo['name']:22} {'  '.join(parts) or 'no manifests'}")
        print(f"{'':22}   locks: {kinds or '-'}")
    write_json(OUT / "_corpus_inventory.json", result)
    return 0


# ---------------------------------------------------------------- find / show


def _repo_dir(only: str) -> Path:
    repos = load_corpus(only)
    if len(repos) != 1:
        sys.exit("this action needs exactly one repo: --only <name>")
    return CORPUS / repos[0]["name"]


def cmd_find(args: argparse.Namespace) -> int:
    """List files in one clone whose name matches ``--pattern``."""
    root = _repo_dir(args.only)
    shown = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for filename in sorted(filenames):
            if fnmatch.fnmatchcase(filename, args.pattern):
                print((Path(dirpath) / filename).relative_to(root).as_posix())
                shown += 1
                if shown >= args.limit:
                    print(f"... stopped at {args.limit} matches")
                    return 0
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    """Print one file from a clone (text, size-capped)."""
    root = _repo_dir(args.only).resolve()
    target = (root / args.path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        sys.exit(f"not a file inside the clone: {args.path}")
    data = target.read_bytes()[: args.max_bytes]
    sys.stdout.write(data.decode("utf-8", errors="replace"))
    return 0


# ---------------------------------------------------------------- scan


def out_path(label: str, name: str, mode: str) -> Path:
    """Return the JSON output path for one scan."""
    suffix = "_dev" if mode == "dev" else ""
    if label == "baseline":
        return OUT / f"{name}.scan_baseline{suffix}.json"
    if label == "scan":
        return OUT / f"{name}.scan{suffix}.json"
    return OUT / f"_{label}_{name}{suffix}.json"


def _check(name: str, mode: str, fmt: str, target: Path, timeout: int) -> tuple[int, str]:
    """Run ``licenseal check`` on one clone; return ``(exit code, combined output)``."""
    cmd = [
        "licenseal",
        "check",
        "-p",
        str(CORPUS / name),
        "--dev" if mode == "dev" else "--no-dev",
        "-f",
        fmt,
        "--no-strict",
        "-o",
        str(target),
    ]
    try:
        proc = run(cmd, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return -9, f"{exc.stderr or ''}\nTIMEOUT after {timeout}s"
    return proc.returncode, proc.stderr + proc.stdout


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan each repo in the requested modes, writing JSON and a run record."""
    modes = [m for m in args.modes.split(",") if m]
    if any(m not in MODES for m in modes):
        sys.exit(f"modes must be drawn from {MODES}")
    log_dir = OUT / "_logs" / args.label
    log_dir.mkdir(parents=True, exist_ok=True)
    run_path = OUT / f"_{args.label}_run.json"
    record = load_json(run_path)
    record["source_rev"] = os.environ.get("STRESS_SRC_REV", "")
    record["source_dirty"] = os.environ.get("STRESS_SRC_DIRTY", "")
    record["licenseal_version"] = run(["licenseal", "--version"]).stdout.strip()
    scans = record.setdefault("scans", {})
    for repo in load_corpus(args.only):
        name = repo["name"]
        for mode in modes:
            key = f"{name}:{mode}"
            target = out_path(args.label, name, mode)
            if args.label == "baseline" and target.exists() and not args.force:
                print(f"keep     {key:32} baseline exists (--force retakes it)", flush=True)
                continue
            target.unlink(missing_ok=True)
            started = time.monotonic()
            code, output = _check(name, mode, "json", target, args.timeout)
            seconds = round(time.monotonic() - started, 1)
            suffix = "_dev" if mode == "dev" else ""
            (log_dir / f"{name}{suffix}.err").write_text(output, encoding="utf-8")
            crashed = "Traceback (most recent call last)" in output
            scans[key] = {
                "exit": code,
                "seconds": seconds,
                "wrote_json": target.exists(),
                "crashed": crashed,
                "taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            flag = "CRASH" if crashed else ("ok" if target.exists() else "nojson")
            print(f"{flag:8} {key:32} exit={code} {seconds:7.1f}s", flush=True)
            write_json(run_path, record)
    return 0


# ---------------------------------------------------------------- report


def _load_scan(label: str, name: str, mode: str) -> dict | None:
    path = out_path(label, name, mode)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def cmd_report(args: argparse.Namespace) -> int:
    """Summarise one label's outputs: counts per repo, mode, and ecosystem."""
    record = load_json(OUT / f"_{args.label}_run.json")
    inv_all = load_json(OUT / "_corpus_inventory.json")
    lock = load_json(LOCK)
    rev = record.get("source_rev", "?")[:12]
    lines = [
        f"# Stress corpus: {args.label}",
        "",
        f"- {record.get('licenseal_version', 'licenseal ?')} at `{rev}`"
        f" (src dirty: {record.get('source_dirty') or 'no'})",
        "",
        "| repo | commit | mode | exit | secs | license | total | ok | warn | viol | unk | gaps"
        " | per-ecosystem |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    notes: list[str] = []
    for repo in load_corpus(args.only):
        name = repo["name"]
        inv = inv_all.get(name, {})
        present = set(inv.get("manifests", {})) | set(inv.get("lockfiles", {}))
        sha = lock.get(name, {}).get("sha", "")[:10]
        for mode in MODES:
            meta = record.get("scans", {}).get(f"{name}:{mode}", {})
            timing = f"{meta.get('exit', '?')} | {meta.get('seconds', '?')}"
            head = f"| {name} | {sha} | {mode} | {timing}"
            data = _load_scan(args.label, name, mode)
            if data is None:
                state = "CRASH" if meta.get("crashed") else "no output"
                lines.append(f"{head} | {state} | | | | | | | |")
                notes.append(f"{name} ({mode}): {state}; see _logs/{args.label}/")
                continue
            s = data.get("summary", {})
            per_eco = Counter(d.get("ecosystem") for d in data.get("dependencies", []))
            eco_text = ", ".join(f"{e} {n}" for e, n in sorted(per_eco.items()))
            lines.append(
                f"{head} | {data.get('project_license', '')} | {s.get('total', 0)}"
                f" | {s.get('ok', 0)} | {s.get('warnings', 0)} | {s.get('violations', 0)}"
                f" | {s.get('unknown', 0)} | {s.get('gaps', 0)} | {eco_text} |"
            )
            if mode == "dev":
                for eco in sorted(present - set(per_eco)):
                    counts = (
                        f"{inv['manifests'].get(eco, 0)} manifest(s),"
                        f" {inv['lockfiles'].get(eco, 0)} lockfile(s)"
                    )
                    notes.append(f"{name}: {eco} has {counts} but contributes 0 dependencies")
            for diag in data.get("diagnostics", []):
                notes.append(f"{name} ({mode}) gap: {diag.get('path')}: {diag.get('reason')}")
    if notes:
        lines += ["", "## Notes", "", *[f"- {n}" for n in dict.fromkeys(notes)]]
    text = "\n".join(lines) + "\n"
    (OUT / f"_{args.label}_summary.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


# ---------------------------------------------------------------- diff


def _index(data: dict) -> dict[tuple, dict]:
    return {
        (d.get("ecosystem"), d.get("name"), d.get("resolved_version", ""), d.get("origin", "")): d
        for d in data.get("dependencies", [])
    }


def _name(key: tuple) -> str:
    origin = f" from {key[3]}" if key[3] else ""
    return f"{key[0]}:{key[1]}@{key[2]}{origin}"


def _label(key: tuple, dep: dict) -> str:
    return f"{_name(key)} [{dep.get('license')}/{dep.get('verdict')}]"


def _diagnostics(data: dict) -> set[tuple[str, str, str]]:
    return {
        (d.get("path", ""), d.get("severity", ""), d.get("reason", ""))
        for d in data.get("diagnostics", [])
    }


def _diff_one(tag: str, base: dict, fresh: dict, limit: int) -> list[str]:
    b, f = _index(base), _index(fresh)
    added, removed = sorted(set(f) - set(b)), sorted(set(b) - set(f))
    changed = [
        (k, {x: (b[k].get(x), f[k].get(x)) for x in DIFF_FIELDS if b[k].get(x) != f[k].get(x)})
        for k in sorted(set(b) & set(f))
        if any(b[k].get(x) != f[k].get(x) for x in DIFF_FIELDS)
    ]
    bs, fs = base.get("summary", {}), fresh.get("summary", {})
    project = [x for x in PROJECT_FIELDS if base.get(x) != fresh.get(x)]
    bd, fd = _diagnostics(base), _diagnostics(fresh)
    if not (added or removed or changed or project) and bs == fs and bd == fd:
        return []
    lines = [f"- {tag}: +{len(added)} -{len(removed)} ~{len(changed)}"]
    lines += [f"  - {x}: {base.get(x)!r} -> {fresh.get(x)!r}" for x in project]
    lines += [
        f"  - summary.{key}: {bs.get(key)} -> {fs.get(key)}"
        for key in sorted(set(bs) | set(fs))
        if bs.get(key) != fs.get(key)
    ]
    lines += [f"  - added   {_label(k, f[k])}" for k in added[:limit]]
    lines += [f"  - removed {_label(k, b[k])}" for k in removed[:limit]]
    for k, delta in changed[:limit]:
        detail = "; ".join(f"{x}: {old} -> {new}" for x, (old, new) in delta.items())
        lines.append(f"  - changed {_name(k)} {detail}")
    for word, diagnostics in (("added  ", fd - bd), ("removed", bd - fd)):
        lines += [
            f"  - diagnostic {word} [{severity}] {path}: {reason}"
            for path, severity, reason in sorted(diagnostics)[:limit]
        ]
    return lines


def cmd_diff(args: argparse.Namespace) -> int:
    """Compare ``fresh`` outputs with ``baseline``, keyed by (ecosystem, name, version, origin)."""
    lines = ["# fresh vs baseline", ""]
    differs = False
    for repo in load_corpus(args.only):
        name = repo["name"]
        for mode in MODES:
            tag = f"{name} ({mode})"
            base, fresh = _load_scan("baseline", name, mode), _load_scan("fresh", name, mode)
            if base is None or fresh is None:
                lines.append(f"- {tag}: missing {'baseline' if base is None else 'fresh'} output")
                differs = True
                continue
            delta = _diff_one(tag, base, fresh, args.limit)
            differs = differs or bool(delta)
            lines += delta or [f"- {tag}: identical"]
    text = "\n".join(lines) + "\n"
    (OUT / "_diff_summary.md").write_text(text, encoding="utf-8")
    print(text)
    return 1 if differs else 0


# ---------------------------------------------------------------- markdown


def cmd_markdown(args: argparse.Namespace) -> int:
    """Render the ``--no-dev`` Markdown report per repo and sanity-check it."""
    failures = 0
    for repo in load_corpus(args.only):
        name = repo["name"]
        target = OUT / f"_fresh_{name}.md"
        target.unlink(missing_ok=True)
        code, _ = _check(name, "no-dev", "markdown", target, args.timeout)
        text = target.read_text(encoding="utf-8") if target.exists() else ""
        rows = sum(1 for line in text.splitlines() if line.startswith("|"))
        fresh = _load_scan("fresh", name, "no-dev") or {}
        total = fresh.get("summary", {}).get("total")
        ok = bool(text.strip()) and text.lstrip().startswith("#")
        failures += 0 if ok else 1
        state = "ok" if ok else "BAD"
        print(f"{state:8} {name:22} exit={code} table-lines={rows} json-total={total}", flush=True)
    return 1 if failures else 0


# ---------------------------------------------------------------- gapfill


def _flagged(summary: dict) -> int:
    return sum(summary.get(k, 0) for k in ("warnings", "violations", "unknown"))


def _gapfill_one(name: str, timeout: int) -> str:
    """Run the review gap-fill loop for one repo; return a one-line result."""
    report = out_path("fresh", name, "no-dev")
    fresh = _load_scan("fresh", name, "no-dev")
    if fresh is None:
        return "skip     no fresh --no-dev JSON (run fresh first)"
    placed = CORPUS / name / REVIEW_FILE
    if placed.exists():
        return "skip     the clone ships its own review file"
    work = Path("/tmp") / "gapfill" / name  # noqa: S108  # nosec B108
    work.mkdir(parents=True, exist_ok=True)
    scaffold = work / REVIEW_FILE
    scaffold.unlink(missing_ok=True)
    init = run(["licenseal", "init-review-file", "-p", str(work), "--from-report", str(report)])
    # One note per reason a stanza could not be written.
    notes = re.findall(r"Note: (\d+) flagged", init.stdout + init.stderr)
    unscaffoldable = sum(int(count) for count in notes)
    if not scaffold.exists():
        return f"ok       nothing to scaffold (flagged={_flagged(fresh.get('summary', {}))})"
    text = scaffold.read_text(encoding="utf-8")
    filled = text.count('license = ""')
    result = work / "after.json"
    result.unlink(missing_ok=True)
    try:
        placed.write_text(text.replace('license = ""', 'license = "MIT"'), encoding="utf-8")
        code, output = _check(name, "no-dev", "json", result, timeout)
    finally:
        placed.unlink(missing_ok=True)
    if not result.exists():
        return f"FAIL     check produced no JSON (exit={code}): {output.strip()[-200:]}"
    after = json.loads(result.read_text(encoding="utf-8")).get("summary", {})
    before = fresh.get("summary", {})
    checks = {
        "reviewed==filled": after.get("reviewed", 0) == filled,
        "flagged drop==filled": _flagged(before) - _flagged(after) == filled,
        "residual==unscaffoldable": _flagged(after) == unscaffoldable,
    }
    state = "ok" if all(checks.values()) else "FAIL"
    failed = ", ".join(k for k, passed in checks.items() if not passed)
    detail = (
        f"filled={filled} reviewed={after.get('reviewed', 0)}"
        f" flagged {_flagged(before)}->{_flagged(after)} unscaffoldable={unscaffoldable}"
    )
    return f"{state:8} {detail}{' | failed: ' + failed if failed else ''}"


def cmd_gapfill(args: argparse.Namespace) -> int:
    """Scaffold, fill, and apply a review file per repo, then remove it again."""
    lines = []
    for repo in load_corpus(args.only):
        line = f"{repo['name']:22} {_gapfill_one(repo['name'], args.timeout)}"
        print(line, flush=True)
        lines.append(line)
    (OUT / "_gapfill_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 1 if any(" FAIL " in f" {line} " for line in lines) else 0


def main() -> int:
    """Parse arguments and dispatch to a subcommand."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    commands = {
        "clone": cmd_clone,
        "inventory": cmd_inventory,
        "find": cmd_find,
        "show": cmd_show,
        "scan": cmd_scan,
        "report": cmd_report,
        "diff": cmd_diff,
        "markdown": cmd_markdown,
        "gapfill": cmd_gapfill,
    }
    for name, func in commands.items():
        p = sub.add_parser(name)
        p.set_defaults(func=func)
        p.add_argument("--only", default="")
        if name == "clone":
            p.add_argument("--pinned", action="store_true")
            p.add_argument("--url", default="")
            p.add_argument("--name", default="")
        if name == "find":
            p.add_argument("--pattern", required=True)
            p.add_argument("--limit", type=int, default=200)
        if name == "show":
            p.add_argument("--path", required=True)
            p.add_argument("--max-bytes", type=int, default=200_000)
        if name in ("scan", "report"):
            p.add_argument("--label", default="baseline", choices=LABELS)
        if name == "scan":
            p.add_argument("--modes", default="no-dev,dev")
            p.add_argument("--force", action="store_true")
        if name in ("scan", "markdown", "gapfill"):
            p.add_argument("--timeout", type=int, default=3600)
        if name == "diff":
            p.add_argument("--limit", type=int, default=25)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
