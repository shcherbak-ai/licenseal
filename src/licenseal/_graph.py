"""Graph helpers for transitive-dependency attribution.

Lives outside `transitive.py` so the lockfile parsers (imported by
`transitive.py`) can use it too without creating a circular import.
"""

from __future__ import annotations


def compute_direct_ancestors(
    edges: dict[str, set[str]],
    roots: dict[str, str],
) -> dict[str, tuple[str, ...]]:
    """Reverse-BFS from each root through the edge graph.

    `edges` maps lowercased name → set of lowercased child names.
    `roots` maps lowercased name → original-case name for the depth-0 deps.
    Returns lowercased name → sorted tuple of original-case ancestor names that
    can reach it. Cycles terminate naturally via the per-root `seen` set.
    """
    ancestors: dict[str, set[str]] = {}
    for root_lower, root_name in roots.items():
        front: set[str] = {root_lower}
        seen: set[str] = {root_lower}
        while front:
            new_front: set[str] = set()
            for node in front:
                for child in edges.get(node, ()):
                    if child in seen:
                        continue
                    seen.add(child)
                    ancestors.setdefault(child, set()).add(root_name)
                    new_front.add(child)
            front = new_front
    return {k: tuple(sorted(v)) for k, v in ancestors.items()}
