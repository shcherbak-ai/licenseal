"""Graph helpers for transitive-dependency attribution.

Lives outside `transitive.py` so the lockfile parsers (imported by
`transitive.py`) can use it too without creating a circular import.
"""

from __future__ import annotations

from collections.abc import Hashable
from typing import TypeVar

_Node = TypeVar("_Node", bound=Hashable)


def compute_direct_ancestors(
    edges: dict[_Node, set[_Node]],
    roots: dict[_Node, str],
) -> dict[_Node, tuple[str, ...]]:
    """Reverse-BFS from each root through the edge graph.

    `edges` maps a node → the set of its child nodes. A node is whatever key
    the caller's graph uses: a lowercased name where one name is one package,
    or a tuple that also carries the version where two versions of a package
    must not share ancestry.
    `roots` maps each depth-0 node → its original-case name.
    Returns node → sorted tuple of the original-case names of the roots that
    can reach it. Cycles terminate naturally via the per-root `seen` set.
    """
    ancestors: dict[_Node, set[str]] = {}
    for root, root_name in roots.items():
        front: set[_Node] = {root}
        seen: set[_Node] = {root}
        while front:
            new_front: set[_Node] = set()
            for node in front:
                for child in edges.get(node, ()):
                    if child in seen:
                        continue
                    seen.add(child)
                    ancestors.setdefault(child, set()).add(root_name)
                    new_front.add(child)
            front = new_front
    return {k: tuple(sorted(v)) for k, v in ancestors.items()}
