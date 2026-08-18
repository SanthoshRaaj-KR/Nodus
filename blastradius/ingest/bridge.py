"""Join the micro graph to the macro graph.

An ``ExternalImport`` is a module specifier appearing in a service's source
(``import { sign } from "vulnerable-pkg"``). A ``PackageVersion`` is a resolved
entry in that service's lockfile. The bridge decides which version a given
import statement actually loads at runtime.

The subtlety: a lockfile routinely contains several versions of the same
package. Application code resolves from the repo root, so it loads the
*hoisted* top-level copy -- ``node_modules/<name>`` -- not whatever nested copy
some transitive dependency sees. Picking the wrong one would report the wrong
version as reachable, so this always prefers ``root_level``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .lockfile import ParsedLock


@dataclass(frozen=True)
class ImportLink:
    """One resolved ExternalImport -> PackageVersion edge."""

    service: str
    import_key: str
    specifier: str
    package_key: str
    confidence: str  # "hoisted" | "sole-version" | "ambiguous"


def link_imports(
    service: str,
    imports: list[dict],
    lock: ParsedLock,
) -> tuple[list[ImportLink], list[str]]:
    """Resolve each import specifier against the lockfile.

    Returns the links plus the specifiers that matched nothing -- node builtins
    (``node:fs``, ``path``) and unlisted packages both land there, and the
    ingest report prints them rather than dropping them silently.
    """
    by_name: dict[str, list[str]] = {}
    for key, pv in lock.packages.items():
        by_name.setdefault(pv.name, []).append(key)

    links: list[ImportLink] = []
    unmatched: list[str] = []

    for imp in imports:
        specifier = imp["specifier"]

        hoisted = lock.root_level.get(specifier)
        if hoisted:
            links.append(
                ImportLink(service, imp["key"], specifier, hoisted, "hoisted")
            )
            continue

        candidates = by_name.get(specifier, [])
        if not candidates:
            unmatched.append(specifier)
            continue
        if len(candidates) == 1:
            links.append(
                ImportLink(service, imp["key"], specifier, candidates[0], "sole-version")
            )
            continue

        # Several versions present and none hoisted to the root. Node would
        # resolve by nesting, which we cannot replay from source alone, so link
        # every candidate and mark it: over-reporting exposure is the safe
        # direction to be wrong in.
        for candidate in candidates:
            links.append(
                ImportLink(service, imp["key"], specifier, candidate, "ambiguous")
            )

    return links, unmatched
