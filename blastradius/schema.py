"""Single source of truth for the blast-radius graph model.

Two graphs joined by one bridge:

    macro (lockfile)   Service --DEPENDS_ON--> PackageVersion --DEPENDS_ON--> ...
    bridge             ExternalImport --RESOLVES_TO--> PackageVersion
    micro (AST)        Route --HANDLED_BY--> Function --CALLS--> Function
                       Function --CALLS_EXTERNAL--> ExternalImport

HydraDB requires a variable-length traversal to pin the *source* id, so every
"who reaches this" question is a forward walk over a materialised inverse edge.
INVERSE_OF below is the whole reason ingest writes each edge twice.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# Node labels
# --------------------------------------------------------------------------

SERVICE = "Service"
PACKAGE_VERSION = "PackageVersion"
FILE = "File"
FUNCTION = "Function"
EXTERNAL_IMPORT = "ExternalImport"
ROUTE = "Route"
ARTIFACT = "PersistenceArtifact"

NODE_LABELS = (
    SERVICE,
    PACKAGE_VERSION,
    FILE,
    FUNCTION,
    EXTERNAL_IMPORT,
    ROUTE,
    ARTIFACT,
)

# --------------------------------------------------------------------------
# Edge types
# --------------------------------------------------------------------------

DEPENDS_ON = "DEPENDS_ON"          # Service|PackageVersion -> PackageVersion
REQUIRED_BY = "REQUIRED_BY"        # inverse; spans PV->PV and PV->Service
CONTAINS = "CONTAINS"              # File -> Function
CALLS = "CALLS"                    # Function -> Function
CALLED_BY = "CALLED_BY"            # inverse
CALLS_EXTERNAL = "CALLS_EXTERNAL"  # Function -> ExternalImport
IMPORT_USED_BY = "IMPORT_USED_BY"  # inverse
HANDLED_BY = "HANDLED_BY"          # Route -> Function
HANDLES = "HANDLES"                # inverse
RESOLVES_TO = "RESOLVES_TO"        # ExternalImport -> PackageVersion
IMPORTED_AS = "IMPORTED_AS"        # inverse
HAS_ARTIFACT = "HAS_ARTIFACT"      # Service -> PersistenceArtifact
DECLARED_IN = "DECLARED_IN"        # File -> Service

#: Written at ingest so that backward reachability is a pinned-source forward
#: walk. Nothing else in the codebase may assume a reversed traversal works.
INVERSE_OF = {
    DEPENDS_ON: REQUIRED_BY,
    CALLS: CALLED_BY,
    CALLS_EXTERNAL: IMPORT_USED_BY,
    HANDLED_BY: HANDLES,
    RESOLVES_TO: IMPORTED_AS,
}

EDGE_TYPES = (
    DEPENDS_ON,
    REQUIRED_BY,
    CONTAINS,
    CALLS,
    CALLED_BY,
    CALLS_EXTERNAL,
    IMPORT_USED_BY,
    HANDLED_BY,
    HANDLES,
    RESOLVES_TO,
    IMPORTED_AS,
    HAS_ARTIFACT,
    DECLARED_IN,
)

# --------------------------------------------------------------------------
# Id allocation
# --------------------------------------------------------------------------
# `id` is a single global non-negative integer space shared by nodes AND
# reified relationships, so the blocks below must stay disjoint. Ids come from
# a persisted counter (see ids.py) rather than a hash: a counter is dense,
# enumerable, and makes re-ingest idempotent.

NODE_BLOCK_SIZE = 100_000_000
EDGE_BLOCK_SIZE = 100_000_000
EDGE_SPACE_START = 10_000_000_000

#: label -> (first id, last id)
NODE_BLOCKS = {
    label: (
        (i + 1) * NODE_BLOCK_SIZE,
        (i + 2) * NODE_BLOCK_SIZE - 1,
    )
    for i, label in enumerate(NODE_LABELS)
}

#: edge type -> (first id, last id)
EDGE_BLOCKS = {
    etype: (
        EDGE_SPACE_START + i * EDGE_BLOCK_SIZE,
        EDGE_SPACE_START + (i + 1) * EDGE_BLOCK_SIZE - 1,
    )
    for i, etype in enumerate(EDGE_TYPES)
}

BLOCKS = {**NODE_BLOCKS, **EDGE_BLOCKS}

# --------------------------------------------------------------------------
# Sentinels
# --------------------------------------------------------------------------
# `WHERE` has no IS NULL, so absence cannot be tested for. Every property is
# always written, using these stand-ins instead of being omitted.

UNKNOWN_TS = 0            # timestamp not known
STILL_LIVE = 4_102_444_800  # 2100-01-01, "no end yet"
UNKNOWN_STR = ""
UNKNOWN_INT = -1


def block_for(kind: str) -> tuple[int, int]:
    """Id range reserved for a node label or edge type."""
    try:
        return BLOCKS[kind]
    except KeyError:
        raise KeyError(
            f"{kind!r} is not a known label or edge type; "
            f"add it to NODE_LABELS or EDGE_TYPES first"
        ) from None
