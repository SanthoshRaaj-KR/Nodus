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
PRESENT_IN = "PRESENT_IN"          # PackageVersion -> Service, transitive closure
HAS_PACKAGE = "HAS_PACKAGE"        # inverse
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
#:
#: PRESENT_IN is different in kind: it is the *transitive closure* of
#: DEPENDS_ON, flattened in Python at ingest. It exists because a variable-
#: length traversal must declare a maximum depth, and a real npm tree is
#: routinely deeper than any bound we would want to hardcode -- so a bounded
#: walk would silently under-report exposure. One hop over PRESENT_IN is both
#: exact at any depth and far faster.
INVERSE_OF = {
    DEPENDS_ON: REQUIRED_BY,
    PRESENT_IN: HAS_PACKAGE,
    CALLS: CALLED_BY,
    CALLS_EXTERNAL: IMPORT_USED_BY,
    HANDLED_BY: HANDLES,
    RESOLVES_TO: IMPORTED_AS,
}

EDGE_TYPES = (
    DEPENDS_ON,
    REQUIRED_BY,
    PRESENT_IN,
    HAS_PACKAGE,
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


# ==========================================================================
# Package-graph extension (blast-radius v2)
# ==========================================================================
# Adds the ecosystem tier -- Package/PackageVersion identity, declared
# dependency ranges, lockfile resolution, and the maintainer / repository /
# publisher relationships -- on top of the labels above.
#
# APPEND ONLY. NODE_BLOCKS and EDGE_BLOCKS derive each id range from the
# *position* of a label in NODE_LABELS / EDGE_TYPES. Inserting or reordering an
# entry silently remaps every id already handed out by ids.py, which would
# repoint existing edges at unrelated nodes. New entries go at the end, and
# nothing is ever removed.
#
# The code-graph labels (File, Function, Route, ExternalImport) and their edges
# are untouched and remain owned by the AST half of the project; the two graphs
# meet at PackageVersion and at Service.

# -- new node labels -------------------------------------------------------

PACKAGE = "Package"                  # name identity, persists across versions
LOCKFILE = "Lockfile"                # one resolved manifest, with observation time
LOCKFILE_ENTRY = "LockfileEntry"     # one resolved entry within a lockfile
MAINTAINER = "Maintainer"            # npm account holding publish rights
REPOSITORY = "Repository"            # shared source/CI infrastructure
ORGANIZATION = "Organization"        # npm scope or source-host owner
PUBLISHER = "PublisherIdentity"      # account that published a specific version
ADVISORY = "Advisory"                # known vulnerability (CVE/GHSA/OSV)
INCIDENT = "Incident"                # supply-chain compromise

PKG_NODE_LABELS = (
    PACKAGE,
    LOCKFILE,
    LOCKFILE_ENTRY,
    MAINTAINER,
    REPOSITORY,
    ORGANIZATION,
    PUBLISHER,
    ADVISORY,
    INCIDENT,
)

# -- new edge types --------------------------------------------------------
# Names deliberately avoid the ones above: CONTAINS, RESOLVES_TO, DEPENDS_ON
# and PRESENT_IN already carry code-graph or sample-loader meanings, and
# reusing a type with different endpoints would make a query silently mix two
# unrelated relationships.

HAS_VERSION = "HAS_VERSION"          # Package -> PackageVersion
VERSION_OF = "VERSION_OF"            # inverse

REQUIRES = "REQUIRES"                # PackageVersion -> Package, carries the range
REQUIRED_BY = "REQUIRED_BY_RANGE"    # inverse
SATISFIED_BY = "SATISFIED_BY"        # PackageVersion -> PackageVersion (semver)
SATISFIES = "SATISFIES"              # inverse -- the reverse-dependency edge

HAS_LOCKFILE = "HAS_LOCKFILE"        # Service -> Lockfile
LOCKFILE_OF = "LOCKFILE_OF"          # inverse
HAS_ENTRY = "HAS_ENTRY"              # Lockfile -> LockfileEntry
ENTRY_OF = "ENTRY_OF"                # inverse
RESOLVES_VERSION = "RESOLVES_VERSION"  # LockfileEntry -> PackageVersion (truth)
RESOLVED_VIA = "RESOLVED_VIA"        # inverse

#: PackageVersion -> Service, the flattened transitive closure. One hop, exact
#: at any depth. A bounded walk would under-report deep npm trees, and an
#: under-report is the failure mode that most flatters the tool.
RESOLVED_IN = "RESOLVED_IN"
RESOLVES_PKG = "RESOLVES_PKG"        # inverse

MAINTAINED_BY = "MAINTAINED_BY"      # Package -> Maintainer
MAINTAINS = "MAINTAINS"              # inverse
SOURCED_FROM = "SOURCED_FROM"        # PackageVersion -> Repository
SOURCE_OF = "SOURCE_OF"              # inverse
OWNED_BY = "OWNED_BY"                # Package -> Organization
OWNS = "OWNS"                        # inverse
PUBLISHED_BY = "PUBLISHED_BY"        # PackageVersion -> PublisherIdentity
PUBLISHED = "PUBLISHED"              # inverse
MEMBER_OF = "MEMBER_OF"              # Maintainer -> Organization
HAS_MEMBER = "HAS_MEMBER"            # inverse

TYPOSQUAT_OF = "TYPOSQUAT_OF"        # Package -> Package (imitator -> target)
TYPOSQUAT_TARGET_OF = "TYPOSQUAT_TARGET_OF"  # inverse

AFFECTS = "AFFECTS"                  # Advisory -> PackageVersion
AFFECTED_BY = "AFFECTED_BY"          # inverse
COMPROMISES = "COMPROMISES"          # Incident -> PackageVersion
COMPROMISED_BY = "COMPROMISED_BY"    # inverse

PKG_EDGE_TYPES = (
    HAS_VERSION, VERSION_OF,
    REQUIRES, REQUIRED_BY,
    SATISFIED_BY, SATISFIES,
    HAS_LOCKFILE, LOCKFILE_OF,
    HAS_ENTRY, ENTRY_OF,
    RESOLVES_VERSION, RESOLVED_VIA,
    RESOLVED_IN, RESOLVES_PKG,
    MAINTAINED_BY, MAINTAINS,
    SOURCED_FROM, SOURCE_OF,
    OWNED_BY, OWNS,
    PUBLISHED_BY, PUBLISHED,
    MEMBER_OF, HAS_MEMBER,
    TYPOSQUAT_OF, TYPOSQUAT_TARGET_OF,
    AFFECTS, AFFECTED_BY,
    COMPROMISES, COMPROMISED_BY,
)

#: The inverse of each edge type, where one exists.
#:
#: Note this is the *catalogue*, not the write list -- see PKG_NEEDS_INVERSE.
PKG_INVERSE_OF = {
    HAS_VERSION: VERSION_OF,
    REQUIRES: REQUIRED_BY,
    SATISFIED_BY: SATISFIES,
    HAS_LOCKFILE: LOCKFILE_OF,
    HAS_ENTRY: ENTRY_OF,
    RESOLVES_VERSION: RESOLVED_VIA,
    RESOLVED_IN: RESOLVES_PKG,
    MAINTAINED_BY: MAINTAINS,
    SOURCED_FROM: SOURCE_OF,
    OWNED_BY: OWNS,
    PUBLISHED_BY: PUBLISHED,
    MEMBER_OF: HAS_MEMBER,
    TYPOSQUAT_OF: TYPOSQUAT_TARGET_OF,
    AFFECTS: AFFECTED_BY,
    COMPROMISES: COMPROMISED_BY,
}

#: Edge types whose inverse is actually written at ingest.
#:
#: Measured against a live node (tests/verify_constraints.py) rather than
#: assumed. Three separate facts came out of that run:
#:
#:   1. A *variable-length* backward pattern is rejected outright, so a
#:      multi-hop "who reaches this" needs either a materialised inverse or a
#:      path procedure. The sample is right about this.
#:   2. A *single-hop* backward pattern is fine. Both
#:      `MATCH (a)-[:E]->(b {id: $id})` and `MATCH (b {id: $id})<-[:E]-(a)`
#:      return the expected row with no inverse edge present. The sample's
#:      blanket "every edge is written twice" is therefore over-broad: it
#:      generalises a variable-length restriction to every edge in the graph.
#:   3. `algo.SSpaths` accepts `relDirection: 'incoming'` and returns paths.
#:
#: So only SATISFIED_BY -- the one relationship a query walks backwards for
#: more than one hop -- needs its inverse materialised. Dropping the rest
#: roughly halves the edge count and the write time, with no query lost.
PKG_NEEDS_INVERSE = frozenset({SATISFIED_BY})

# -- id blocks for the extension ------------------------------------------
# Placed above the base node space (which ends below 1e9) and above the base
# edge space, so the two schemes cannot overlap even as either grows.

PKG_NODE_SPACE_START = 1_000_000_000
PKG_EDGE_SPACE_START = 20_000_000_000

PKG_NODE_BLOCKS = {
    label: (
        PKG_NODE_SPACE_START + i * NODE_BLOCK_SIZE,
        PKG_NODE_SPACE_START + (i + 1) * NODE_BLOCK_SIZE - 1,
    )
    for i, label in enumerate(PKG_NODE_LABELS)
}

PKG_EDGE_BLOCKS = {
    etype: (
        PKG_EDGE_SPACE_START + i * EDGE_BLOCK_SIZE,
        PKG_EDGE_SPACE_START + (i + 1) * EDGE_BLOCK_SIZE - 1,
    )
    for i, etype in enumerate(PKG_EDGE_TYPES)
}

BLOCKS.update(PKG_NODE_BLOCKS)
BLOCKS.update(PKG_EDGE_BLOCKS)

ALL_NODE_LABELS = NODE_LABELS + PKG_NODE_LABELS
ALL_EDGE_TYPES = EDGE_TYPES + PKG_EDGE_TYPES

# -- sentinels for the extension -------------------------------------------
# `WHERE` has no IS NULL, so a property that is sometimes absent cannot be
# tested for at all. Every property is written on every node of its label,
# using these stand-ins. Sentinels fail safe: an unknown timestamp is 0, which
# never falls inside a live window, so it reports as unknown, not as exposure.

UNKNOWN_SCORE = -1          # CVSS not yet derived from the vector
NO_DEPTH = -1               # depth not applicable
DIRECT_DEPTH = 1            # a project's own declared dependency

#: Evidence strength, ordered. Stored as an integer so ORDER BY works -- there
#: is no min/max aggregate to lean on, and string ordering is not worth
#: relying on.
EVIDENCE_CONFIRMED = 3       # a lockfile resolves the exact version
EVIDENCE_POSSIBLE_EXACT = 2  # a range provably admits the exact version
EVIDENCE_POSSIBLE = 1        # a range names the package, version unproven
EVIDENCE_RELATED = 0         # shares a maintainer, repo, publisher or name
