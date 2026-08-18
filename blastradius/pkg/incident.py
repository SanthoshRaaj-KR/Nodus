"""Synthetic supply-chain incidents.

Nothing here touches a real malicious package. An incident is a node in our own
database pointing at one ordinary, healthy public package version; no artifact
is downloaded, nothing is executed, and the package itself is not modified in
any way. We are testing graph logic, and graph logic does not care whether the
tampering was real.

An ``Incident`` is deliberately a different node type from an ``Advisory``,
with a different edge:

    Advisory --AFFECTS-->     PackageVersion    means VULNERABLE
    Incident --COMPROMISES--> PackageVersion    means SUPPLY_CHAIN_COMPROMISED

A known CVE and a tampered artifact are not the same claim and must not be
scored on one scale. A decade-old low-severity advisory outranking an active
compromise is exactly the failure that makes a security tool ignorable.

The incident carries a **live window**. A compromised version is usually pulled
within hours, so "did this project resolve it while it was live" is a different
and much smaller question than "does this project hold that version now". The
window is what makes that answerable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .. import schema
from ..hydra_client import HydraClient
from ..ids import IdAllocator
from .identity import version_key
from .writer import PackageGraphWriter

__all__ = ["SyntheticIncident", "create_incident", "SIMULATED_COMPROMISED"]

SIMULATED_COMPROMISED = "SIMULATED_COMPROMISED"


@dataclass
class SyntheticIncident:
    incident_id: str
    package: str
    version: str
    status: str = SIMULATED_COMPROMISED
    summary: str = ""
    #: Epoch seconds. Defaults to a six-hour window ending now, which is the
    #: rough shape of a real npm compromise: published, detected, unpublished.
    live_from: int = 0
    live_until: int = 0

    @property
    def target_key(self) -> str:
        return version_key(self.package, self.version)


def create_incident(
    client: HydraClient,
    ids: IdAllocator,
    package: str,
    version: str,
    incident_id: str = "SYNTHETIC-001",
    window_hours: int = 6,
    live_from: int | None = None,
    live_until: int | None = None,
    verbose: bool = True,
) -> SyntheticIncident:
    """Record a simulated compromise against one exact version.

    The edge points at the ``PackageVersion``, never at the ``Package``. That
    is the whole version-awareness property: ``lodash@4.17.21`` being marked
    must leave ``4.17.20`` and ``4.17.22`` untouched, and a test asserts it.
    """
    now = int(time.time())
    until = live_until if live_until is not None else now
    since = live_from if live_from is not None else until - window_hours * 3600

    incident = SyntheticIncident(
        incident_id=incident_id,
        package=package,
        version=version,
        summary=(
            f"Simulated supply-chain compromise of {package}@{version}. "
            f"Synthetic: no real malicious package is involved, nothing was "
            f"downloaded, and the package was not modified."
        ),
        live_from=since,
        live_until=until,
    )

    target_id = ids.lookup(schema.PACKAGE_VERSION, incident.target_key)
    if target_id is None:
        raise LookupError(
            f"{package}@{version} is not in the graph, so an incident against "
            f"it would point at nothing. Ingest it first, or pick a version "
            f"the corpus actually holds."
        )

    writer = PackageGraphWriter(client, ids, source="synthetic", verbose=False)
    # Teach the writer the target's label without restaging it. Staging would
    # write a full property row built from defaults and blank the published
    # date, licence and provenance that ingest already put there.
    writer.register(schema.PACKAGE_VERSION, target_id)
    node_id = writer.node(
        schema.INCIDENT, incident_id,
        incident_id=incident_id,
        status=incident.status,
        summary=incident.summary,
        live_from=since,
        live_until=until,
        source="synthetic",
        ingested_at=now,
    )
    writer.edge(schema.COMPROMISES, node_id, target_id, source="synthetic")
    writer.flush()

    if verbose:
        print(f"incident {incident_id} -> {package}@{version} [{incident.status}]")
        print(f"  live window: {since} .. {until} ({window_hours}h)")
        print("  synthetic: no real malicious package, nothing downloaded or run")
    return incident
