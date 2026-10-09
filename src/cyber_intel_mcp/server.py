"""cyber-intel MCP server.

Exposes a frozen snapshot of CVE, CISA KEV and MITRE ATT&CK data as MCP tools.
Every tool is read-only and every result carries `source_id`s an agent can cite.

Run over stdio (what Claude Desktop and most MCP clients expect):
    cyber-intel-mcp
"""

from __future__ import annotations

import logging
import os
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__
from .store import SnapshotStore

# stdio servers must never print to stdout - it carries the protocol. Log to stderr.
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cyber-intel-mcp")

PACKAGE_SAMPLE_DIR = Path(__file__).parent / "data" / "sample"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


def resolve_data_dir() -> Path:
    """CYBER_INTEL_DATA_DIR if set, else ./data/snapshot if built, else the bundled sample."""
    env = os.environ.get("CYBER_INTEL_DATA_DIR")
    if env:
        return Path(env).expanduser()
    local = Path.cwd() / "data" / "snapshot"
    if (local / "manifest.json").exists():
        return local
    return PACKAGE_SAMPLE_DIR


@lru_cache(maxsize=1)
def get_store() -> SnapshotStore:
    data_dir = resolve_data_dir()
    store = SnapshotStore(data_dir)
    log.info(
        "Loaded snapshot %s: %d CVEs, %d KEV entries, %d ATT&CK techniques",
        data_dir, len(store.cves), len(store.kev), len(store.techniques),
    )
    return store


mcp = MCPServer(
    name="cyber-intel",
    version=__version__,
    instructions=(
        "Read-only cybersecurity reference data (CVE records, CISA KEV catalog, MITRE ATT&CK techniques) "
        "from a frozen snapshot. Cite the `source_id` values returned by tools. If a tool reports "
        "found=false, the snapshot does not contain that record - say so rather than guessing."
    ),
)


@mcp.tool(annotations=READ_ONLY)
def lookup_cve(
    cve_id: Annotated[str, Field(description="CVE identifier, e.g. CVE-2021-44228")],
) -> dict[str, Any]:
    """Get a CVE record: description, CVSS score, CWEs, affected products, dates, and whether it is in CISA KEV."""
    cve_id = cve_id.strip().upper()
    if not CVE_ID_RE.match(cve_id):
        raise ToolError(f"'{cve_id}' is not a valid CVE id (expected CVE-YYYY-NNNN).")
    store = get_store()
    record = store.cves.get(cve_id)
    kev = store.kev.get(cve_id)
    if record is None:
        return {
            "found": False,
            "cve_id": cve_id,
            "in_kev": kev is not None,
            "source_ids": [f"kev:{cve_id}"] if kev else [],
            "message": "CVE record not in this snapshot." + (f" It is listed in KEV; call get_source('kev:{cve_id}') for the KEV entry." if kev else ""),
        }
    source_ids = [f"cve:{cve_id}"] + ([f"kev:{cve_id}"] if kev else [])
    return {
        "found": True,
        **record,
        "in_kev": kev is not None,
        "kev_date_added": kev["date_added"] if kev else None,
        "source_ids": source_ids,
    }


@mcp.tool(annotations=READ_ONLY)
def search_kev(
    vendor: Annotated[str | None, Field(description="Case-insensitive substring of the vendor, e.g. 'Ivanti'")] = None,
    product: Annotated[str | None, Field(description="Case-insensitive substring of the product, e.g. 'Exchange'")] = None,
    added_after: Annotated[str | None, Field(description="Only entries added on/after this date (YYYY-MM-DD)")] = None,
    added_before: Annotated[str | None, Field(description="Only entries added on/before this date (YYYY-MM-DD)")] = None,
    ransomware_only: Annotated[bool, Field(description="Only entries with known ransomware campaign use")] = False,
    limit: Annotated[int, Field(ge=1, le=100, description="Max entries to return (oldest first)")] = 25,
) -> dict[str, Any]:
    """Search the CISA Known Exploited Vulnerabilities catalog. Returns the total match count plus matching entries sorted by date added."""
    for name, value in (("added_after", added_after), ("added_before", added_before)):
        if value and not DATE_RE.match(value):
            raise ToolError(f"{name} must be YYYY-MM-DD, got '{value}'.")
    if not any([vendor, product, added_after, added_before, ransomware_only]):
        raise ToolError("Give at least one filter (vendor, product, a date, or ransomware_only).")
    matches = get_store().search_kev(vendor, product, added_after, added_before, ransomware_only)
    shown = matches[:limit]
    return {
        "total_matches": len(matches),
        "returned": len(shown),
        "truncated": len(matches) > len(shown),
        "entries": [{**e, "source_id": f"kev:{e['cve_id']}"} for e in shown],
    }


@mcp.tool(annotations=READ_ONLY)
def get_attack_technique(
    technique_id: Annotated[str, Field(description="ATT&CK technique id, e.g. T1190 or T1059.001")],
) -> dict[str, Any]:
    """Get a MITRE ATT&CK Enterprise technique: name, tactics, platforms and description."""
    technique_id = technique_id.strip().upper()
    if not TECHNIQUE_ID_RE.match(technique_id):
        raise ToolError(f"'{technique_id}' is not a valid technique id (expected T1234 or T1234.001).")
    technique = get_store().techniques.get(technique_id)
    if technique is None:
        return {"found": False, "technique_id": technique_id, "source_ids": [],
                "message": "Technique not in this snapshot (it may be revoked or deprecated)."}
    return {"found": True, **technique, "source_ids": [f"attack:{technique_id}"]}


@mcp.tool(annotations=READ_ONLY)
def search_corpus(
    query: Annotated[str, Field(description="Keywords to search for, e.g. 'JNDI remote code execution'")],
    doc_types: Annotated[
        list[str] | None, Field(description="Restrict to any of: 'cve', 'kev', 'attack'. Default: all.")
    ] = None,
    limit: Annotated[int, Field(ge=1, le=20)] = 5,
) -> dict[str, Any]:
    """Keyword (BM25) search across all CVE, KEV and ATT&CK records. Use it when you don't know an exact id."""
    allowed = {"cve", "kev", "attack"}
    types = set(doc_types or [])
    if types - allowed:
        raise ToolError(f"Unknown doc_types {sorted(types - allowed)}; use {sorted(allowed)}.")
    hits = get_store().index.search(query, limit=limit, doc_types=types or None)
    return {
        "query": query,
        "results": [
            {"source_id": d.source_id, "type": d.doc_type, "title": d.title,
             "snippet": d.text[:300], "score": round(score, 3)}
            for d, score in hits
        ],
    }


@mcp.tool(annotations=READ_ONLY)
def get_source(
    source_id: Annotated[str, Field(description="A source id returned by another tool, e.g. 'kev:CVE-2021-44228'")],
) -> dict[str, Any]:
    """Fetch the full record behind a source id. Use it to verify that a citation supports a claim."""
    record = get_store().get_source(source_id.strip())
    if record is None:
        return {"found": False, "source_id": source_id}
    return {"found": True, "source_id": source_id.strip(), "record": record}


@mcp.resource(
    "cyber-intel://snapshot",
    name="snapshot-manifest",
    description="When the data snapshot was built, from which sources, and record counts.",
    mime_type="application/json",
)
def snapshot_manifest() -> dict[str, Any]:
    store = get_store()
    return {**store.manifest, "data_dir": str(store.data_dir)}


def main() -> None:
    get_store()  # fail fast with a clear error if the snapshot is missing
    mcp.run("stdio")


if __name__ == "__main__":
    main()
