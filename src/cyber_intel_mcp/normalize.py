"""Turn raw upstream records into the small, flat shapes the server serves.

Upstream sources:
  * CVE records  - CVE List V5 (github.com/CVEProject/cvelistV5)
  * KEV catalog  - CISA Known Exploited Vulnerabilities (github.com/cisagov/kev-data)
  * ATT&CK       - MITRE ATT&CK Enterprise STIX bundle (github.com/mitre/cti)

Keeping normalization separate from fetching means the same code is used for the
bundled sample and for a full snapshot you build yourself.
"""

from __future__ import annotations

import re
from typing import Any

# CVSS versions in order of preference (newest first).
_CVSS_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")

_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")


def _first_english(items: list[dict[str, Any]] | None) -> str:
    for item in items or []:
        if item.get("lang", "en").lower().startswith("en"):
            return (item.get("value") or "").strip()
    return ""


def _pick_cvss(metrics: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    for key in _CVSS_KEYS:
        for metric in metrics or []:
            data = metric.get(key)
            if data and "baseScore" in data:
                return {
                    "version": data.get("version") or key.removeprefix("cvssV").replace("_", "."),
                    "base_score": data.get("baseScore"),
                    "severity": data.get("baseSeverity"),
                    "vector": data.get("vectorString"),
                }
    return None


def normalize_cve(record: dict[str, Any]) -> dict[str, Any]:
    """Flatten a CVE JSON 5.x record."""
    meta = record.get("cveMetadata", {})
    containers = record.get("containers", {})
    cna = containers.get("cna", {})
    adps = containers.get("adp", []) or []

    # Prefer the CNA's own score; fall back to CISA's ADP (Vulnrichment) score.
    cvss = _pick_cvss(cna.get("metrics"))
    cvss_source = "cna" if cvss else None
    if cvss is None:
        for adp in adps:
            cvss = _pick_cvss(adp.get("metrics"))
            if cvss:
                cvss_source = (adp.get("providerMetadata") or {}).get("shortName") or "adp"
                break

    cwes: list[str] = []
    for container in [cna, *adps]:
        for pt in container.get("problemTypes") or []:
            for d in pt.get("descriptions") or []:
                cwe = d.get("cweId")
                if cwe and cwe not in cwes:
                    cwes.append(cwe)

    affected = [
        {"vendor": a.get("vendor"), "product": a.get("product")}
        for a in cna.get("affected") or []
        if a.get("vendor") or a.get("product")
    ]

    references = [r["url"] for r in cna.get("references") or [] if r.get("url")]

    return {
        "cve_id": meta.get("cveId"),
        "state": meta.get("state"),
        "date_published": (meta.get("datePublished") or "")[:10] or None,
        "date_updated": (meta.get("dateUpdated") or "")[:10] or None,
        "assigner": meta.get("assignerShortName"),
        "title": cna.get("title"),
        "description": _first_english(cna.get("descriptions")),
        "cvss": cvss,
        "cvss_source": cvss_source,
        "cwes": cwes,
        "affected": affected[:20],
        "references": references[:10],
    }


def normalize_kev_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": entry.get("cveID"),
        "vendor": (entry.get("vendorProject") or "").strip(),
        "product": (entry.get("product") or "").strip(),
        "name": (entry.get("vulnerabilityName") or "").strip(),
        "date_added": entry.get("dateAdded"),
        "due_date": entry.get("dueDate"),
        "short_description": (entry.get("shortDescription") or "").strip(),
        "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
        "cwes": entry.get("cwes") or [],
    }


def normalize_attack_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract current (not revoked/deprecated) techniques from the STIX bundle."""
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext or not ext.get("external_id"):
            continue
        description = _CITATION_RE.sub("", obj.get("description") or "")
        description = re.sub(r"[ \t]+", " ", description).strip()
        techniques.append(
            {
                "technique_id": ext["external_id"],
                "name": obj.get("name"),
                "tactics": [
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                ],
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                "description": description,
                "url": ext.get("url"),
            }
        )
    techniques.sort(key=lambda t: t["technique_id"])
    return techniques
