"""Build a frozen data snapshot for the server.

    cyber-intel-fetch                       # every CVE in the KEV catalog -> data/snapshot/
    cyber-intel-fetch --cves CVE-2021-44228 CVE-2017-0144
    cyber-intel-fetch --sample              # rebuild the small sample bundled with the package

All sources are public and fetched from GitHub, so no API key is needed:
  * CISA KEV        github.com/cisagov/kev-data
  * CVE List V5     github.com/CVEProject/cvelistV5
  * MITRE ATT&CK    github.com/mitre/cti  (Enterprise)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .normalize import normalize_attack_bundle, normalize_cve, normalize_kev_entry

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CVE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve_id}.json"

PACKAGE_SAMPLE_DIR = Path(__file__).parent / "data" / "sample"

# Well-known CVEs for the bundled sample. Most are in KEV; a few are deliberately not,
# so "is this in KEV?" can have a "no" answer.
SAMPLE_CVES = [
    "CVE-2014-0160", "CVE-2014-6271", "CVE-2017-0143", "CVE-2017-0144", "CVE-2017-5638",
    "CVE-2018-13379", "CVE-2019-0708", "CVE-2019-11510", "CVE-2019-19781", "CVE-2020-1472",
    "CVE-2020-5902", "CVE-2020-10148", "CVE-2021-21972", "CVE-2021-22005", "CVE-2021-26855",
    "CVE-2021-26857", "CVE-2021-26858", "CVE-2021-27065", "CVE-2021-31207", "CVE-2021-34473",
    "CVE-2021-34523", "CVE-2021-34527", "CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105",
    "CVE-2022-1388", "CVE-2022-22965", "CVE-2022-26134", "CVE-2022-30190", "CVE-2022-40684",
    "CVE-2022-41040", "CVE-2022-41082", "CVE-2023-0669", "CVE-2023-2868", "CVE-2023-4966",
    "CVE-2023-20198", "CVE-2023-20273", "CVE-2023-22515", "CVE-2023-23397", "CVE-2023-27350",
    "CVE-2023-34362", "CVE-2023-38831", "CVE-2023-46805", "CVE-2024-21887", "CVE-2024-21893",
    "CVE-2024-3400", "CVE-2014-3566", "CVE-2016-2183", "CVE-2023-44487", "CVE-2024-3094",
]


def http_get_json(url: str, retries: int = 3) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": "cyber-intel-mcp/0.1"})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None
            if attempt == retries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
        time.sleep(2 ** attempt)
    return None


def cve_url(cve_id: str) -> str:
    _, year, number = cve_id.split("-")
    return CVE_URL.format(year=year, bucket=int(number) // 1000, cve_id=cve_id)


def fetch_cves(cve_ids: list[str], workers: int) -> tuple[list[dict[str, Any]], list[str]]:
    records, missing = [], []

    def one(cve_id: str):
        return cve_id, http_get_json(cve_url(cve_id))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for done, (cve_id, raw) in enumerate(pool.map(one, cve_ids), start=1):
            if raw is None or raw.get("cveMetadata", {}).get("state") != "PUBLISHED":
                missing.append(cve_id)
            else:
                records.append(normalize_cve(raw))
            if done % 100 == 0 or done == len(cve_ids):
                print(f"  CVE records: {done}/{len(cve_ids)}", file=sys.stderr)
    records.sort(key=lambda r: r["cve_id"])
    return records, missing


def write_json(path: Path, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))


def build_snapshot(out_dir: Path, cve_ids: list[str] | None, workers: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Downloading CISA KEV catalog...", file=sys.stderr)
    kev_raw = http_get_json(KEV_URL)
    kev = sorted((normalize_kev_entry(e) for e in kev_raw["vulnerabilities"]), key=lambda e: e["cve_id"])

    print("Downloading MITRE ATT&CK Enterprise (~50 MB)...", file=sys.stderr)
    attack_raw = http_get_json(ATTACK_URL)
    techniques = normalize_attack_bundle(attack_raw)
    # The bundle carries no release number, so record the newest modification date instead.
    attack_last_modified = max(
        (o.get("modified", "") for o in attack_raw["objects"] if o.get("type") == "attack-pattern"), default=""
    )[:10] or None

    targets = sorted(set(cve_ids)) if cve_ids else [e["cve_id"] for e in kev]
    print(f"Downloading {len(targets)} CVE records...", file=sys.stderr)
    cves, missing = fetch_cves(targets, workers)

    write_json(out_dir / "kev.json", kev)
    write_json(out_dir / "attack.json", techniques)
    write_json(out_dir / "cves.json", cves)
    manifest = {
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kev_catalog_version": kev_raw.get("catalogVersion"),
        "attack_last_modified": attack_last_modified,
        "counts": {"cves": len(cves), "kev": len(kev), "attack_techniques": len(techniques)},
        "missing_cves": missing,
        "sources": {"kev": KEV_URL, "attack": ATTACK_URL, "cve": CVE_URL},
        "attribution": "MITRE ATT&CK(R) content (c) The MITRE Corporation, used under the ATT&CK Terms of Use. "
                       "CVE records from the CVE Program; KEV from CISA.",
    }
    with open(out_dir / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Snapshot written to {out_dir} ({manifest['counts']}); missing: {missing or 'none'}", file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=Path("data/snapshot"), help="output directory")
    parser.add_argument("--cves", nargs="+", help="specific CVE ids (default: every CVE in KEV)")
    parser.add_argument("--sample", action="store_true", help="rebuild the bundled sample snapshot")
    parser.add_argument("--workers", type=int, default=8, help="parallel downloads")
    args = parser.parse_args(argv)

    if args.sample:
        build_snapshot(PACKAGE_SAMPLE_DIR, SAMPLE_CVES, args.workers)
    else:
        build_snapshot(args.out, [c.upper() for c in args.cves] if args.cves else None, args.workers)


if __name__ == "__main__":
    main()
