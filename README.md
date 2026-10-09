# cyber-intel-mcp

An [MCP](https://modelcontextprotocol.io) server that gives AI agents read-only access to cybersecurity reference data:

- **CVE records** from the [CVE Program](https://github.com/CVEProject/cvelistV5)
- **CISA's Known Exploited Vulnerabilities (KEV) catalog** ([kev-data](https://github.com/cisagov/kev-data))
- **MITRE ATT&CK® Enterprise techniques** ([mitre/cti](https://github.com/mitre/cti))

It is the tool layer for a study of agent reliability: *Can AI agents reliably complete multi-step research tasks?* Two design choices follow from that:

1. **Frozen snapshot, not live APIs.** The server reads from local JSON files built at a known point in time (recorded in `manifest.json`). Eval answers stay correct while experiments run, and results are reproducible.
2. **Every result carries a `source_id`** (`cve:CVE-2021-44228`, `kev:CVE-2021-44228`, `attack:T1190`). Agents cite these ids, and the eval can check each citation against the record behind it with `get_source`.

## Tools

| Tool | What it does |
|---|---|
| `lookup_cve(cve_id)` | CVE description, CVSS score and its source, CWEs, affected products, dates, and KEV status |
| `search_kev(vendor, product, added_after, added_before, ransomware_only, limit)` | Filter the KEV catalog; returns the total match count plus entries sorted by date added |
| `get_attack_technique(technique_id)` | ATT&CK technique name, tactics, platforms, description |
| `search_corpus(query, doc_types, limit)` | BM25 keyword search over all CVE, KEV and ATT&CK records |
| `get_source(source_id)` | Full record behind a source id, used to verify citations |

All tools are annotated read-only. Malformed input (e.g. `CVE-bad`) returns a tool error; a well-formed id that isn't in the snapshot returns `found: false`, so an agent can tell "I asked wrongly" apart from "this isn't in the data".

There is also one resource, `cyber-intel://snapshot`, which describes the loaded snapshot.

## Quick start

Requires Python 3.10+.

```bash
git clone https://github.com/<your-username>/cyber-intel-mcp.git
cd cyber-intel-mcp
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The package ships with a **sample snapshot**: the full KEV catalog, all current ATT&CK Enterprise techniques, and 50 well-known CVE records (Log4Shell, EternalBlue, ProxyLogon, MOVEit and others, plus a few that are deliberately *not* in KEV). It works straight after install.

### Build a full snapshot

```bash
cyber-intel-fetch                 # CVE records for every KEV entry (~1,700) -> data/snapshot/
cyber-intel-fetch --cves CVE-2024-3400 CVE-2023-4966   # or just the CVEs you need
```

All sources are fetched from GitHub, so no API key is needed. The server uses the first of these it finds:

1. the directory in the `CYBER_INTEL_DATA_DIR` environment variable
2. `./data/snapshot/` (git-ignored, because it is large and reproducible)
3. the bundled sample

## Use it from an MCP client

### MCP Inspector (good for poking at tools by hand)

```bash
npx @modelcontextprotocol/inspector cyber-intel-mcp
```

### Claude Desktop

Add this to `claude_desktop_config.json` (Windows: `%APPDATA%\Claude\`, macOS: `~/Library/Application Support/Claude/`), using the full path to the script inside your virtual environment:

```json
{
  "mcpServers": {
    "cyber-intel": {
      "command": "C:\\path\\to\\cyber-intel-mcp\\.venv\\Scripts\\cyber-intel-mcp.exe"
    }
  }
}
```

On macOS/Linux the command is `/path/to/cyber-intel-mcp/.venv/bin/cyber-intel-mcp`. To use a full snapshot, add `"env": {"CYBER_INTEL_DATA_DIR": "/path/to/data/snapshot"}`.

## Data notes

- **CVSS scores come from the CVE record**: the CNA's own score when it gives one, otherwise CISA's ADP (Vulnrichment) score. `cvss_source` says which. These can differ from NVD's score. For example, Microsoft scores Zerologon (CVE-2020-1472) at 5.5, while NVD lists 10.0. Write eval gold answers against the snapshot, not against memory.
- **There is no direct CVE → ATT&CK link** in these sources. Questions that need one require an extra mapping dataset.
- KEV grows over time, so counts in the sample are only correct as of its `kev_catalog_version`.

## Project layout

```
src/cyber_intel_mcp/
  server.py      MCP server and tool definitions
  store.py       snapshot loader and BM25 search index
  normalize.py   flattens upstream CVE / KEV / ATT&CK formats
  fetch.py       builds snapshots (cyber-intel-fetch)
  data/sample/   bundled sample snapshot
tests/           store unit tests + end-to-end tests through an MCP client
```

## License and attribution

Code: MIT (see `LICENSE`).

Data: CVE records © The MITRE Corporation, provided by the CVE Program. The KEV catalog is published by CISA. MITRE ATT&CK® content © The MITRE Corporation, reproduced under the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® is a registered trademark of The MITRE Corporation.
