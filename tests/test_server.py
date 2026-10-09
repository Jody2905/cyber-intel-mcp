"""End-to-end tests: talk to the server through a real MCP client (in-process).

Assertions avoid exact KEV counts, which grow every time CISA adds an entry.
"""

import asyncio
import json

import pytest
from mcp import Client

from cyber_intel_mcp.server import mcp


def call(tool: str, args: dict):
    async def run():
        async with Client(mcp) as client:
            return await client.call_tool(tool, args)

    return asyncio.run(run())


def test_lists_all_tools_as_read_only():
    async def run():
        async with Client(mcp) as client:
            return (await client.list_tools()).tools

    tools = {t.name: t for t in asyncio.run(run())}
    assert set(tools) == {"lookup_cve", "search_kev", "get_attack_technique", "search_corpus", "get_source"}
    assert all(t.annotations.read_only_hint for t in tools.values())


def test_lookup_cve_log4shell():
    result = call("lookup_cve", {"cve_id": "cve-2021-44228"})  # lowercase on purpose
    data = result.structured_content
    assert not result.is_error and data["found"]
    assert data["cvss"]["base_score"] == 10
    assert data["in_kev"] and data["kev_date_added"] == "2021-12-10"
    assert data["source_ids"] == ["cve:CVE-2021-44228", "kev:CVE-2021-44228"]


def test_lookup_cve_not_in_kev():
    data = call("lookup_cve", {"cve_id": "CVE-2021-45105"}).structured_content
    assert data["found"] and data["in_kev"] is False
    assert data["source_ids"] == ["cve:CVE-2021-45105"]


def test_lookup_cve_in_kev_but_not_in_sample():
    data = call("lookup_cve", {"cve_id": "CVE-2015-5477"}).structured_content
    assert data["found"] is False and data["in_kev"] is True


@pytest.mark.parametrize(
    "tool,args",
    [
        ("lookup_cve", {"cve_id": "log4shell"}),
        ("get_attack_technique", {"technique_id": "1190"}),
        ("search_kev", {}),
        ("search_kev", {"vendor": "Ivanti", "added_after": "Jan 2024"}),
        ("search_corpus", {"query": "x", "doc_types": ["blog"]}),
    ],
)
def test_bad_input_is_a_tool_error(tool, args):
    assert call(tool, args).is_error


def test_search_kev_vendor_and_dates():
    data = call("search_kev", {"vendor": "ivanti", "added_after": "2024-01-01", "added_before": "2024-01-31"}).structured_content
    ids = [e["cve_id"] for e in data["entries"]]
    assert {"CVE-2023-46805", "CVE-2024-21887"} <= set(ids)
    dates = [e["date_added"] for e in data["entries"]]
    assert dates == sorted(dates) and all("2024-01-01" <= d <= "2024-01-31" for d in dates)


def test_search_kev_limit_and_ransomware():
    data = call("search_kev", {"ransomware_only": True, "limit": 3}).structured_content
    assert data["returned"] == 3 and data["truncated"] and data["total_matches"] > 3
    assert all(e["known_ransomware_use"] == "Known" for e in data["entries"])


def test_get_attack_technique():
    data = call("get_attack_technique", {"technique_id": "t1190"}).structured_content
    assert data["name"] == "Exploit Public-Facing Application"
    assert "initial-access" in data["tactics"]
    assert "(Citation:" not in data["description"]


def test_search_corpus_finds_log4shell_first():
    results = call("search_corpus", {"query": "Log4j JNDI LDAP"}).structured_content["results"]
    assert results[0]["source_id"] == "cve:CVE-2021-44228"


def test_get_source_round_trip():
    data = call("get_source", {"source_id": "attack:T1190"}).structured_content
    assert data["found"] and data["record"]["technique_id"] == "T1190"
    assert call("get_source", {"source_id": "nvd:CVE-2021-44228"}).structured_content["found"] is False


def test_snapshot_resource():
    async def run():
        async with Client(mcp) as client:
            return await client.read_resource("cyber-intel://snapshot")

    manifest = json.loads(asyncio.run(run()).contents[0].text)
    assert manifest["counts"]["cves"] == 300
