"""Read-only access to a frozen data snapshot, plus a small BM25 search index.

A snapshot directory contains:
  manifest.json  - when and from where the snapshot was built
  cves.json      - list of normalized CVE records
  kev.json       - list of normalized CISA KEV entries
  attack.json    - list of normalized ATT&CK techniques

Every record has a stable *source id* ("cve:CVE-2021-44228", "kev:CVE-2021-44228",
"attack:T1190"). Tools return these ids so an agent can cite them, and the eval
can check whether a citation really supports a claim.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*")
_STOPWORDS = frozenset(
    "a an and are as at be by can for from has in is it its of on or that the this to "
    "via was were which with could allow allows".split()
)


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


@dataclass
class Document:
    source_id: str
    doc_type: str  # "cve" | "kev" | "attack"
    title: str
    text: str


class BM25Index:
    """Classic Okapi BM25 - small, dependency-free, and easy to explain in a paper."""

    def __init__(self, docs: list[Document], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.k1, self.b = k1, b
        self.term_freqs: list[Counter[str]] = []
        self.doc_lens: list[int] = []
        df: Counter[str] = Counter()
        for doc in docs:
            tokens = tokenize(f"{doc.title} {doc.title} {doc.text}")  # title counts double
            tf = Counter(tokens)
            self.term_freqs.append(tf)
            self.doc_lens.append(len(tokens))
            df.update(tf.keys())
        n = len(docs) or 1
        self.avg_len = (sum(self.doc_lens) / n) or 1.0
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def search(self, query: str, limit: int = 5, doc_types: set[str] | None = None) -> list[tuple[Document, float]]:
        q_terms = set(tokenize(query))
        if not q_terms:
            return []
        scored = []
        for i, doc in enumerate(self.docs):
            if doc_types and doc.doc_type not in doc_types:
                continue
            tf = self.term_freqs[i]
            norm = self.k1 * (1 - self.b + self.b * self.doc_lens[i] / self.avg_len)
            score = 0.0
            for term in q_terms:
                f = tf.get(term)
                if f:
                    score += self.idf[term] * f * (self.k1 + 1) / (f + norm)
            if score > 0:
                scored.append((doc, score))
        scored.sort(key=lambda pair: (-pair[1], pair[0].source_id))
        return scored[:limit]


class SnapshotStore:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        if not (self.data_dir / "manifest.json").exists():
            raise FileNotFoundError(f"No snapshot found in {self.data_dir} (missing manifest.json)")
        self.manifest: dict[str, Any] = self._load("manifest.json")
        self.cves: dict[str, dict[str, Any]] = {c["cve_id"]: c for c in self._load("cves.json")}
        self.kev: dict[str, dict[str, Any]] = {k["cve_id"]: k for k in self._load("kev.json")}
        self.techniques: dict[str, dict[str, Any]] = {t["technique_id"]: t for t in self._load("attack.json")}
        self.index = BM25Index(self._build_documents())

    def _load(self, name: str) -> Any:
        with open(self.data_dir / name, encoding="utf-8") as f:
            return json.load(f)

    def _build_documents(self) -> list[Document]:
        docs: list[Document] = []
        for c in self.cves.values():
            products = ", ".join(f"{a['vendor']} {a['product']}" for a in c["affected"][:5])
            docs.append(
                Document(f"cve:{c['cve_id']}", "cve", f"{c['cve_id']} {c.get('title') or ''}".strip(),
                         f"{c['description']} Affected: {products}. {' '.join(c['cwes'])}")
            )
        for k in self.kev.values():
            docs.append(
                Document(f"kev:{k['cve_id']}", "kev", f"{k['cve_id']} {k['name']}",
                         f"{k['vendor']} {k['product']}. {k['short_description']}")
            )
        for t in self.techniques.values():
            docs.append(
                Document(f"attack:{t['technique_id']}", "attack", f"{t['technique_id']} {t['name']}",
                         f"Tactics: {', '.join(t['tactics'])}. {t['description']}")
            )
        return docs

    # ---- search ---------------------------------------------------------

    _ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

    def search(self, query: str, limit: int = 5, doc_types: set[str] | None = None) -> list[tuple[Document, float, str]]:
        """Hybrid search: exact identifier matches first, then BM25 keyword matches.

        Plain BM25 lets an id like CVE-2021-44228 be outranked by long documents
        that repeat the query's other words ("CVSS base score" appears verbatim in
        many vendor descriptions). Real retrieval systems match identifiers exactly,
        so ids found in the query are looked up directly and ranked first.
        Returns (document, score, match) with match "exact_id" or "keyword".
        """
        keyword = self.index.search(query, limit=limit, doc_types=doc_types)
        top = keyword[0][1] if keyword else 0.0
        ids = {m.upper() for m in self._ID_RE.findall(query)}
        exact = [d for d in self.index.docs
                 if d.source_id.split(":", 1)[1] in ids and (not doc_types or d.doc_type in doc_types)]
        exact.sort(key=lambda d: d.source_id)
        seen = {d.source_id for d in exact}
        results = [(d, round(top + 1.0, 3), "exact_id") for d in exact]
        results += [(d, sc, "keyword") for d, sc in keyword if d.source_id not in seen]
        return results[:limit]

    # ---- lookups -------------------------------------------------------

    def get_source(self, source_id: str) -> dict[str, Any] | None:
        prefix, _, key = source_id.partition(":")
        key = key.strip()
        if prefix == "cve":
            return self.cves.get(key.upper())
        if prefix == "kev":
            return self.kev.get(key.upper())
        if prefix == "attack":
            return self.techniques.get(key.upper())
        return None

    def search_kev(
        self,
        vendor: str | None = None,
        product: str | None = None,
        added_after: str | None = None,
        added_before: str | None = None,
        ransomware_only: bool = False,
    ) -> list[dict[str, Any]]:
        def matches(entry: dict[str, Any]) -> bool:
            if vendor and vendor.lower() not in entry["vendor"].lower():
                return False
            if product and product.lower() not in entry["product"].lower():
                return False
            if added_after and entry["date_added"] < added_after:
                return False
            if added_before and entry["date_added"] > added_before:
                return False
            if ransomware_only and entry["known_ransomware_use"] != "Known":
                return False
            return True

        results = [e for e in self.kev.values() if matches(e)]
        results.sort(key=lambda e: (e["date_added"], e["cve_id"]))
        return results
