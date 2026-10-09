from cyber_intel_mcp.store import BM25Index, Document, tokenize


def test_tokenize_keeps_ids_and_drops_stopwords():
    assert tokenize("The CVE-2021-44228 flaw in Log4j 2.15") == ["cve-2021-44228", "flaw", "log4j", "2.15"]


def test_bm25_ranks_the_relevant_document_first():
    docs = [
        Document("a", "cve", "Heartbleed", "OpenSSL TLS heartbeat memory disclosure"),
        Document("b", "cve", "Log4Shell", "Log4j JNDI lookup remote code execution"),
        Document("c", "attack", "Phishing", "Adversaries send phishing messages"),
    ]
    hits = BM25Index(docs).search("log4j jndi")
    assert hits[0][0].source_id == "b"
    assert all(doc.source_id != "c" for doc, _ in hits)


def test_bm25_doc_type_filter_and_empty_query():
    docs = [Document("a", "cve", "x", "shared term"), Document("b", "kev", "y", "shared term")]
    index = BM25Index(docs)
    assert [d.source_id for d, _ in index.search("shared", doc_types={"kev"})] == ["b"]
    assert index.search("the of and") == []
