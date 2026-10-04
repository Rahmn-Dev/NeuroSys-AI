from types import SimpleNamespace

from sre_agent.memory_graph import best_case_candidate, extract_features, similarity


def _case(title, kind="service_incident", entities=None, keywords=None):
    return SimpleNamespace(title=title, case_kind=kind, entities=entities or [], keywords=keywords or [])


def test_memory_features_extract_system_entities_without_markdown_history():
    features = extract_features("2026-09-30 06:48:39 Nginx gagal membaca /etc/nginx/nginx.conf dan port 443 error 502")
    assert "nginx" in features["entities"]
    assert "/etc/nginx/nginx.conf" in features["entities"]
    assert "port:443" in features["entities"]
    assert "http:502" in features["entities"]
    assert "2026" not in features["entities"]
    assert "port:48" not in features["entities"]
    assert features["kind"] == "service_incident"


def test_semantic_resolver_can_reopen_an_older_related_case():
    nginx = _case("cek nginx error", entities=["nginx"], keywords=["nginx"])
    clock = _case("sekarang jam berapa", kind="time_lookup", keywords=["jam", "berapa"])
    matched, confidence = best_case_candidate("nginx masih gagal", [clock, nginx])
    assert matched is nginx
    assert confidence >= 0.52


def test_unrelated_prompt_does_not_reuse_case():
    nginx = _case("cek nginx error", entities=["nginx"], keywords=["nginx"])
    matched, _ = best_case_candidate("sekarang jam berapa", [nginx])
    assert matched is None


def test_shared_entity_creates_stronger_correlation():
    current = extract_features("website 502 dari nginx pada port 443")
    related = _case("nginx TLS error", entities=["nginx", "443"], keywords=["nginx", "tls"])
    unrelated = _case("postgres disk usage", entities=["postgres"], keywords=["postgres", "disk"])
    assert similarity(current, related)[0] > similarity(current, unrelated)[0]
