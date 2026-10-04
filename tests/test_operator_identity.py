import pytest

from aegis_nexus.app import _load_operator_keys, create_app


def _client(tmp_path, **config):
    base = {"TESTING": True, "DATABASE_PATH": str(tmp_path / "aegis.db")}
    base.update(config)
    return create_app(base).test_client()


def test_load_operator_keys_parses_names_and_rotation_lists():
    parsed = _load_operator_keys(
        '{"alice": "alice-key", "bob": ["bob-new", "bob-old"], "carol": ""}'
    )
    assert parsed == {"alice": "alice-key", "bob": ["bob-new", "bob-old"]}


def test_load_operator_keys_rejects_hostile_input():
    with pytest.raises(ValueError):
        _load_operator_keys("not-json")
    with pytest.raises(ValueError):
        _load_operator_keys("[]")
    with pytest.raises(ValueError):
        _load_operator_keys('{"has space": "k"}')
    with pytest.raises(ValueError):
        _load_operator_keys('{"evil<script>": "k"}')
    with pytest.raises(ValueError):
        _load_operator_keys('{"bob": ["a", "b", "c", "d", "e"]}')
    with pytest.raises(ValueError):
        _load_operator_keys('{"bob": [123]}')
    with pytest.raises(ValueError):
        _load_operator_keys('{"bob": 123}')


def test_load_operator_keys_bounds_count():
    many = "{" + ",".join(f'"op{i}": "k{i}"' for i in range(65)) + "}"
    with pytest.raises(ValueError):
        _load_operator_keys(many)


def test_load_operator_keys_truncates_oversized_secret():
    parsed = _load_operator_keys('{"alice": "' + "x" * 600 + '"}')
    assert len(parsed["alice"]) == 512


def test_named_operator_identity_authenticates_and_is_surfaced(tmp_path):
    client = _client(
        tmp_path,
        OPERATOR_KEYS={"alice": "alice-key", "bob": "bob-key"},
    )

    unauth = client.get("/api/v1/operator/status").get_json()
    assert unauth["authenticated"] is False
    assert unauth["required"] is True
    assert unauth["configured"] is True
    # The roster must never leak to unauthenticated callers.
    assert "operator" not in unauth
    assert "operator_identity_count" not in unauth

    status = client.get(
        "/api/v1/operator/status",
        headers={"X-Aegis-Operator-Key": "bob-key"},
    ).get_json()
    assert status["authenticated"] is True
    assert status["operator"] == "bob"
    assert status["operator_auth_mode"] == "named_identities"
    assert status["operator_identity_count"] == 2

    # Protected API is reachable with a named key.
    assert client.get(
        "/api/v1/dashboard",
        headers={"X-Aegis-Operator-Key": "alice-key"},
    ).status_code == 200

    # A wrong key is rejected fail-closed.
    assert client.get(
        "/api/v1/dashboard",
        headers={"X-Aegis-Operator-Key": "nope"},
    ).status_code == 401


def test_named_operator_rotation_overlap(tmp_path):
    client = _client(tmp_path, OPERATOR_KEYS={"bob": ["bob-new", "bob-old"]})
    for key in ("bob-new", "bob-old"):
        status = client.get(
            "/api/v1/operator/status",
            headers={"X-Aegis-Operator-Key": key},
        ).get_json()
        assert status["authenticated"] is True
        assert status["operator"] == "bob"


def test_named_and_shared_key_coexist(tmp_path):
    client = _client(
        tmp_path,
        OPERATOR_API_KEY="lab-key",
        OPERATOR_IDENTITY="lab-operator",
        OPERATOR_KEYS={"alice": "alice-key"},
    )

    named = client.get(
        "/api/v1/operator/status",
        headers={"X-Aegis-Operator-Key": "alice-key"},
    ).get_json()
    assert named["operator"] == "alice"
    assert named["operator_auth_mode"] == "named_identities"

    shared = client.get(
        "/api/v1/operator/status",
        headers={"X-Aegis-Operator-Key": "lab-key"},
    ).get_json()
    assert shared["authenticated"] is True
    # The shared/lab key resolves to the configured default identity.
    assert shared["operator"] == "lab-operator"


def test_shared_key_only_reports_shared_mode(tmp_path):
    client = _client(tmp_path, OPERATOR_API_KEY="lab-key")
    status = client.get(
        "/api/v1/operator/status",
        headers={"X-Aegis-Operator-Key": "lab-key"},
    ).get_json()
    assert status["operator"] == "operator"
    assert status["operator_auth_mode"] == "shared_key"
    assert status["operator_identity_count"] == 0


def test_unauthenticated_lab_mode_has_default_identity(tmp_path):
    # TESTING with no keys configured keeps the single-key lab mode open.
    client = _client(tmp_path)
    status = client.get("/api/v1/operator/status").get_json()
    assert status["authenticated"] is True
    assert status["operator"] == "operator"
    assert status["operator_auth_mode"] == "unauthenticated_lab"


def test_named_operator_keys_stripped_from_shareable_exports(tmp_path):
    client = _client(
        tmp_path,
        OPERATOR_KEYS={"alice": "super-secret-operator-key"},
        THREAT_CONTEXT_ADAPTER_JSON="",
    )
    response = client.get(
        "/api/v1/threat-context/stix",
        headers={"X-Aegis-Operator-Key": "super-secret-operator-key"},
    )
    # Provider may not support STIX export in this config; when it does, the
    # operator secret must never appear in the shareable bundle.
    if response.status_code == 200:
        assert b"super-secret-operator-key" not in response.data
