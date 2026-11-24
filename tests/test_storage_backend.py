from __future__ import annotations

import inspect

from aegis_nexus.storage_backend import REQUIRED_METHODS, StorageBackend
from aegis_nexus.store import Store


def test_sqlite_store_is_the_reference_storage_backend(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    # Structural conformance: Store satisfies the StorageBackend protocol.
    assert isinstance(store, StorageBackend)


def test_store_provides_every_required_backend_method(tmp_path):
    store = Store(str(tmp_path / "aegis.db"))
    missing = [name for name in REQUIRED_METHODS if not callable(getattr(store, name, None))]
    assert missing == [], f"SQLite backend is missing required methods: {missing}"


def test_required_methods_are_unique_and_public():
    assert len(REQUIRED_METHODS) == len(set(REQUIRED_METHODS))
    assert all(not name.startswith("_") for name in REQUIRED_METHODS)


def test_ingest_signature_matches_backend_contract():
    sig = inspect.signature(Store.ingest)
    assert "collector_received_at" in sig.parameters
