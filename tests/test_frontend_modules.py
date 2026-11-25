"""Frontend ES-module boundary invariants (Cycle I, ADR 0003).

After the app.js -> ES-module split, the static frontend has a deliberate
star shape that keeps it cycle-free:

- `core.js` is a leaf: it imports no other local module.
- each self-contained view module (`map.js`, `health.js`, …) imports ONLY from
  `core.js` — never from `app.js` and never from another view module.
- `app.js` is the entry/orchestrator: it may import `core.js` and the view
  modules, and it is the only module allowed to.

These tests fail if a future change reintroduces a cross-module dependency that
would create an import cycle (e.g. a view importing app.js, or two views
importing each other), so the modular boundary cannot silently regress.
`i18n.js` is a classic `window.AEGIS_I18N` global, not an ES module, so it is
excluded from the ES-import graph.
"""

from __future__ import annotations

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "src" / "aegis_nexus" / "static"
ENTRY = "app.js"
LEAF = "core.js"
NON_ESM = {"i18n.js"}  # window global, not an ES module

_LOCAL_IMPORT = re.compile(r'from\s+"\./([A-Za-z0-9_]+\.js)"')


def _local_imports(path: Path) -> set[str]:
    return set(_LOCAL_IMPORT.findall(path.read_text(encoding="utf-8")))


def _modules() -> dict[str, Path]:
    return {p.name: p for p in STATIC.glob("*.js") if p.name not in NON_ESM}


def test_core_is_a_leaf_module():
    core = STATIC / LEAF
    assert _local_imports(core) == set(), (
        f"{LEAF} must not import any local module (it is the shared leaf)"
    )


def test_view_modules_import_only_core():
    modules = _modules()
    views = {name: p for name, p in modules.items() if name not in {ENTRY, LEAF}}
    offenders = {
        name: sorted(imports - {LEAF})
        for name, p in views.items()
        if (imports := _local_imports(p)) - {LEAF}
    }
    assert offenders == {}, (
        "view modules may import only from core.js (anything else risks an "
        f"import cycle): {offenders}"
    )


def test_entry_imports_resolve_to_existing_modules():
    modules = _modules()
    app_imports = _local_imports(STATIC / ENTRY)
    missing = sorted(name for name in app_imports if name not in modules)
    assert missing == [], f"{ENTRY} imports modules that do not exist: {missing}"
    # app.js is expected to compose core + the view modules.
    assert LEAF in app_imports, f"{ENTRY} should import the shared {LEAF}"
