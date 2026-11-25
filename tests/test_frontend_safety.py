import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "aegis_nexus" / "static"
TEMPLATE = ROOT / "src" / "aegis_nexus" / "templates" / "index.html"
I18N_JS = STATIC / "i18n.js"

# All application ES modules / scripts, so the safe-DOM and i18n invariants hold
# across the whole frontend after the app.js module split (ADR 0003), not just
# app.js. i18n.js holds the translation tables and is checked separately.
APP_SCRIPTS = sorted(p for p in STATIC.glob("*.js") if p.name != "i18n.js")


def _all_app_js() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in APP_SCRIPTS)


def test_frontend_i18n_covers_template_and_literal_translation_keys():
    template = TEMPLATE.read_text(encoding="utf-8")
    app_js = _all_app_js()
    i18n_js = I18N_JS.read_text(encoding="utf-8")

    template_keys = set(re.findall(r'data-i18n(?:-(?:placeholder|title|aria))?="([^"]+)"', template))
    literal_t_keys = set(re.findall(r'\bt\("([^"]+)"\)', app_js))
    required = template_keys | literal_t_keys

    missing = sorted(key for key in required if i18n_js.count(f'"{key}"') < 2)
    assert missing == [], f"Missing IT/EN translations: {missing}"


def test_frontend_does_not_use_attacker_controlled_html_sinks():
    # Every application script, not only app.js, must avoid attacker-controlled
    # HTML sinks.
    forbidden = (".innerHTML", "insertAdjacentHTML", "document.write(", "eval(")
    for script in APP_SCRIPTS:
        source = script.read_text(encoding="utf-8")
        offending = [token for token in forbidden if token in source]
        assert not offending, f"{script.name} uses forbidden HTML sink(s): {offending}"


def test_frontend_exposes_operator_audit_view():
    template = TEMPLATE.read_text(encoding="utf-8")
    app_js = _all_app_js()
    assert 'data-view-target="audit"' in template
    assert 'data-view="audit"' in template
    assert 'id="audit-list"' in template
    # The audit view is loaded from the operator-authenticated endpoint.
    assert "/api/v1/audit" in app_js
    assert "loadAudit" in app_js
