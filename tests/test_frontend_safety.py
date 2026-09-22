import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "src" / "aegis_nexus" / "templates" / "index.html"
APP_JS = ROOT / "src" / "aegis_nexus" / "static" / "app.js"
I18N_JS = ROOT / "src" / "aegis_nexus" / "static" / "i18n.js"


def test_frontend_i18n_covers_template_and_literal_translation_keys():
    template = TEMPLATE.read_text(encoding="utf-8")
    app_js = APP_JS.read_text(encoding="utf-8")
    i18n_js = I18N_JS.read_text(encoding="utf-8")

    template_keys = set(re.findall(r'data-i18n(?:-(?:placeholder|title|aria))?="([^"]+)"', template))
    literal_t_keys = set(re.findall(r'\bt\("([^"]+)"\)', app_js))
    required = template_keys | literal_t_keys

    missing = sorted(key for key in required if i18n_js.count(f'"{key}"') < 2)
    assert missing == [], f"Missing IT/EN translations: {missing}"


def test_frontend_does_not_use_attacker_controlled_html_sinks():
    app_js = APP_JS.read_text(encoding="utf-8")
    forbidden = (".innerHTML", "insertAdjacentHTML", "document.write(", "eval(")
    assert not any(token in app_js for token in forbidden)
