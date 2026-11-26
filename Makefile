.PHONY: install test run up down ps smoke logs backup egress-validate egress-guard egress-status egress-remove verify-integrity verify-restore sbom sast audit typecheck lint pcap-smoke

install:
	python -m pip install -e '.[dev]'

test:
	pytest -q

run:
	@test -n "$$AEGIS_OPERATOR_API_KEY" || (echo "Set AEGIS_OPERATOR_API_KEY before make run"; exit 1)
	AEGIS_DATABASE_PATH="$${AEGIS_DATABASE_PATH:-./data/aegis.db}" flask --app aegis_nexus.app run --host 127.0.0.1 --port 8600

up:
	docker compose up -d --build

down:
	docker compose down

ps:
	docker compose ps

smoke:
	@test -n "$$AEGIS_SENSOR_API_KEY" || (echo "Set AEGIS_SENSOR_API_KEY to an allowlisted sensor secret before make smoke"; exit 1)
	python scripts/smoke_test.py

logs:
	docker compose logs -f collector

backup:
	docker compose --profile ops run --rm backup

verify-integrity:
	python scripts/verify_integrity.py $(DB)

verify-restore:
	python scripts/verify_restore.py $(BACKUP)

sbom:
	python scripts/generate_sbom.py $(if $(OUT),--output $(OUT),)

sast:
	@command -v bandit >/dev/null || (echo "bandit not installed (pip install bandit)"; exit 1)
	bandit -r src --baseline .bandit-baseline.json

audit:
	@command -v pip-audit >/dev/null || (echo "pip-audit not installed (pip install pip-audit)"; exit 1)
	pip-audit

typecheck:
	@command -v mypy >/dev/null || (echo "mypy not installed (pip install mypy)"; exit 1)
	mypy

lint:
	@command -v ruff >/dev/null || (echo "ruff not installed (pip install ruff)"; exit 1)
	ruff check src tests scripts

egress-validate:
	@bash scripts/egress_guard.sh validate

egress-guard:
	@sudo bash scripts/egress_guard.sh install

egress-status:
	@sudo bash scripts/egress_guard.sh status

egress-remove:
	@sudo bash scripts/egress_guard.sh remove

# Host-only manual smoke test for the opt-in PCAP capture sidecars (ADR 0005).
# Needs a running Docker daemon + real traffic, so it is not a CI gate; run it on
# a real host (e.g. Ubuntu). Override the decoy with AEGIS_PCAP_SMOKE_DECOY.
pcap-smoke:
	@bash scripts/pcap_smoke.sh
