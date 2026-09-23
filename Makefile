.PHONY: install test run up down ps smoke logs backup egress-guard egress-status egress-remove

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

egress-guard:
	@sudo bash scripts/egress_guard.sh install

egress-status:
	@sudo bash scripts/egress_guard.sh status

egress-remove:
	@sudo bash scripts/egress_guard.sh remove
