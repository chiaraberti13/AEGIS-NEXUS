.PHONY: install test run up down smoke logs backup
install:
	python -m pip install -e '.[dev]'
test:
	pytest -q
run:
	AEGIS_DATABASE_PATH=./data/aegis.db flask --app aegis_nexus.app run --host 127.0.0.1 --port 8600
up:
	docker compose up -d --build
down:
	docker compose down
smoke:
	python scripts/smoke_test.py
logs:
	docker compose logs -f collector
\nbackup:\n\tpython scripts/backup.py\n