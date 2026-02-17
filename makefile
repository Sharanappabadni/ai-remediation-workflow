run:
	docker compose up --build

up:
	docker compose up -d

down:
	docker compose down -v

logs:
	docker compose logs -f

rebuild:
	docker compose build --no-cache

test:
	curl -X POST http://python-agent:8000/analyze \
	-H "Content-Type: application/json" \
	-d '{"type":"image","input":"debian:10"}