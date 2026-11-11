COMPOSE = docker compose -p tunnelslate
TOOLS = docker compose -p tunnelslate-tools -f deploy/docker-compose.tools.yml

.PHONY: first-start build up down logs check test vpn-up

# All startup steps are automatic. Aliases are retained for existing workflows.
first-start up vpn-up:
	$(COMPOSE) up -d

build:
	$(COMPOSE) build tunnelslate tunnelslate-vpn

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f --tail=100 tunnelslate tunnelslate-vpn

check:
	$(COMPOSE) config --quiet
	$(TOOLS) run --build --rm --no-deps tunnelslate-frontend-check

test:
	$(TOOLS) run --build --rm --no-deps tunnelslate-backend-test
	$(TOOLS) run --build --rm --no-deps tunnelslate-vpn-test
