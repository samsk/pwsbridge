GO ?= go
COMPOSE ?= docker compose -f deploy/compose/docker-compose.yml

.PHONY: test tidy build up down e2e

test:
	$(GO) test ./...

tidy:
	$(GO) mod tidy

build:
	CGO_ENABLED=0 $(GO) build -o bin/pwsbridge ./cmd/pwsbridge

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

e2e:
	$(COMPOSE) --profile e2e run --rm e2e
