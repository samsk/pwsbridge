# pwsbridge agent guide

## Purpose

pwsbridge ingests Weather Underground and Ecowitt uploads, publishes SI observations
to pluggable sinks, and can fan out to the real cloud using a public DNS resolver.

## Rules

- SI inside the process; unit conversion only in `internal/units`
- station response `success` only after accept; fanout/sink errors never change it
- passwords never logged (`PASSWORD`, `PASSKEY`, `key`)
- Ecowitt `PASSKEY` matches `password` by default; optional `passkey` / `PWSBRIDGE_STATION_PASSKEY` overrides
- public resolver only for cloud fanout; never `net.DefaultResolver`
- new protocol = new `internal/ingress/<name>` package
- new output = new `Sink` implementation
- file soft cap ~200 lines; document exported funcs (purpose, inputs, outputs)
- one station uses `PWSBRIDGE_*` env vars; YAML only when `PWSBRIDGE_CONFIG` is set
- derived metrics default off; enable per tenant (`PWSBRIDGE_DERIVED` or `derived:`)
- weather metrics only on `/metrics/station/{id}` (station auth); service metrics on `PWSBRIDGE_METRICS_LISTEN`
- an origin-project bug is not fixed until its named negative test exists
- run tests via `docker compose -f deploy/compose/docker-compose.yml run --rm test`
  (or `PATH=$HOME/.local/go/bin:$PATH go test ./...` when Docker is unavailable)

## Module map

| Path | Role |
|------|------|
| `cmd/pwsbridge` | process entry |
| `internal/config` | env + optional YAML |
| `internal/obs` | SI observation |
| `internal/units` | imperial → SI |
| `internal/calc` | optional derived metrics |
| `internal/ingress/*` | protocol parsers |
| `internal/sink/*` | MQTT, Prometheus, SQLite, Influx |
| `internal/fanout` | cloud forward with public DNS |
| `internal/policy` | auth, rate limit, ASN learn |
| `internal/server` | HTTP handler contract |
| `internal/app` | wire and run |
