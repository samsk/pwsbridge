# pwsbridge

Personal weather station bridge ([pwsbridge.com](https://pwsbridge.com)).

Receives weather uploads from stations that speak **Weather Underground (WU)** or **Ecowitt**, converts them to SI units, and publishes them to **Home Assistant via MQTT discovery** (and optionally Prometheus, SQLite, InfluxDB). Can also forward the same upload to the real Weather Underground cloud.

Typical use: point your station (or DNS) at pwsbridge so Home Assistant gets live sensors without a cloud account—or keep WU upload and mirror the data into HA.

## What you get in Home Assistant

When MQTT is configured, pwsbridge publishes [MQTT discovery](https://www.home-assistant.io/integrations/mqtt/) for each station. Entities appear as a device like **Weather Station (FT0300)** with sensors such as temperature (°C), humidity, pressure (hPa), wind (km/h), rain (mm), and more.

| Topic pattern | Purpose |
|---------------|---------|
| `homeassistant/device/{tenant}_{station}/config` | Discovery payload |
| `pwsbridge/{tenant}/{station}/state` | JSON state (SI values) |
| `pwsbridge/{tenant}/{station}/availability` | `online` / `offline` |
| `pwsbridge/{tenant}/{station}/fanout/{name}` | Fan-out status (`ok` / `paused` / `disabled`) when forwarding |

If no new upload arrives within the stale timeout (default 5 minutes), availability flips to `offline`.

---

## Credentials (WU and Ecowitt)

Configure once; the weather station itself usually needs no change.

| Config | WU upload | Ecowitt upload |
|--------|-----------|----------------|
| `station_id` | Query `ID` | Public name for MQTT / HA / metrics only |
| `station_password` | Query `PASSWORD` | Default match for device `PASSKEY` |
| `station_passkey` (optional) | unused | Override when device `PASSKEY` ≠ WU password |

Examples:

```bash
# Same secret for WU and Ecowitt (typical)
PWSBRIDGE_STATION_ID=FT0300
PWSBRIDGE_STATION_PASSWORD=my-wu-password

# Ecowitt PASSKEY differs from WU password
PWSBRIDGE_STATION_ID=FT0300
PWSBRIDGE_STATION_PASSWORD=my-wu-password
PWSBRIDGE_STATION_PASSKEY=AABBCCDDEEFF00112233445566778899
```

YAML multi-station: `password:` is the WU secret; optional `passkey:` overrides Ecowitt only. See [`deploy/compose/pwsbridge.example.yaml`](deploy/compose/pwsbridge.example.yaml).

---

## Home Assistant add-on

### Install

1. **Settings → Add-ons → Add-on store → ⋮ → Repositories**
2. Add this repository URL (the folder that contains [`addon/repository.yaml`](addon/repository.yaml)):
   ```text
   https://github.com/samsk/pwsbridge
   ```
   Or clone the repo and use a [local add-on](https://developers.home-assistant.io/docs/add-ons/tutorial) from `addon/pwsbridge`.
3. Install **pwsbridge**, then open **Configuration**.

### Configure

| Option | What to set |
|--------|-------------|
| `station_id` | Public id (WU `ID`; HA device name) |
| `station_password` | WU `PASSWORD` (also default Ecowitt `PASSKEY`) |
| `station_passkey` | Optional; set only if Ecowitt `PASSKEY` differs |
| `auth_mode` | `password` (recommended) or `open` |
| `mqtt_broker` | Leave **empty** to use the HA Mosquitto add-on automatically; or set e.g. `tcp://core-mosquitto:1883` |
| `mqtt_username` / `mqtt_password` | Only if you are not using the supervisor MQTT service |
| `forward_wu` | `true` to also send uploads to Weather Underground (default `false`) |
| `derived` | `true` to compute dew point, feels-like, etc. when the station omits them |
| `listen` | Default `:8080` (map host 80→8080 for WU DNS hijack; do not bind 80 inside) |

Also enable the **Mosquitto broker** add-on (or another MQTT broker) and the **MQTT** integration in Home Assistant.

### Expose the upload port

Under the add-on **Network** / port mapping:

- Map **8080** for a Customized / Ecowitt server URL, or
- Map host **80** onto container **8080** when the station only talks to `rtupdate.wunderground.com` on port 80 and you hijack DNS (see [Station setup](#station-setup)). The process listens on 8080 only (no privileged bind).

Start the add-on, then confirm sensors appear under **Settings → Devices → MQTT**.

More option detail: [`addon/pwsbridge/DOCS.md`](addon/pwsbridge/DOCS.md).

---

## MQTT without the add-on

Run pwsbridge anywhere MQTT can reach your broker (Docker Compose, bare metal, another host).

```bash
export PWSBRIDGE_LISTEN=":8080"
export PWSBRIDGE_AUTH_MODE=password
export PWSBRIDGE_STATION_ID=FT0300
export PWSBRIDGE_STATION_PASSWORD=station-key
# export PWSBRIDGE_STATION_PASSKEY=...   # only if Ecowitt PASSKEY differs
export PWSBRIDGE_MQTT_BROKER=tcp://192.168.1.10:1883
export PWSBRIDGE_MQTT_USERNAME=   # optional
export PWSBRIDGE_MQTT_PASSWORD=   # optional
export PWSBRIDGE_MQTT_DISCOVERY_PREFIX=homeassistant
export PWSBRIDGE_FORWARD_WU=false
export PWSBRIDGE_DERIVED=false

# Docker
docker compose -f deploy/compose/docker-compose.yml up -d --build
```

In Home Assistant:

1. Install / configure the **MQTT** integration against the same broker.
2. Leave discovery enabled (default prefix `homeassistant`).
3. After the first successful upload, the weather device and entities show up automatically—no YAML sensors required.

---

## Station setup

### Weather Underground path (e.g. Sainlogic FT-0300)

Many consoles only upload to WU hosts and have no “custom server” field.

1. On your LAN DNS (AdGuard, Pi-hole, router), resolve both to the machine running pwsbridge:
   - `rtupdate.wunderground.com`
   - `weatherstation.wunderground.com`
2. Ensure that host accepts the upload on **port 80** (or whatever the station uses)—map host **80** → container **8080** if needed.
3. On the console, enable Wunderground with the **same** station ID and password as pwsbridge (`station_id` / `station_password`).
4. Optional: set `PWSBRIDGE_FORWARD_WU=true` so pwsbridge still sends the upload to the real WU cloud (using a public DNS resolver, not your LAN rewrite).

### Ecowitt / “Customized” server

If the station supports a custom upload URL:

1. Protocol: typically HTTP POST to path `/data/report`
2. Server: IP or hostname of pwsbridge
3. Port: `8080` (or your mapped port)
4. Path: `/data/report`
5. Upload interval: a few seconds or more; pwsbridge rate-limits by default (`2s`)

The console keeps sending its device **PASSKEY**. In pwsbridge, that value must equal `station_password` unless you set `station_passkey` / `passkey:`. The public `station_id` is only for MQTT topics and HA naming (letters, digits, `_`, `-`, max 64 chars).

### Pointing WU software at pwsbridge directly

WU-compatible firmware posts to:

```text
/weatherstation/updateweatherstation.php?ID=...&PASSWORD=...&action=updateraw&...
```

Point the host at pwsbridge (DNS or custom server) with matching `ID` / `PASSWORD`.

---

## Docker Compose quick start

```bash
cp deploy/compose/.env.example .env   # set station id/password
docker compose -f deploy/compose/docker-compose.yml up -d --build
```

Compose includes Mosquitto. Set at least:

```env
PWSBRIDGE_STATION_ID=FT0300
PWSBRIDGE_STATION_PASSWORD=changeme
PWSBRIDGE_MQTT_BROKER=tcp://mosquitto:1883
PWSBRIDGE_AUTH_MODE=password
PWSBRIDGE_FORWARD_WU=false
```

Then point your station (or DNS) at the host’s published port (`8080` by default). Map `80:8080` when DNS-hijacking WU on port 80.

The Compose service runs read-only as non-root with dropped capabilities. Mosquitto is published on `127.0.0.1:1883` only. For a LAN-reachable broker, add a password file and set `allow_anonymous false`.

---

## Configuration cheat sheet

| Variable | Default | Meaning |
|----------|---------|---------|
| `PWSBRIDGE_LISTEN` | `:8080` | HTTP listen address |
| `PWSBRIDGE_AUTH_MODE` | `password` | `password` or `open` |
| `PWSBRIDGE_STATION_ID` | — | Public station id (WU `ID`) |
| `PWSBRIDGE_STATION_PASSWORD` | — | WU `PASSWORD` (default Ecowitt `PASSKEY`) |
| `PWSBRIDGE_STATION_PASSKEY` | — | Optional Ecowitt `PASSKEY` override |
| `PWSBRIDGE_MQTT_BROKER` | — | e.g. `tcp://core-mosquitto:1883` |
| `PWSBRIDGE_MQTT_USERNAME` / `_PASSWORD` | — | Broker credentials |
| `PWSBRIDGE_MQTT_DISCOVERY_PREFIX` | `homeassistant` | HA discovery prefix |
| `PWSBRIDGE_FORWARD_WU` | `false` | Fan-out to real WU |
| `PWSBRIDGE_FORWARD_RESOLVER` | `1.1.1.1:53` | Public DNS for fan-out (IP literal; UDP or `https://…`) |
| `PWSBRIDGE_DERIVED` | `false` | Fill dew point / feels-like / etc. |
| `PWSBRIDGE_RATE_LIMIT` | `2s` | Min interval per station |
| `PWSBRIDGE_STALE_TIMEOUT` | `300s` | MQTT offline after silence |
| `PWSBRIDGE_PROMETHEUS` | `true` | Weather + service metrics |
| `PWSBRIDGE_METRICS_LISTEN` | `127.0.0.1:9091` | Process metrics bind (when Prometheus on) |
| `PWSBRIDGE_METRICS_TOKEN` | — | Required if metrics listen is not loopback |
| `PWSBRIDGE_CONFIG` | — | Path to multi-station YAML |
| `PWSBRIDGE_DATA_DIR` | `/data` | Root for SQLite paths |

Multi-station example: [`deploy/compose/pwsbridge.example.yaml`](deploy/compose/pwsbridge.example.yaml) (`PWSBRIDGE_CONFIG=/path/to/pwsbridge.yaml`).

With more than one tenant, auth must be `password`, each MQTT/SQLite/Influx sink belongs to one tenant, and those sink hosts must be public addresses. Prometheus may stay shared.

### Fan-out refusals

When `forward_wu` is enabled and Weather Underground **rejects** the upload (not a network timeout), pwsbridge pauses that station’s fan-out with increasing delays, then disables it after 24 hours of refusals. Status is retained on `pwsbridge/{tenant}/{station}/fanout/wu` and shown as a diagnostic HA sensor. Transport errors do not pause forwarding and do not delay local MQTT publish.

### Metrics (optional)

| Endpoint | Content | Auth |
|----------|---------|------|
| `GET /metrics/station/{id}` on the ingest port | Weather gauges for that station | Basic (`id` / password) or Bearer password; skipped if `auth_mode=open` |
| `GET /metrics` on `PWSBRIDGE_METRICS_LISTEN` | Process counters | Bearer `PWSBRIDGE_METRICS_TOKEN` when bind is not loopback |

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| No HA entities | MQTT integration + broker; `PWSBRIDGE_MQTT_BROKER`; first successful upload; discovery prefix |
| Station keeps retrying | Port mapping (host 80 → 8080); DNS rewrite target; matching id/password |
| `INVALIDPASSWORDID` (WU) | Wrong `PASSWORD` or unknown `ID` |
| `INVALIDPASSWORDID` (Ecowitt) | `PASSKEY` must equal `station_password`, or `station_passkey` if set |
| Entities go unavailable | Station stopped uploading; increase `stale_timeout` if uploads are sparse |
| WU cloud missing data | Enable `forward_wu`; check fanout MQTT state; fan-out uses public DNS, not your LAN rewrite |

---

## Development

```bash
docker compose -f deploy/compose/docker-compose.yml --profile test run --rm test
# or: PATH=$HOME/.local/go/bin:$PATH go test ./...
```

Injection fuzz targets: `scripts/fuzz.sh` (uses the compose `test` service).

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0)
