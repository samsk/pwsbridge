# pwsbridge Home Assistant add-on

Receives Weather Underground (and Ecowitt) uploads and publishes Home Assistant MQTT discovery sensors.

## Credentials

| Option | Role |
|--------|------|
| `station_id` | Public id: WU `ID`, MQTT topics, HA device name |
| `station_password` | WU `PASSWORD`. Also the default Ecowitt `PASSKEY` |
| `station_passkey` | Optional. Set only when the device Ecowitt `PASSKEY` is not the same as the WU password |

The weather station console usually needs no change: keep uploading with its existing WU password / Ecowitt PASSKEY, and mirror those values into the options above.

## Network

Enable DNS rewrites for `rtupdate.wunderground.com` and `weatherstation.wunderground.com` to the Home Assistant host when the station has no Customized Server option.

Map host port **80** to add-on port **8080** when the station uploads on port 80. The process listens on **8080** only (no privileged bind inside the container).

## Options

All options map to `PWSBRIDGE_*` environment variables.

| Option | Env | Notes |
|--------|-----|--------|
| listen | PWSBRIDGE_LISTEN | Default `:8080` |
| log_level | PWSBRIDGE_LOG_LEVEL | |
| auth_mode | PWSBRIDGE_AUTH_MODE | `password` (recommended) or `open` |
| station_id | PWSBRIDGE_STATION_ID | Public id |
| station_password | PWSBRIDGE_STATION_PASSWORD | WU password / default Ecowitt PASSKEY |
| station_passkey | PWSBRIDGE_STATION_PASSKEY | Optional Ecowitt override |
| mqtt_broker | PWSBRIDGE_MQTT_BROKER | Empty → supervisor MQTT service |
| mqtt_username | PWSBRIDGE_MQTT_USERNAME | |
| mqtt_password | PWSBRIDGE_MQTT_PASSWORD | |
| mqtt_discovery_prefix | PWSBRIDGE_MQTT_DISCOVERY_PREFIX | Default `homeassistant` |
| prometheus | PWSBRIDGE_PROMETHEUS | |
| forward_wu | PWSBRIDGE_FORWARD_WU | Default `false` |
| forward_resolver | PWSBRIDGE_FORWARD_RESOLVER | IP literal, e.g. `1.1.1.1:53` |
| derived | PWSBRIDGE_DERIVED | |
| rate_limit | PWSBRIDGE_RATE_LIMIT | |
| stale_timeout | PWSBRIDGE_STALE_TIMEOUT | |

## Fan-out

When `forward_wu` is true and Weather Underground refuses an upload, forwarding for that station pauses (then disables after 24h of refusals). Status appears as a diagnostic MQTT sensor on the weather device. Network timeouts do not pause forwarding.
