#!/usr/bin/env sh
# Run injection fuzz targets inside the compose test service.
set -eu

COMPOSE="${COMPOSE:-docker compose -f deploy/compose/docker-compose.yml}"
FUZZTIME="${FUZZTIME:-10s}"

TARGETS="
internal/policy:FuzzValidStationID
internal/ingress/wu:FuzzWUApplyParams
internal/ingress/ecowitt:FuzzEcowittApplyParams
internal/ingress/ecowitt:FuzzParseDateUTC
internal/sink/mqtt:FuzzDiscoveryPayload
internal/server:FuzzWUHandler
internal/server:FuzzEcowittHandler
"

for entry in $TARGETS; do
	pkg="${entry%%:*}"
	name="${entry##*:}"
	echo "==> fuzz $pkg $name ($FUZZTIME)"
	$COMPOSE run --rm test go test "./$pkg" -run='^$' "-fuzz=$name" "-fuzztime=$FUZZTIME"
done
