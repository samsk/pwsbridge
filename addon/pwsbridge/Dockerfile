ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.21
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /pwsbridge ./cmd/pwsbridge

FROM ${BUILD_FROM}
COPY --from=build /pwsbridge /usr/bin/pwsbridge
COPY addon/pwsbridge/rootfs /
RUN chmod a+x /etc/s6-overlay/s6-rc.d/pwsbridge/run
LABEL io.hass.name="pwsbridge" io.hass.type="addon" io.hass.version="0.1.0"
