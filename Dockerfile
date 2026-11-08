FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pwsbridge ./cmd/pwsbridge
RUN mkdir -p /out/data && chown 65532:65532 /out/data

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/pwsbridge /pwsbridge
COPY --from=build --chown=65532:65532 /out/data /data
USER nonroot:nonroot
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/pwsbridge"]
