FROM golang:1.26-alpine AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -o /mock-wu main.go

FROM gcr.io/distroless/static:nonroot
COPY --from=build /mock-wu /mock-wu
EXPOSE 80 443
ENTRYPOINT ["/mock-wu"]
