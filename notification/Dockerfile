# syntax=docker/dockerfile:1
# Сборка статического бинарника, затем минимальный distroless-образ без shell,
# запускаемый от непривилегированного пользователя.

FROM golang:1.24-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/notification ./cmd/notification

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/notification /notification
USER nonroot:nonroot
# Портов наружу нет: /healthz слушает только 127.0.0.1:8000 для HEALTHCHECK
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 CMD ["/notification", "healthcheck"]
ENTRYPOINT ["/notification"]
