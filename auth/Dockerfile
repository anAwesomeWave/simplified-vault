# syntax=docker/dockerfile:1
# Сборка статического бинарника, затем минимальный distroless-образ без shell,
# запускаемый от непривилегированного пользователя.

FROM golang:1.24-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/auth ./cmd/auth

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/auth /auth
USER nonroot:nonroot
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 CMD ["/auth", "healthcheck"]
ENTRYPOINT ["/auth"]
