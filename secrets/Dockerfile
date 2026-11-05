FROM golang:1.26.4-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/secrets ./cmd/secrets

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/secrets /secrets
USER 65532:65532
EXPOSE 8000
ENTRYPOINT ["/secrets"]
