FROM node:24-alpine AS frontend
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run check && npm run build

FROM golang:1.26.4-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/gateway /gateway
COPY --from=frontend /ui/dist /frontend
ENV FRONTEND_DIR=/frontend
USER 65532:65532
EXPOSE 8000
ENTRYPOINT ["/gateway"]
