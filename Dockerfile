# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=""
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/supunhg/filo-go/internal/version.Version=${VERSION} -X github.com/supunhg/filo-go/internal/version.Commit=${COMMIT}" \
      -o /out/filo ./cmd/filo

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 1000 filo \
    && mkdir -p /data && chown filo:filo /data
COPY --from=builder /out/filo /usr/local/bin/filo
COPY --from=builder /src/formats /etc/filo/formats
USER filo
WORKDIR /data
ENTRYPOINT ["filo"]
CMD ["--help"]

LABEL org.opencontainers.image.title="filo" \
      org.opencontainers.image.description="Fast, single-binary file forensics: identify, scan, carve and analyze files" \
      org.opencontainers.image.source="https://github.com/supunhg/filo-go" \
      org.opencontainers.image.licenses="Apache-2.0"
