# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/filo ./cmd/filo/

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN adduser -D -u 1000 filo

# Copy binary from builder
COPY --from=builder /build/filo /usr/local/bin/filo

# Copy format definitions
COPY --from=builder /build/formats /etc/filo/formats

# Create directories for data
RUN mkdir -p /data /output && chown -R filo:filo /data /output

# Switch to non-root user
USER filo

# Set working directory
WORKDIR /data

# Default entrypoint
ENTRYPOINT ["filo"]

# Default command
CMD ["--help"]

# Labels
LABEL maintainer="sanchithahewagamage@gmail.com"
LABEL description="filo-go - Forensic Intelligence & Learning Operator"
LABEL version="0.4.0"
