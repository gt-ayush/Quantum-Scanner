# Multi-stage Dockerfile for Quantum Sentinel AI
# Optimized for production with minimal image size

# Stage 1: Build
FROM golang:1.20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
# Using -ldflags to reduce binary size and remove debug symbols
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.Version=1.0.0" \
    -o quantum-sentinel-api \
    ./cmd/api

# Stage 2: Runtime
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Create non-root user for security
RUN addgroup -g 1000 quantum-sentinel && \
    adduser -D -u 1000 -G quantum-sentinel quantum-sentinel

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/quantum-sentinel-api /app/

# Copy entrypoint script
COPY --chown=quantum-sentinel:quantum-sentinel entrypoint.sh /app/

# Give permissions
RUN chmod +x /app/quantum-sentinel-api /app/entrypoint.sh

# Create data directory if needed
RUN mkdir -p /app/data && chown quantum-sentinel:quantum-sentinel /app/data

# Switch to non-root user
USER quantum-sentinel

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default environment variables
ENV DB_CONNECTION_URL="postgresql://postgres:password@db:5432/quantum_sentinel"
ENV JWT_SECRET="change-this-in-production"
ENV SERVER_HOST="0.0.0.0"
ENV SERVER_PORT="8080"

# Run the application
ENTRYPOINT ["/app/entrypoint.sh"]
