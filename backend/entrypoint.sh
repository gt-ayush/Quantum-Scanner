#!/bin/sh
# Entrypoint script for Quantum Sentinel API Docker container

set -e

# Log startup information
echo "================================================"
echo "Quantum Sentinel AI - Starting API Server"
echo "================================================"
echo "Version: 1.0.0"
echo "Time: $(date)"
echo ""

# Verify required environment variables
if [ -z "$DB_CONNECTION_URL" ]; then
    echo "ERROR: DB_CONNECTION_URL environment variable is not set"
    exit 1
fi

if [ -z "$JWT_SECRET" ]; then
    echo "WARNING: JWT_SECRET is using default value. Set it in production!"
fi

# Display configuration
echo "Configuration:"
echo "- Server Host: ${SERVER_HOST:-0.0.0.0}"
echo "- Server Port: ${SERVER_PORT:-8080}"
echo "- Database: (configured)"
echo "- JWT Secret: (configured)"
echo ""

# Start the application with config
exec /app/quantum-sentinel-api \
    -host "${SERVER_HOST:-0.0.0.0}" \
    -port "${SERVER_PORT:-8080}" \
    -db "$DB_CONNECTION_URL" \
    -jwt-secret "$JWT_SECRET"
