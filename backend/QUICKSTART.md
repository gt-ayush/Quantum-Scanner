# Quantum Sentinel AI - Quick Start Guide

Get up and running with Quantum Sentinel AI in 5 minutes.

## Prerequisites

- Go 1.20+ installed
- PostgreSQL 12+ running
- Git (for cloning)

## Quick Start (Local Development)

### 1. Clone and Setup

```bash
cd backend
go mod tidy
```

### 2. Start PostgreSQL

```bash
# Using Docker (recommended)
docker run -d --name quantum-db \
  -e POSTGRES_DB=quantum_sentinel \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  postgres:15

# Wait for database to be ready
sleep 5
```

### 3. Set Environment Variables
**Linux**
```bash
export DB_CONNECTION_URL="postgresql://postgres:password@localhost:5432/quantum_sentinel"
export JWT_SECRET="test-secret-key-change-it"
```
**Windows**
```shell
$env:DB_CONNECTION_URL="postgresql://postgres:password@localhost:5432/quantum_sentinel"
$env:JWT_SECRET="test-secret-key-change-it"
```

### 4. Build and Run

```bash
# Build
go build -o bin/quantum-sentinel-api ./cmd/api

# Run
./bin/quantum-sentinel-api -host 0.0.0.0 -port 8080
```

Expected output:
```
Successfully connected to PostgreSQL database
Starting Quantum Sentinel API server on 0.0.0.0:8080
```

### 5. Test the API

In another terminal:

```bash
# Health check (no auth required)
curl http://localhost:8080/health

# Response:
{
  "status": "UP",
  "timestamp": "2024-03-24T10:30:00Z",
  "service": "Quantum Sentinel AI",
  "version": "1.0.0"
}
```

## Scanning an Endpoint

### Generate a Test JWT Token

```bash
# For development, create a simple token
go run -e "$(cat <<'EOF'
package main
import (
    "fmt"
    "github.com/golang-jwt/jwt/v5"
    "time"
)
func main() {
    claims := jwt.MapClaims{
        "user_id": "test@example.com",
        "email":   "test@example.com",
        "role":    "Admin",
        "exp":     time.Now().Add(time.Hour).Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, _ := token.SignedString([]byte("test-secret-key-change-this-in-production"))
    fmt.Println(tokenString)
}
EOF
)"
```

Or use an online JWT generator with:
- **Payload**: `{"user_id":"test@example.com","email":"test@example.com","role":"Admin"}`
- **Secret**: `test-secret-key-change-this-in-production`

### Scan a Domain

```bash
# Replace TOKEN with your JWT token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X POST http://localhost:8080/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "port": 443,
    "service": "HTTPS"
  }' | jq .
```

### Response Example

```json
{
  "status": "SUCCESS",
  "message": "Scan completed for example.com:443",
  "cbom": {
    "cbom_version": "1.0.0",
    "generated_at": "2024-03-24T10:30:00Z",
    "asset": {
      "fqdn": "example.com",
      "port": 443,
      "service": "HTTPS",
      "exposure": "Production"
    },
    "cryptographic_inventory": {
      "tls_version": "TLS 1.3",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "key_length": 384,
      "key_exchange": "ECDHE",
      "signature_algorithm": "ECDSA"
    },
    "quantum_assessment": {
      "vulnerability_score": 1.0,
      "risk_level": "LOW",
      "is_quantum_safe": true,
      "components": [
        {
          "component": "TLS_VERSION",
          "score": 1.0,
          "risk_level": "LOW",
          "reason": "TLS version 0x303"
        }
      ],
      "recommendations": [
        "Upgrade to TLS 1.3 with post-quantum cryptography (PQC) cipher suites (e.g., MLKEM768+ECC)"
      ]
    }
  }
}
```

## Batch Scanning

Scan multiple endpoints concurrently:

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X POST "http://localhost:8080/api/v1/batch-scan?maxWorkers=10" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "assets": [
      {"fqdn": "example.com", "port": 443, "service": "HTTPS"},
      {"fqdn": "api.example.com", "port": 443, "service": "HTTPS"},
      {"fqdn": "payment.example.com", "port": 8443, "service": "HTTPS"}
    ]
  }' | jq .
```

## Database Queries

### Query Recent Scans

```bash
# Connect to PostgreSQL
psql -U postgres -h localhost -d quantum_sentinel

# View scan history
SELECT fqdn, risk_level, vulnerability_score, generated_at 
FROM scan_history 
ORDER BY generated_at DESC 
LIMIT 10;
```

### Query Critical Vulnerabilities

```sql
SELECT fqdn, risk_level, vulnerability_score, generated_at 
FROM scan_history 
WHERE risk_level = 'CRITICAL' 
ORDER BY vulnerability_score DESC;
```

### Query CBOM Data

```sql
-- Find all ECDHE cipher suites
SELECT fqdn, 
       cbom_data->>'generated_at' as timestamp,
       cbom_data->'cryptographic_inventory'->>'cipher_suite' as cipher
FROM scan_history 
WHERE cbom_data->'cryptographic_inventory'->>'cipher_suite' LIKE '%ECDHE%';

-- Find TLS 1.2 endpoints
SELECT fqdn, 
       cbom_data->'cryptographic_inventory'->>'tls_version' as tls_version
FROM scan_history 
WHERE cbom_data->'cryptographic_inventory'->>'tls_version' = 'TLS 1.2';
```

## Useful Commands

### View Logs

```bash
# Real-time logs
tail -f quantum_sentinel.log

# Search for errors
grep "ERROR" quantum_sentinel.log
```

### Restart Service

```bash
# Stop
kill $(lsof -t -i:8080)

# Start
./bin/quantum-sentinel-api
```

### Database Maintenance

```bash
# Backup database
pg_dump quantum_sentinel > backup_$(date +%Y%m%d).sql

# Analyze query performance
EXPLAIN ANALYZE 
SELECT * FROM scan_history 
WHERE fqdn = 'example.com' 
ORDER BY generated_at DESC;

# Vacuum for maintenance
VACUUM ANALYZE scan_history;
```

## Production Deployment

See [CONFIGURATION.md](CONFIGURATION.md) for detailed deployment instructions.

### Docker Deployment

```bash
# Build image
docker build -t quantum-sentinel-api:latest .

# Run container
docker run -d --name quantum-api \
  -e DB_CONNECTION_URL="postgresql://..." \
  -e JWT_SECRET="your-secret" \
  -p 8080:8080 \
  quantum-sentinel-api:latest
```

### Docker Compose

```bash
docker-compose up -d
```

## Troubleshooting

### Connection Refused

```
Error: Failed to initialize database: failed to ping database
```

**Solution**: 
- Ensure PostgreSQL is running: `docker ps | grep postgres`
- Check connection string: `echo $DB_CONNECTION_URL`
- Verify credentials

### JWT Error

```
Unauthorized: Invalid token
```

**Solution**:
- Verify token is valid JWT format
- Check JWT_SECRET matches token signing key
- Ensure token hasn't expired

### Port Already in Use

```
Address already in use: :8080
```

**Solution**:
```bash
# Kill process on port
lsof -ti:8080 | xargs kill -9

# Or use different port
./bin/quantum-sentinel-api -port 9090
```

### Database Schema Error

```
ERROR: relation "scan_history" does not exist
```

**Solution**:
- Server automatically creates schema on startup
- Ensure PostgreSQL is running before starting server
- Check database permissions

## Next Steps

1. **Review** [README.md](README.md) for detailed documentation
2. **Configure** environment-specific settings in [CONFIGURATION.md](CONFIGURATION.md)
3. **Deploy** using Docker or Kubernetes
4. **Integrate** with your dashboard/monitoring tools
5. **Run** production scans on your infrastructure

## Example Workflow

```bash
# 1. Generate JWT token
TOKEN="eyJhbGc..."

# 2. Scan a domain
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"domain":"bank.example.com"}'

# 3. Check result
curl http://localhost:8080/api/v1/cbom?domain=bank.example.com \
  -H "Authorization: Bearer $TOKEN"

# 4. Query database for critical vulnerabilities
psql -U postgres -d quantum_sentinel \
  -c "SELECT * FROM scan_history WHERE risk_level='CRITICAL'"

# 5. Generate recommendations
# Use API analysis endpoint for detailed assessment
curl http://localhost:8080/api/v1/risk-summary \
  -H "Authorization: Bearer $TOKEN"
```

## Support

For issues and questions:
1. Check [README.md](README.md) FAQ section
2. Review [CONFIGURATION.md](CONFIGURATION.md) for setup issues
3. Check application logs for detailed error messages
4. Verify database connectivity and credentials

---

**Version**: 1.0.0  
**Last Updated**: March 24, 2026
