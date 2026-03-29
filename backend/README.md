# Quantum Sentinel AI - Backend Implementation

**Production-Grade Backend for Quantum Cryptography Vulnerability Scanner**

A comprehensive Go-based REST API for passive quantum cryptography scanning of banking infrastructure, implementing CERT-In compliance and post-quantum cryptography (PQC) risk assessment per the Software Requirement Specification (SRS).

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Database Schema](#database-schema)
- [RBAC & Security](#rbac--security)
- [Quantum Scoring Algorithm](#quantum-scoring-algorithm)
- [Deployment](#deployment)
- [Development](#development)

## Overview

Quantum Sentinel AI is a specialized security scanner designed to identify quantum-vulnerable cryptographic implementations in banking networks. The backend:

- **Passive TLS Discovery**: Probes endpoints without establishing persistent connections
- **CBOM Generation**: Creates CERT-In compliant Cryptographic Bills of Materials (Annexure-D)
- **PQC Scoring**: Implements Annexure-B quantum vulnerability scoring (0.0-10.0 scale)
- **Batch Processing**: Handles 1,000+ assets concurrently using worker pool pattern
- **Audit Compliance**: Complete audit logging and role-based access control (RBAC)

## Architecture

### Directory Structure

```
backend/
├── cmd/
│   └── api/
│       └── main.go           # API server entry point
├── internal/
│   ├── api/
│   │   ├── handlers.go       # REST endpoint handlers
│   │   └── middleware.go     # JWT & RBAC middleware
│   ├── analyzer/
│   │   └── risk_scorer.go    # PQC vulnerability scoring engine
│   ├── core/
│   │   ├── models.go         # Data structures (CBOM, Asset, etc.)
│   │   └── ports.go          # Interface definitions
│   ├── repository/
│   │   └── postgres.go       # PostgreSQL persistence layer
│   └── scanner/
│       ├── discovery.go      # Worker pool & batch scanning
│       └── tls_probe.go      # TLS handshake & cert extraction
├── go.mod                    # Go module definition
└── go.sum                    # Dependency checksums
```

### Technology Stack

- **Language**: Go 1.20+
- **Database**: PostgreSQL 12+ with JSONB support
- **Authentication**: JWT (github.com/golang-jwt/jwt/v5)
- **Database Driver**: pgx/v5 (native PostgreSQL driver)
- **HTTP Server**: Go standard library `net/http`

## Features

### 1. **Passive TLS Scanning**
- Non-intrusive endpoint scanning
- Certificate validation & analysis
- Support for multiple TLS versions (1.0 - 1.3)
- Comprehensive cipher suite evaluation

### 2. **CBOM Generation** (Annexure-D Compliant)
- Complete cryptographic inventory
- Certificate metadata extraction
- Quantum vulnerability assessment
- Actionable recommendations

### 3. **PQC Threat Assessment** (Annexure-B Scoring)
- **TLS Version Scoring**: 1.0 (TLS 1.3) to 10.0 (Legacy)
- **Cipher Suite Evaluation**: RSA, DHE, ECDHE, PQC detection
- **Key Length Analysis**: Quantum-specific threats for different key sizes
- **Component-Level Scoring**: Individual component vulnerabilities with reasons
- **Risk Categorization**: LOW, MEDIUM, HIGH, CRITICAL

### 4. **Batch Processing**
- Worker pool pattern for concurrent scanning
- Configurable worker count (recommended 10-50)
- Context-aware cancellation support
- Per-asset error handling with retry capability

### 5. **RBAC & Audit**
- **Roles**: Admin, Checker, Operator, Auditor
- **JWT Authentication**: HMAC-SHA256 signing
- **Audit Logging**: Complete user action tracking
- **CORS Support**: Secure cross-origin requests

### 6. **Data Persistence**
- JSONB storage for flexible CBOM queries
- Optimized indexes for common queries
- Batch scan job tracking
- Historical scan retention & cleanup

## Installation

### Prerequisites

- Go 1.20 or later
- PostgreSQL 12 or later
- Git

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/quantum-sentinel.git
cd quantum-sentinel/backend
```

### Step 2: Install Dependencies

```bash
go get github.com/golang-jwt/jwt/v5
go get github.com/jackc/pgx/v5
go mod tidy
```

### Step 3: Build the Binary

```bash
go build -o bin/quantum-sentinel-api ./cmd/api
```

### Step 4: Set Up Database

```bash
# Create database
createdb quantum_sentinel

# Or use PostgreSQL client
psql -U postgres -c "CREATE DATABASE quantum_sentinel;"
```

## Configuration

### Environment Variables

```bash
# Database connection
export DB_CONNECTION_URL="postgresql://user:password@localhost:5432/quantum_sentinel"

# JWT secret (change this in production!)
export JWT_SECRET="your-super-secret-key-min-32-chars-recommended"

# Optionally configure server
export SERVER_HOST="0.0.0.0"
export SERVER_PORT="8080"
```

### Command-Line Flags

```bash
./bin/quantum-sentinel-api \
  -host 0.0.0.0 \
  -port 8080 \
  -db "postgresql://user:password@localhost:5432/quantum_sentinel" \
  -jwt-secret "your-jwt-secret"
```

## API Endpoints

### Authentication

All endpoints except `/health` require a Bearer token:

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" https://api.example.com/api/v1/...
```

### Public Endpoints

#### Health Check
```
GET /health
```

**Response**: `200 OK`
```json
{
  "status": "UP",
  "timestamp": "2024-03-24T10:30:00Z",
  "service": "Quantum Sentinel AI",
  "version": "1.0.0"
}
```

### Scan Endpoints (Admin, Operator)

#### Single Scan
```
POST /api/v1/scan
```

**Request**:
```json
{
  "domain": "example.com",
  "port": 443,
  "service": "HTTPS"
}
```

**Response**: `200 OK`
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
          "reason": "TLS 1.3 supports PQC cipher suites"
        },
        {
          "component": "CIPHER_SUITE",
          "score": 4.0,
          "risk_level": "MEDIUM",
          "reason": "ECDHE requires harvest-now-decrypt-later mitigation"
        }
      ],
      "recommendations": [
        "Upgrade to TLS 1.3 with post-quantum cryptography (PQC) cipher suites"
      ]
    }
  }
}
```

#### Batch Scan
```
POST /api/v1/batch-scan?maxWorkers=20
```

**Request**:
```json
{
  "assets": [
    {"fqdn": "api.example.com", "port": 443},
    {"fqdn": "payment.example.com", "port": 443},
    {"fqdn": "legacy.example.com", "port": 1194}
  ]
}
```

**Response**: `200 OK`
```json
{
  "status": "SUCCESS",
  "total": 3,
  "scanned": 3,
  "failed": 0,
  "results": [
    {
      "asset": {"fqdn": "api.example.com"},
      "success": true,
      "error": null
    }
  ]
}
```

### CBOM Endpoints (Checker, Operator, Auditor)

#### Get Latest CBOM
```
GET /api/v1/cbom?domain=example.com
```

**Response**: `200 OK` (Same structure as scan response)

### History Endpoints (Auditor)

#### Get Scan History
```
GET /api/v1/history?domain=example.com&limit=50&riskLevel=CRITICAL
```

**Response**: `200 OK`
```json
{
  "status": "SUCCESS",
  "domain": "example.com",
  "count": 15,
  "history": [
    { "cbom": {...} }
  ]
}
```

### Analysis Endpoints (Checker, Auditor)

#### Analyze Cipher Suite
```
GET /api/v1/analyze/cipher-suite?cipher=TLS_AES_256_GCM_SHA384
```

**Response**: `200 OK`
```json
{
  "status": "SUCCESS",
  "cipher": "TLS_AES_256_GCM_SHA384",
  "score": 4.0,
  "risk_level": "MEDIUM",
  "reason": "ECDHE requires harvest-now-decrypt-later mitigation",
  "recommendations": [
    "Use PQC-based cipher suites (MLKEM+ECC)",
    "Implement hybrid classical-quantum key exchange"
  ]
}
```

#### Get Risk Summary
```
GET /api/v1/risk-summary
```

**Response**: `200 OK`
```json
{
  "status": "SUCCESS",
  "timestamp": "2024-03-24T10:30:00Z",
  "risk_summary": {
    "critical": 5,
    "high": 12,
    "medium": 34,
    "low": 98
  },
  "total_scans": 149,
  "critical_domains": ["legacy-api.example.com"]
}
```

## Database Schema

### Tables

#### `scan_history`
Stores CBOM results with JSONB index support:

```sql
CREATE TABLE scan_history (
  id BIGSERIAL PRIMARY KEY,
  fqdn VARCHAR(255) NOT NULL,
  port INT NOT NULL DEFAULT 443,
  service VARCHAR(100),
  generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  cbom_data JSONB NOT NULL,                 -- Full CBOM stored as JSONB
  risk_level VARCHAR(50),                   -- Indexed for fast filtering
  vulnerability_score NUMERIC(4, 2),        -- For queries
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  created_by VARCHAR(255),
  
  INDEX idx_fqdn (fqdn),
  INDEX idx_risk_level (risk_level),
  INDEX idx_generated_at (generated_at),
  INDEX idx_cbom_data USING GIN (cbom_data)  -- GIN index for JSONB queries
);
```

#### `scan_batch`
Tracks batch scan jobs:

```sql
CREATE TABLE scan_batch (
  id BIGSERIAL PRIMARY KEY,
  batch_id VARCHAR(36) UNIQUE NOT NULL,
  total_scans INT NOT NULL,
  successful_scans INT DEFAULT 0,
  failed_scans INT DEFAULT 0,
  status VARCHAR(50) NOT NULL,              -- RUNNING, COMPLETED, FAILED
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  created_by VARCHAR(255),
  metadata JSONB,                           -- Batch-specific metadata
  
  INDEX idx_batch_id (batch_id),
  INDEX idx_status (status)
);
```

#### `audit_log`
Complete audit trail:

```sql
CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  action VARCHAR(100) NOT NULL,            -- SCAN, BATCH_SCAN, VIEW_CBOM, etc.
  resource_type VARCHAR(100),              -- Asset, CBOM, Batch
  resource_id VARCHAR(255),
  details TEXT,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  
  INDEX idx_user_id (user_id),
  INDEX idx_timestamp (timestamp)
);
```

## RBAC & Security

### Roles and Permissions

| Role | /scan | /batch-scan | /cbom | /history | /risk-summary | /analyze |
|------|:-----:|:-----------:|:-----:|:--------:|:-------------:|:--------:|
| Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Operator | ✓ | ✓ | ✓ | - | - | - |
| Checker | - | - | ✓ | - | ✓ | ✓ |
| Auditor | - | - | ✓ | ✓ | ✓ | ✓ |

### JWT Token Structure

```json
{
  "user_id": "user@example.com",
  "email": "user@example.com",
  "role": "Admin",
  "roles": ["Admin"],
  "org": "example-bank",
  "iat": 1711270200,
  "exp": 1711356600
}
```

### Security Best Practices

1. **JWT Secret**: Use a cryptographically strong secret (min 32 chars)
2. **HTTPS Only**: Always use HTTPS in production
3. **Token Rotation**: Implement token refresh mechanism
4. **Rate Limiting**: Add rate limiting middleware (not in base implementation)
5. **Connection Security**: Use SSL for PostgreSQL connections

## Quantum Scoring Algorithm

### Scoring Methodology (Annexure-B)

The system evaluates four key components, with the **maximum score** being the vulnerability score:

#### 1. TLS Version Scoring

| Version | Score | Risk Level | Rationale |
|---------|:-----:|:----------:|-----------|
| TLS 1.3 | 1.0 | LOW | Supports PQC cipher suites |
| TLS 1.2 | 5.0 | MEDIUM | Upgrade to 1.3 recommended |
| TLS 1.1 | 9.0 | CRITICAL | Obsolete, immediately disable |
| TLS 1.0 | 9.5 | CRITICAL | Critically weak |

#### 2. Cipher Suite Scoring

| Suite Type | Score | Risk Level | Threat Model |
|------------|:-----:|:----------:|--------------|
| MLKEM/KYBER | 1.0 | LOW | Post-quantum resistant |
| ECDHE P-384+ | 4.0 | MEDIUM | Harvest-now-decrypt-later |
| ECDHE P-256 | 5.0 | MEDIUM | Grover's algorithm threat |
| DHE | 6.0 | HIGH | Shor's algorithm vulnerable |
| RSA | 9.5 | CRITICAL | Broken by quantum computers |

#### 3. Key Length Scoring

The algorithm differentiates based on public key algorithm:

**RSA**:
- >= 4096 bits: 4.0 (MEDIUM) - Temporary safety
- 2048-4095 bits: 7.0 (HIGH) - Vulnerable to near-term attacks
- < 2048 bits: 9.5 (CRITICAL) - Immediately compromised

**ECC**:
- P-384/P-521: 3.5 (MEDIUM)
- P-256: 5.0 (MEDIUM) - Vulnerable to Grover's algorithm
- < P-256: 8.0 (HIGH)

**AES Symmetric**:
- AES-256: 2.0 (LOW) - Quantum-resistant
- AES-128: 4.0 (MEDIUM) - Vulnerable to Grover's algorithm

#### 4. Key Exchange Scoring

| Method | Score | Quantum Impact |
|--------|:-----:|---|
| PQC (MLKEM+KYBER) | 1.0 | Resistant |
| ECDHE | 5.0 | Requires strategic planning |
| DHE | 6.5 | Significant quantum risk |
| RSA | 9.5 | Completely broken |

### Scoring Formula

```
Vulnerability Score = MAX(TLS_Score, Cipher_Score, KeyExchange_Score, KeyLength_Score)
Risk Level = {
  0.0-2.5:   LOW
  2.5-5.0:   MEDIUM
  5.0-7.5:   HIGH
  7.5-10.0:  CRITICAL
}
```

### Quantum Safety Threshold

`is_quantum_safe = vulnerability_score <= 2.0`

This ensures only the most quantum-resistant configurations (TLS 1.3 + PQC cipher suites) are marked as quantum-safe.

## Deployment

### Docker (Recommended for Production)

Create a `Dockerfile`:

```dockerfile
FROM golang:1.20-alpine AS builder
WORKDIR /build
COPY . .
RUN go build -o bin/quantum-sentinel-api ./cmd/api

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/bin/quantum-sentinel-api /usr/local/bin/
EXPOSE 8080
ENV DB_CONNECTION_URL="postgresql://postgres:password@db:5432/quantum_sentinel"
ENTRYPOINT ["quantum-sentinel-api"]
```

### Docker Compose Stack

```yaml
version: '3.8'
services:
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: quantum_sentinel
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  api:
    build: ./backend
    ports:
      - "8080:8080"
    environment:
      DB_CONNECTION_URL: "postgresql://postgres:secure_password@db:5432/quantum_sentinel"
      JWT_SECRET: "your-super-secure-jwt-secret-key"
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

volumes:
  postgres_data:
```

Run with:
```bash
docker-compose up -d
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: quantum-sentinel-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: quantum-sentinel-api
  template:
    metadata:
      labels:
        app: quantum-sentinel-api
    spec:
      containers:
      - name: api
        image: quantum-sentinel-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: DB_CONNECTION_URL
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: connection-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: jwt-secret
              key: secret
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
---
apiVersion: v1
kind: Service
metadata:
  name: quantum-sentinel-api
spec:
  type: LoadBalancer
  selector:
    app: quantum-sentinel-api
  ports:
  - port: 443
    targetPort: 8080
    protocol: TCP
```

## Development

### Building from Source

```bash
cd backend
go build -o bin/quantum-sentinel-api ./cmd/api
./bin/quantum-sentinel-api
```

### Running Tests

```bash
go test ./...
```

### Code Quality

```bash
# Format code
go fmt ./...

# Lint with golangci-lint
golangci-lint run

# Vet for suspicious code
go vet ./...
```

### Running Locally

1. Start PostgreSQL:
   ```bash
   docker run -d --name postgres \
     -e POSTGRES_DB=quantum_sentinel \
     -e POSTGRES_PASSWORD=password \
     -p 5432:5432 \
     postgres:15
   ```

2. Set environment variables:
   ```bash
   export DB_CONNECTION_URL="postgresql://postgres:password@localhost:5432/quantum_sentinel"
   export JWT_SECRET="test-secret-key-not-for-production"
   ```

3. Run the server:
   ```bash
   go run ./cmd/api
   ```

4. Test an endpoint:
   ```bash
   curl http://localhost:8080/health
   ```

## Performance Considerations

### Worker Pool Sizing

For optimal performance:
- **Network I/O bound**: 10-20 workers (DNS lookups, TLS handshakes)
- **CPU intensive**: Number of CPU cores
- **Batch recommendations**: Start with 10 workers, monitor and adjust

### Database Optimization

- GIN indexes on JSONB columns for complex queries
- Connection pooling with pgx (10-50 connections recommended)
- Regular vacuum & analyze for table statistics

### Caching Strategy

Consider implementing:
- Cipher suite definitions cache
- Recent CBOM results cache
- JWT token validation cache

## Comprehensive Example Usage

### Generate JWT Token (Development)

```bash
# Using JWT CLI tool
jwt encode -S HS256 -s "your-jwt-secret" \
  -P user_id:test@example.com \
  -P email:test@example.com \
  -P role:Admin \
  -P org:example-bank
```

### Scan a Single Domain

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X POST http://localhost:8080/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "port": 443,
    "service": "HTTPS"
  }'
```

### Perform Batch Scan

```bash
curl -X POST "http://localhost:8080/api/v1/batch-scan?maxWorkers=20" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "assets": [
      {"fqdn": "api.example.com", "port": 443},
      {"fqdn": "payment.example.com", "port": 443},
      {"fqdn": "admin.example.com", "port": 8443}
    ]
  }'
```

### Query Scan History

```bash
curl -X GET "http://localhost:8080/api/v1/history?domain=example.com&limit=10&riskLevel=CRITICAL" \
  -H "Authorization: Bearer $TOKEN"
```

## Compliance & Standards

- **CERT-In Requirements**: CBOM format per Annexure-D
- **Scoring Methodology**: Annexure-B quantum vulnerability assessment
- **RBAC Framework**: Annexure-A role definitions
- **Security Standards**: TLS best practices, JWT RFC 7519

## Support & Troubleshooting

### Common Issues

1. **Database Connection Error**: Verify PostgreSQL is running and connection URL is correct
2. **JWT Validation Failed**: Check JWT_SECRET environment variable matches token signing key
3. **Port Already in Use**: Change port with `-port` flag or `SERVER_PORT` env var
4. **TLS Certificate Error**: Ensure target domain has valid certificate (InsecureSkipVerify is enabled for scanning)

## License

Internal Use - Proprietary Software

---

**Version**: 1.0.0  
**Last Updated**: March 24, 2026  
**Maintainer**: Quantum Sentinel Development Team
