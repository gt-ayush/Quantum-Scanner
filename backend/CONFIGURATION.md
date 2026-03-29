# Quantum Sentinel AI - Configuration Guide

This document provides detailed configuration options for deploying Quantum Sentinel AI in various environments.

## Environment Configuration

### Development Environment

```bash
# .env.development
DB_CONNECTION_URL="postgresql://postgres:password@localhost:5432/quantum_sentinel_dev"
JWT_SECRET="dev-secret-key-change-this-in-production"
SERVER_HOST="localhost"
SERVER_PORT="8080"
LOG_LEVEL="DEBUG"
```

### Staging Environment

```bash
# .env.staging
DB_CONNECTION_URL="postgresql://user:password@staging-db.internal:5432/quantum_sentinel"
JWT_SECRET="staging-jwt-secret-min-32-characters-recommended"
SERVER_HOST="0.0.0.0"
SERVER_PORT="8080"
LOG_LEVEL="INFO"
CORS_ALLOWED_ORIGINS="https://staging.example.com"
```

### Production Environment

```bash
# .env.production (Secure storage recommended: AWS Secrets Manager, HashiCorp Vault, etc.)
DB_CONNECTION_URL="postgresql://user:$(cat /run/secrets/db_password)@prod-db.internal:5432/quantum_sentinel"
JWT_SECRET="$(cat /run/secrets/jwt_secret)"
SERVER_HOST="0.0.0.0"
SERVER_PORT="8080"
LOG_LEVEL="WARN"
CORS_ALLOWED_ORIGINS="https://api.example.com,https://dashboard.example.com"
TLS_CERT_PATH="/etc/ssl/certificates/cert.pem"
TLS_KEY_PATH="/etc/ssl/certificates/key.pem"
RATE_LIMIT_PER_MINUTE="120"
MAX_REQUEST_SIZE="10MB"
```

## Database Configuration

### PostgreSQL Connection String Options

```bash
# Basic
postgresql://user:password@localhost:5432/quantum_sentinel

# With SSL
postgresql://user:password@prod-db.internal:5432/quantum_sentinel?sslmode=require

# With SSL certificates
postgresql://user:password@prod-db.internal:5432/quantum_sentinel?sslmode=verify-full&sslcert=/path/to/cert&sslkey=/path/to/key

# With connection timeout
postgresql://user:password@localhost:5432/quantum_sentinel?connect_timeout=10
```

### Connection Pool Tuning

In `internal/repository/postgres.go`, adjust these values:

```go
config.MaxConns = 50              // Maximum concurrent connections
config.MinConns = 10              // Minimum idle connections
config.MaxConnLifetime = 5 * time.Minute    // Connection lifetime
config.MaxConnIdleTime = 2 * time.Minute    // Idle connection timeout
config.HealthCheckPeriod = 30 * time.Second // Health check interval
```

## JWT Configuration

### Generating JWT Secret

```bash
# Using OpenSSL
openssl rand -base64 32

# Using Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Using Go
go run -c 'package main; import ("crypto/rand"; "encoding/base64"; "fmt"; "os") 
func main() { b := make([]byte, 32); rand.Read(b); fmt.Println(base64.StdEncoding.EncodeToString(b)) }'
```

### Token Expiration

Default: 1 hour (modify in token generation code)

```go
expirationTime := time.Now().Add(1 * time.Hour)
claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(expirationTime)
```

## TLS/HTTPS Configuration

### Self-Signed Certificate (Development Only)

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate certificate
openssl req -new -x509 -key server.key -out server.crt -days 365
```

### Production Certificate (Let's Encrypt)

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Generate certificate
sudo certbot certonly --standalone -d api.example.com

# Paths
# Certificate: /etc/letsencrypt/live/api.example.com/fullchain.pem
# Private Key: /etc/letsencrypt/live/api.example.com/privkey.pem
```

## Logging Configuration

Current implementation uses Go's standard `log` package. For production, integrate:

```go
// Example: Using structured logging with zap
import "go.uber.org/zap"

logger, _ := zap.NewProduction()
defer logger.Sync()

logger.Info("Server started",
    zap.String("host", config.Host),
    zap.Int("port", config.Port),
)
```

## Rate Limiting Configuration

To add rate limiting (not in base implementation):

```go
import "github.com/didip/tollbooth"

limiter := tollbooth.NewLimiter(120, &http.Header{})  // 120 requests per minute
limiter.SetIPLookups([]string{"X-Forwarded-For", "X-Real-IP", "RemoteAddr"})

// Apply to routes
http.HandleFunc("/api/v1/scan", tollbooth.LimitHandler(limiter, handler.ScanHandler).ServeHTTP)
```

## Security Headers Configuration

In `cmd/api/main.go`, add security headers:

```go
globalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // Security headers
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("X-XSS-Protection", "1; mode=block")
    w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    w.Header().Set("Content-Security-Policy", "default-src 'self'")
    w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
    
    mux.ServeHTTP(w, r)
})
```

## Scanner Configuration

### Worker Pool Settings

Adjust concurrency based on your infrastructure:

```bash
# For light workloads
./quantum-sentinel-api -workers 5

# For standard workloads
./quantum-sentinel-api -workers 20

# For heavy workloads
./quantum-sentinel-api -workers 100
```

### TLS Probe Timeout

In `internal/scanner/tls_probe.go`:

```go
dialer := &net.Dialer{
    Timeout: 10 * time.Second,  // Adjust as needed
}
```

### Supported Ports for Banking

Current implementation probes port 443. To scan multiple ports:

```go
bankingPorts := []int{443, 1194, 1703, 500, 8443}
for _, port := range bankingPorts {
    state, err := scanner.ProbeTLS(domain, port)
    // ...
}
```

## Deployment Environment Variables

### Docker Compose

```yaml
environment:
  DB_CONNECTION_URL: postgresql://postgres:${DB_PASSWORD}@db:5432/quantum_sentinel
  JWT_SECRET: ${JWT_SECRET}
  SERVER_HOST: 0.0.0.0
  SERVER_PORT: 8080
```

### Kubernetes Secrets

```bash
# Create secrets
kubectl create secret generic db-credentials \
  --from-literal=connection-url='postgresql://...'

kubectl create secret generic jwt-secret \
  --from-literal=secret='your-jwt-secret'
```

## Reverse Proxy Configuration

### Nginx

```nginx
upstream quantum_sentinel {
    server localhost:8080;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certificates/cert.pem;
    ssl_certificate_key /etc/ssl/certificates/key.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    limit_req zone=api_limit burst=20 nodelay;

    location / {
        proxy_pass http://quantum_sentinel;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Apache

```apache
<VirtualHost *:443>
    ServerName api.example.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certificates/cert.pem
    SSLCertificateKeyFile /etc/ssl/certificates/key.pem

    <Directory /var/www/proxy>
        Require all granted
    </Directory>

    ProxyPreserveHost On
    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/

    # Security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=31536000"
</VirtualHost>
```

## Monitoring & Observability

### Prometheus Metrics (Add to implementation)

```go
import "github.com/prometheus/client_golang/prometheus"

var (
    scanCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "quantum_sentinel_scans_total",
            Help: "Total number of scans performed",
        },
        []string{"status", "risk_level"},
    )
    scanDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "quantum_sentinel_scan_duration_seconds",
            Help: "Duration of scan operations",
        },
        []string{"domain"},
    )
)
```

### Health Check Endpoint

The `/health` endpoint is available for monitoring:

```bash
curl http://localhost:8080/health
```

## Backup & Restore

### PostgreSQL Backup

```bash
# Full backup
pg_dump quantum_sentinel > quantum_sentinel_backup.sql

# Compressed backup
pg_dump quantum_sentinel | gzip > quantum_sentinel_backup.sql.gz

# Custom format (faster restore)
pg_dump -Fc quantum_sentinel > quantum_sentinel_backup.dump
```

### Restore from Backup

```bash
# From SQL dump
psql quantum_sentinel < quantum_sentinel_backup.sql

# From custom format dump
pg_restore -d quantum_sentinel quantum_sentinel_backup.dump
```

## Scaling Considerations

### Horizontal Scaling

Deploy multiple API instances behind a load balancer:

```
┌──────────────────┐
│   Load Balancer  │
├──────────────────┤
│  API Instance 1  │
│  API Instance 2  │
│  API Instance 3  │
└────────┬─────────┘
         │
    ┌────▼─────┐
    │PostgreSQL │
    └───────────┘
```

### Database Scaling

For high query volumes:
- Use read replicas for `/history` and analysis endpoints
- Implement query result caching
- Archive old scans to separate tables

## Configuration Checklist

- [ ] Database connection verified
- [ ] JWT secret configured (minimum 32 characters)
- [ ] TLS/HTTPS certificates installed
- [ ] CORS origins configured
- [ ] Worker pool size optimized for hardware
- [ ] Backup strategy implemented
- [ ] Monitoring configured
- [ ] Rate limiting enabled
- [ ] Security headers configured
- [ ] Firewall rules configured
- [ ] Log aggregation setup
- [ ] Alerting rules configured

---

**Last Updated**: March 24, 2026
