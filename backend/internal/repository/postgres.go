package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"quantum-sentinel/internal/core"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepo implements the Repository interface using PostgreSQL with pgx
type PostgresRepo struct {
	pool *pgxpool.Pool
}

// NewPostgresRepo creates a new PostgreSQL repository instance
func NewPostgresRepo(pool *pgxpool.Pool) *PostgresRepo {
	return &PostgresRepo{pool: pool}
}

// InitSchema creates the required database tables if they don't exist
// Uses JSONB for flexible CBOM storage as per requirements
func (r *PostgresRepo) InitSchema(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS scan_history (
		id BIGSERIAL PRIMARY KEY,
		fqdn VARCHAR(255) NOT NULL,
		port INT NOT NULL DEFAULT 443,
		service VARCHAR(100),
		generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
		cbom_data JSONB NOT NULL,
		risk_level VARCHAR(50),
		vulnerability_score NUMERIC(4, 2),
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		created_by VARCHAR(255),
		INDEX idx_fqdn (fqdn),
		INDEX idx_risk_level (risk_level),
		INDEX idx_generated_at (generated_at),
		INDEX idx_cbom_data USING GIN (cbom_data)
	);

	CREATE TABLE IF NOT EXISTS scan_batch (
		id BIGSERIAL PRIMARY KEY,
		batch_id VARCHAR(36) UNIQUE NOT NULL,
		total_scans INT NOT NULL,
		successful_scans INT DEFAULT 0,
		failed_scans INT DEFAULT 0,
		status VARCHAR(50) NOT NULL,
		started_at TIMESTAMP WITH TIME ZONE NOT NULL,
		completed_at TIMESTAMP WITH TIME ZONE,
		created_by VARCHAR(255),
		metadata JSONB,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		INDEX idx_batch_id (batch_id),
		INDEX idx_status (status)
	);

	CREATE TABLE IF NOT EXISTS audit_log (
		id BIGSERIAL PRIMARY KEY,
		user_id VARCHAR(255) NOT NULL,
		action VARCHAR(100) NOT NULL,
		resource_type VARCHAR(100),
		resource_id VARCHAR(255),
		details TEXT,
		timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		INDEX idx_user_id (user_id),
		INDEX idx_timestamp (timestamp)
	);
	`

	_, err := r.pool.Exec(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	return nil
}

// Save stores a CBOM record in the database as JSONB
// Parameters:
//   - ctx: Context with timeout
//   - cbom: The CBOM to store
//
// Returns error if the operation fails
func (r *PostgresRepo) Save(ctx context.Context, cbom *core.CBOM) error {
	if cbom == nil {
		return fmt.Errorf("cbom cannot be nil")
	}

	// Marshal CBOM to JSON for JSONB storage
	cbomJSON, err := json.Marshal(cbom)
	if err != nil {
		return fmt.Errorf("failed to marshal CBOM: %w", err)
	}

	query := `
		INSERT INTO scan_history (
			fqdn, port, service, generated_at, cbom_data, 
			risk_level, vulnerability_score, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`

	var id int64
	err = r.pool.QueryRow(ctx, query,
		cbom.Asset.FQDN,
		cbom.Asset.Port,
		cbom.Asset.Service,
		cbom.GeneratedAt,
		cbomJSON,
		cbom.QuantumAssess.RiskLevel,
		cbom.QuantumAssess.VulnerabilityScore,
		"system", // Would be passed from middleware context
	).Scan(&id)

	if err != nil {
		return fmt.Errorf("failed to insert CBOM (fqdn=%s): %w", cbom.Asset.FQDN, err)
	}

	return nil
}

// GetHistory retrieves scan history for a specific domain with optional filtering
// Parameters:
//   - ctx: Context with timeout
//   - domain: The FQDN to query
//   - Optional: filter by date range, risk level, etc.
//
// Returns list of CBOMs or error
func (r *PostgresRepo) GetHistory(ctx context.Context, domain string) ([]core.CBOM, error) {
	return r.GetHistoryWithFilter(ctx, core.HistoryFilter{
		Domain: domain,
		Limit:  100,
	})
}

// GetHistoryWithFilter retrieves scan history with advanced filtering
func (r *PostgresRepo) GetHistoryWithFilter(ctx context.Context, filter core.HistoryFilter) ([]core.CBOM, error) {
	query := `
		SELECT cbom_data FROM scan_history 
		WHERE fqdn = $1
	`

	args := []interface{}{filter.Domain}
	argIndex := 2

	// Add optional filters
	if !filter.StartDate.IsZero() {
		query += fmt.Sprintf(" AND generated_at >= $%d", argIndex)
		args = append(args, filter.StartDate)
		argIndex++
	}

	if !filter.EndDate.IsZero() {
		query += fmt.Sprintf(" AND generated_at <= $%d", argIndex)
		args = append(args, filter.EndDate)
		argIndex++
	}

	if filter.RiskLevel != "" {
		query += fmt.Sprintf(" AND risk_level = $%d", argIndex)
		args = append(args, filter.RiskLevel)
		argIndex++
	}

	// Default limit
	if filter.Limit == 0 {
		filter.Limit = 100
	}

	query += fmt.Sprintf(" ORDER BY generated_at DESC LIMIT %d OFFSET %d", filter.Limit, filter.Offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query history for %s: %w", filter.Domain, err)
	}
	defer rows.Close()

	var cboms []core.CBOM
	for rows.Next() {
		var cbomJSON []byte
		if err := rows.Scan(&cbomJSON); err != nil {
			return nil, fmt.Errorf("failed to scan CBOM: %w", err)
		}

		var cbom core.CBOM
		if err := json.Unmarshal(cbomJSON, &cbom); err != nil {
			return nil, fmt.Errorf("failed to unmarshal CBOM: %w", err)
		}

		cboms = append(cboms, cbom)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating scan history: %w", err)
	}

	return cboms, nil
}

// GetLatestScan retrieves the most recent scan for a domain
func (r *PostgresRepo) GetLatestScan(ctx context.Context, domain string) (*core.CBOM, error) {
	query := `
		SELECT cbom_data FROM scan_history 
		WHERE fqdn = $1 
		ORDER BY generated_at DESC 
		LIMIT 1
	`

	var cbomJSON []byte
	err := r.pool.QueryRow(ctx, query, domain).Scan(&cbomJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // No scan history
		}
		return nil, fmt.Errorf("failed to get latest scan for %s: %w", domain, err)
	}

	var cbom core.CBOM
	if err := json.Unmarshal(cbomJSON, &cbom); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOM: %w", err)
	}

	return &cbom, nil
}

// GetScansByRiskLevel retrieves all scans with a specific risk level
func (r *PostgresRepo) GetScansByRiskLevel(ctx context.Context, riskLevel string, limit int) ([]core.CBOM, error) {
	if limit == 0 {
		limit = 100
	}

	query := `
		SELECT cbom_data FROM scan_history 
		WHERE risk_level = $1 
		ORDER BY generated_at DESC 
		LIMIT $2
	`

	rows, err := r.pool.Query(ctx, query, riskLevel, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query scans by risk level %s: %w", riskLevel, err)
	}
	defer rows.Close()

	var cboms []core.CBOM
	for rows.Next() {
		var cbomJSON []byte
		if err := rows.Scan(&cbomJSON); err != nil {
			return nil, fmt.Errorf("failed to scan CBOM: %w", err)
		}

		var cbom core.CBOM
		if err := json.Unmarshal(cbomJSON, &cbom); err != nil {
			return nil, fmt.Errorf("failed to unmarshal CBOM: %w", err)
		}

		cboms = append(cboms, cbom)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating scans: %w", err)
	}

	return cboms, nil
}

// DeleteOldScans removes scans older than the specified duration
func (r *PostgresRepo) DeleteOldScans(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoffDate := time.Now().Add(-olderThan)

	query := `
		DELETE FROM scan_history 
		WHERE generated_at < $1
	`

	result, err := r.pool.Exec(ctx, query, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old scans: %w", err)
	}

	return result.RowsAffected(), nil
}

// LogAudit records an audit log entry
func (r *PostgresRepo) LogAudit(ctx context.Context, userID, action, resourceType, resourceID, details string) error {
	query := `
		INSERT INTO audit_log (user_id, action, resource_type, resource_id, details)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.pool.Exec(ctx, query, userID, action, resourceType, resourceID, details)
	if err != nil {
		return fmt.Errorf("failed to log audit entry: %w", err)
	}

	return nil
}

// StoreBatchScan records a batch scan job
func (r *PostgresRepo) StoreBatchScan(ctx context.Context, batchID string, totalScans int, createdBy string, metadata map[string]interface{}) error {
	metadataJSON, _ := json.Marshal(metadata)

	query := `
		INSERT INTO scan_batch (batch_id, total_scans, status, started_at, created_by, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.pool.Exec(ctx, query,
		batchID,
		totalScans,
		"RUNNING",
		time.Now(),
		createdBy,
		metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to store batch scan: %w", err)
	}

	return nil
}

// UpdateBatchScanStatus updates the status of a batch scan job
func (r *PostgresRepo) UpdateBatchScanStatus(ctx context.Context, batchID string, status string, successCount, failureCount int) error {
	query := `
		UPDATE scan_batch 
		SET status = $1, successful_scans = $2, failed_scans = $3, completed_at = $4
		WHERE batch_id = $5
	`

	_, err := r.pool.Exec(ctx, query, status, successCount, failureCount, time.Now(), batchID)
	if err != nil {
		return fmt.Errorf("failed to update batch scan status: %w", err)
	}

	return nil
}

// Close closes the database connection pool
func (r *PostgresRepo) Close() {
	if r.pool != nil {
		r.pool.Close()
	}
}
