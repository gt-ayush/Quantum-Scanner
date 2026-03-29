package core

import "context"

// Scanner defines the behavior for cryptographic discovery.
type Scanner interface {
	Scan(ctx context.Context, domain string, port int) (*CBOM, error)
}

// Repository defines the persistence layer for scan results.
type Repository interface {
	Save(ctx context.Context, cbom *CBOM) error
	GetHistory(ctx context.Context, domain string) ([]CBOM, error)
}
