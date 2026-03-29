package core

import (
	"time"
)

const (
	CBOMVersion = "1.0.0"

	// Risk Levels (Annexure-B)
	RiskLevelsLow      = "LOW"
	RiskLevelsMedium   = "MEDIUM"
	RiskLevelsHigh     = "HIGH"
	RiskLevelsCritical = "CRITICAL"
)

// ScanRequest represents the incoming payload for /api/v1/scan
type ScanRequest struct {
	Domain  string `json:"domain"`
	Port    int    `json:"port,omitempty"`
	Service string `json:"service,omitempty"`
}

// BatchScanRequest represents bulk scan payload
type BatchScanRequest struct {
	Assets []Asset `json:"assets"`
}

// CBOM represents the Cryptographic Bill of Materials [cite: 84]
// Compliant with CERT-In and Annexure-D specification
type CBOM struct {
	CBOMVersion   string            `json:"cbom_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Asset         Asset             `json:"asset"`
	CryptoInv     CryptographicInv  `json:"cryptographic_inventory"`
	QuantumAssess QuantumAssessment `json:"quantum_assessment"`
}

// Asset represents a network endpoint for cryptographic scanning
type Asset struct {
	FQDN     string `json:"fqdn"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
	Exposure string `json:"exposure"` // "Production", "Development", "Testing"
}

// CryptographicInv represents the cryptographic inventory (Annexure-D)
type CryptographicInv struct {
	TLSVersion  string          `json:"tls_version"`
	CipherSuite string          `json:"cipher_suite"`
	KeyLength   int             `json:"key_length"`
	KeyExchange string          `json:"key_exchange"`
	Signature   string          `json:"signature_algorithm"`
	Certificate CertificateInfo `json:"certificate,omitempty"`
}

// CertificateInfo holds certificate metadata
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	PublicKeyAlg string    `json:"public_key_algorithm"`
	KeySize      int       `json:"key_size"`
	SignatureAlg string    `json:"signature_algorithm"`
}

// QuantumAssessment represents the quantum vulnerability assessment (Annexure-B)
type QuantumAssessment struct {
	VulnerabilityScore float64          `json:"vulnerability_score"` // 0.0 - 10.0
	RiskLevel          string           `json:"risk_level"`          // LOW, MEDIUM, HIGH, CRITICAL
	Components         []ComponentScore `json:"components"`
	Recommendations    []string         `json:"recommendations"`
	IsQuantumSafe      bool             `json:"is_quantum_safe"`
}

// ComponentScore represents individual component vulnerability scores
type ComponentScore struct {
	Component string  `json:"component"` // "TLS_VERSION", "CIPHER_SUITE", "KEY_LENGTH"
	Score     float64 `json:"score"`     // 0.0 - 10.0
	RiskLevel string  `json:"risk_level"`
	Reason    string  `json:"reason,omitempty"`
}

// ScanResponse represents the API response for a single scan
type ScanResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	CBOM    *CBOM  `json:"cbom,omitempty"`
}

// BatchScanResponse represents the API response for batch scans
type BatchScanResponse struct {
	Status  string       `json:"status"`
	Total   int          `json:"total"`
	Scanned int          `json:"scanned"`
	Failed  int          `json:"failed"`
	Results []ScanResult `json:"results"`
}

// ScanResult represents a single scan result
type ScanResult struct {
	Asset   Asset  `json:"asset"`
	CBOM    *CBOM  `json:"cbom,omitempty"`
	Error   string `json:"error,omitempty"`
	Success bool   `json:"success"`
}

// HistoryFilter for querying scan history
type HistoryFilter struct {
	Domain    string
	StartDate time.Time
	EndDate   time.Time
	RiskLevel string
	Limit     int
	Offset    int
}

// MultiPortScanRequest represents request for scanning multiple ports
type MultiPortScanRequest struct {
	Domain     string `json:"domain"`
	Ports      []int  `json:"ports,omitempty"`
	Common     bool   `json:"use_common_ports,omitempty"` // If true, scan common ports
	MaxWorkers int    `json:"max_workers,omitempty"`
}

// MultiPortScanResponse represents response from multi-port scan
type MultiPortScanResponse struct {
	Status          string                `json:"status"`
	Domain          string                `json:"domain"`
	TotalPorts      int                   `json:"total_ports"`
	AccessiblePorts int                   `json:"accessible_ports"`
	Results         []MultiPortResultItem `json:"results"`
	ScanDurationMs  int64                 `json:"scan_duration_ms"`
}

// MultiPortResultItem represents a single port scan result
type MultiPortResultItem struct {
	Port          int       `json:"port"`
	Service       string    `json:"service"`
	Accessible    bool      `json:"accessible"`
	TLSVersion    string    `json:"tls_version,omitempty"`
	StatusMessage string    `json:"status_message,omitempty"`
	ScannedAt     time.Time `json:"scanned_at"`
}

// APIFinderRequest represents request for API discovery
type APIFinderRequest struct {
	Domain   string `json:"domain"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // "http" or "https"
	Timeout  int    `json:"timeout,omitempty"`  // seconds
}

// APIFinderResponse represents response from API discovery
type APIFinderResponse struct {
	Status         string            `json:"status"`
	Domain         string            `json:"domain"`
	Port           int               `json:"port"`
	Protocol       string            `json:"protocol"`
	TotalEndpoints int               `json:"total_endpoints"`
	ValidEndpoints int               `json:"valid_endpoints"`
	DiscoveredAPIs []APIEndpointInfo `json:"discovered_apis"`
	ScanDurationMs int64             `json:"scan_duration_ms"`
}

// APIEndpointInfo represents discovered API endpoint information
type APIEndpointInfo struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	StatusCode int               `json:"status_code"`
	Service    string            `json:"service"` // REST, GraphQL, SOAP, API-DOCS
	Headers    map[string]string `json:"headers"`
	IsValid    bool              `json:"is_valid"`
	FoundAt    time.Time         `json:"found_at"`
}

// DNSFinderRequest represents request for DNS enumeration
type DNSFinderRequest struct {
	Domain            string `json:"domain"`
	IncludeSubdomains bool   `json:"include_subdomains,omitempty"`
	ReverseIP         string `json:"reverse_ip,omitempty"` // For reverse DNS lookup
}

// DNSFinderResponse represents response from DNS enumeration
type DNSFinderResponse struct {
	Status               string          `json:"status"`
	Domain               string          `json:"domain"`
	TotalRecords         int             `json:"total_records"`
	ARecords             []DNSRecordInfo `json:"a_records,omitempty"`
	AAAARecords          []DNSRecordInfo `json:"aaaa_records,omitempty"`
	MXRecords            []DNSRecordInfo `json:"mx_records,omitempty"`
	NSRecords            []DNSRecordInfo `json:"ns_records,omitempty"`
	TXTRecords           []DNSRecordInfo `json:"txt_records,omitempty"`
	CNAMERecords         []DNSRecordInfo `json:"cname_records,omitempty"`
	SRVRecords           []DNSRecordInfo `json:"srv_records,omitempty"`
	DiscoveredSubdomains []DNSRecordInfo `json:"discovered_subdomains,omitempty"`
	ScanDurationMs       int64           `json:"scan_duration_ms"`
}

// DNSRecordInfo represents a single DNS record
type DNSRecordInfo struct {
	Type     string    `json:"type"`
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Priority int       `json:"priority,omitempty"`
	Weight   int       `json:"weight,omitempty"`
	Port     int       `json:"port,omitempty"`
	Target   string    `json:"target,omitempty"`
	FoundAt  time.Time `json:"found_at"`
}
