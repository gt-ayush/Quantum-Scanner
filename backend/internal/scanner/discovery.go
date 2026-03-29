package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"

	"quantum-sentinel/internal/analyzer"
	"quantum-sentinel/internal/core"
)

// ScanResult holds the outcome of a single endpoint probe
type ScanResult struct {
	Domain string
	State  *tls.ConnectionState
	Error  error
}

// DiscoveryTask represents a single TLS probe task with port information
type DiscoveryTask struct {
	Domain  string
	Port    int
	Service string
}

// BatchScanResult aggregates results from a batch scan operation
type BatchScanResult struct {
	Total      int
	Successful int
	Failed     int
	Results    []ScanResult
	CBOMs      []core.CBOM
}

// RunBatchScan executes TLS probes across multiple domains/ports concurrently using a worker pool.
// This implements the worker pool pattern for handling 1,000+ assets efficiently.
// Parameters:
//   - ctx: Context for cancellation
//   - domains: List of FQDNs to scan
//   - maxWorkers: Number of concurrent workers (recommended 10-50 for network I/O)
//   - ports: Optional list of ports to probe (defaults to 443)
//
// Returns aggregated scan results with error handling.
func RunBatchScan(ctx context.Context, domains []string, maxWorkers int) []ScanResult {
	if maxWorkers <= 0 {
		maxWorkers = 10
	}

	var results []ScanResult

	// Channels for coordinating work
	jobs := make(chan string, len(domains))
	resultsChan := make(chan ScanResult, len(domains))

	var wg sync.WaitGroup

	// 1. Start the worker pool
	for w := 1; w <= maxWorkers; w++ {
		wg.Add(1)
		go worker(ctx, &wg, jobs, resultsChan)
	}

	// 2. Send jobs (domains) to the workers
	for _, domain := range domains {
		jobs <- domain
	}
	close(jobs) // Close channel to signal no more jobs

	// 3. Wait for all workers to finish in a separate goroutine
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// 4. Collect results
	for res := range resultsChan {
		results = append(results, res)
		if res.Error != nil {
			log.Printf("Failed to scan %s: %v", res.Domain, res.Error)
		} else {
			log.Printf("Successfully scanned %s (TLS %s)", res.Domain, TLSVersionString(res.State.Version))
		}
	}

	return results
}

// RunBatchScanWithPorts executes TLS probes on specified ports with full CBOM generation
// Parameters:
//   - ctx: Context for cancellation
//   - tasks: List of DiscoveryTasks with domain, port, and service info
//   - maxWorkers: Number of concurrent workers
//
// Returns CBOMs with quantum assessment data
func RunBatchScanWithPorts(ctx context.Context, tasks []DiscoveryTask, maxWorkers int) BatchScanResult {
	if maxWorkers <= 0 {
		maxWorkers = 10
	}

	var cboms []core.CBOM
	var mu sync.Mutex

	// Channels for coordinating work
	jobs := make(chan DiscoveryTask, len(tasks))
	resultsChan := make(chan ScanResult, len(tasks))

	var wg sync.WaitGroup

	// 1. Start the worker pool
	for w := 1; w <= maxWorkers; w++ {
		wg.Add(1)
		go workerWithCBOM(ctx, &wg, jobs, resultsChan, &cboms, &mu)
	}

	// 2. Send jobs to the workers
	for _, task := range tasks {
		jobs <- task
	}
	close(jobs)

	// 3. Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// 4. Collect results
	results := make([]ScanResult, 0)
	for res := range resultsChan {
		results = append(results, res)
	}

	// Calculate aggregates
	successful := 0
	failed := len(results)
	for _, r := range results {
		if r.Error == nil {
			successful++
			failed--
		}
	}

	return BatchScanResult{
		Total:      len(tasks),
		Successful: successful,
		Failed:     failed,
		Results:    results,
		CBOMs:      cboms,
	}
}

// worker processes domains from the jobs channel until it is closed.
// Probes port 443 (HTTPS) by default for banking infrastructure scans.
func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan string, results chan<- ScanResult) {
	defer wg.Done()
	for domain := range jobs {
		// Check if context was cancelled (e.g., user aborted the scan)
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Standard banking infrastructure ports
		defaultPort := 443

		state, err := ProbeTLS(domain, defaultPort)
		results <- ScanResult{Domain: domain, State: state, Error: err}
	}
}

// workerWithCBOM processes discovery tasks and generates complete CBOMs with quantum assessments.
func workerWithCBOM(ctx context.Context, wg *sync.WaitGroup, jobs <-chan DiscoveryTask,
	results chan<- ScanResult, cboms *[]core.CBOM, mu *sync.Mutex) {
	defer wg.Done()
	for task := range jobs {
		// Check if context was cancelled
		select {
		case <-ctx.Done():
			results <- ScanResult{
				Domain: task.Domain,
				Error:  fmt.Errorf("context cancelled"),
			}
			return
		default:
		}

		// Probe TLS endpoint
		state, err := ProbeTLS(task.Domain, task.Port)
		if err != nil {
			results <- ScanResult{
				Domain: task.Domain,
				State:  nil,
				Error:  fmt.Errorf("TLS probe failed: %w", err),
			}
			continue
		}

		// Generate CBOM
		cbom, err := GenerateCBOM(task.Domain, task.Port, task.Service, state)
		if err != nil {
			results <- ScanResult{
				Domain: task.Domain,
				State:  state,
				Error:  fmt.Errorf("CBOM generation failed: %w", err),
			}
			continue
		}

		// Thread-safe append to cboms
		mu.Lock()
		*cboms = append(*cboms, *cbom)
		mu.Unlock()

		results <- ScanResult{
			Domain: task.Domain,
			State:  state,
			Error:  nil,
		}
	}
}

// GenerateCBOM creates a complete Cryptographic Bill of Materials from TLS connection state
// Implements Annexure-B (Quantum Vulnerability Scoring) and Annexure-D (CBOM format)
func GenerateCBOM(domain string, port int, service string, state *tls.ConnectionState) (*core.CBOM, error) {
	if state == nil {
		return nil, fmt.Errorf("invalid TLS connection state")
	}

	// Extract certificate information
	certInfo, err := ExtractCertificateInfo(state)
	if err != nil {
		log.Printf("Warning: Could not extract certificate info for %s: %v", domain, err)
	}

	// Perform quantum vulnerability assessment
	score, riskLevel, components := analyzer.AnalyzeQuantumVulnerability(state, certInfo)
	recommendations := generateRecommendations(score, riskLevel, state, certInfo)

	asset := core.Asset{
		FQDN:     domain,
		Port:     port,
		Service:  service,
		Exposure: "Production", // Default; would be overridden by configuration
	}

	cryptoInv := core.CryptographicInv{
		TLSVersion:  TLSVersionString(state.Version),
		CipherSuite: CipherSuiteName(state.CipherSuite),
		KeyLength:   extractKeyLength(state, certInfo),
		KeyExchange: extractKeyExchange(state),
		Signature:   extractSignatureAlg(certInfo),
	}

	quantumAssess := core.QuantumAssessment{
		VulnerabilityScore: score,
		RiskLevel:          riskLevel,
		Components:         components,
		Recommendations:    recommendations,
		IsQuantumSafe:      score <= 2.0, // Scores <= 2.0 are considered quantum-safe
	}

	cbom := &core.CBOM{
		CBOMVersion:   core.CBOMVersion,
		GeneratedAt:   time.Now().UTC(),
		Asset:         asset,
		CryptoInv:     cryptoInv,
		QuantumAssess: quantumAssess,
	}

	return cbom, nil
}

// extractKeyLength extracts key length from certificate or TLS state
func extractKeyLength(state *tls.ConnectionState, certInfo map[string]interface{}) int {
	if certInfo != nil {
		if keySize, ok := certInfo["key_size"].(int); ok && keySize > 0 {
			return keySize
		}
	}
	// Default values based on cipher suite
	return 256
}

// extractKeyExchange extracts key exchange algorithm name
func extractKeyExchange(state *tls.ConnectionState) string {
	// Common key exchange patterns
	cipherName := CipherSuiteName(state.CipherSuite)

	if contains(cipherName, "ECDHE") {
		return "ECDHE"
	} else if contains(cipherName, "DHE") {
		return "DHE"
	} else if contains(cipherName, "RSA") {
		return "RSA"
	}
	return "Unknown"
}

// extractSignatureAlg extracts signature algorithm from certificate
func extractSignatureAlg(certInfo map[string]interface{}) string {
	if certInfo != nil {
		if sigAlg, ok := certInfo["signature_alg"].(string); ok {
			return sigAlg
		}
	}
	return "Unknown"
}

// generateRecommendations returns quantum-safe recommendations based on vulnerability
func generateRecommendations(score float64, riskLevel string, state *tls.ConnectionState, certInfo map[string]interface{}) []string {
	recommendations := []string{}

	// TLS Version recommendations
	switch state.Version {
	case tls.VersionTLS13:
		// Good, but recommend PQC cipher suites
		recommendations = append(
			recommendations,
			"Upgrade to TLS 1.3 with post-quantum cryptography (PQC) cipher suites (e.g., MLKEM768+ECC)",
		)
	case tls.VersionTLS12:
		recommendations = append(
			recommendations,
			"Upgrade from TLS 1.2 to TLS 1.3 or higher with PQC support",
		)
	case tls.VersionTLS11, tls.VersionTLS10:
		recommendations = append(
			recommendations,
			"CRITICAL: Immediately disable TLS 1.0/1.1. Upgrade to TLS 1.3 with PQC cipher suites",
		)
	}

	// Cipher suite recommendations
	cipherName := CipherSuiteName(state.CipherSuite)
	if contains(cipherName, "RSA") {
		recommendations = append(
			recommendations,
			"Replace RSA key exchange with ECDHE or PQC-based key exchange (e.g., MLKEM)",
		)
	}

	// Quantum-specific recommendations
	if score > 5.0 {
		recommendations = append(
			recommendations,
			"Begin quantum cryptography transition planning. Implement hybrid PQC schemes",
		)
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Current configuration is acceptable. Continue monitoring for PQC updates")
	}

	return recommendations
}

// contains is a simple string contains helper
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
