package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"quantum-sentinel/internal/core"
)

// CommonPorts defines well-known ports for security scanning
type CommonPorts struct {
	Port    int
	Service string
	Name    string
}

// GetCommonPorts returns a list of commonly scanned ports
func GetCommonPorts() []CommonPorts {
	return []CommonPorts{
		{443, "HTTPS", "HTTPS"},
		{8443, "HTTPS-ALT", "HTTPS Alternative"},
		{80, "HTTP", "HTTP"},
		{8080, "HTTP-ALT", "HTTP Alternative"},
		{8000, "HTTP-ALT2", "HTTP Alternative 2"},
		{8888, "HTTP-ALT3", "HTTP Alternative 3"},
		{22, "SSH", "SSH"},
		{21, "FTP", "FTP"},
		{25, "SMTP", "SMTP"},
		{110, "POP3", "POP3"},
		{143, "IMAP", "IMAP"},
		{465, "SMTPS", "SMTPS"},
		{587, "SMTP-TLS", "SMTP with TLS"},
		{993, "IMAPS", "IMAPS"},
		{995, "POP3S", "POP3S"},
		{3306, "MySQL", "MySQL"},
		{5432, "PostgreSQL", "PostgreSQL"},
		{5984, "CouchDB", "CouchDB"},
		{6379, "Redis", "Redis"},
		{27017, "MongoDB", "MongoDB"},
		{3000, "Node", "Node.js"},
		{5000, "Flask", "Flask/Python"},
		{8000, "Django", "Django"},
		{9000, "Apache", "Apache/PHP"},
		{9200, "Elasticsearch", "Elasticsearch"},
		{9300, "Elasticsearch-node", "Elasticsearch Node"},
		{27017, "NoSQL", "NoSQL Database"},
		{6443, "K8S", "Kubernetes API"},
		{10250, "Kubelet", "Kubelet API"},
	}
}

// PortScanTask represents a single port scan task
type PortScanTask struct {
	Domain  string
	Port    int
	Service string
}

// PortScanResult represents the result of scanning a single port
type PortScanResult struct {
	Domain     string
	Port       int
	Service    string
	State      interface{}
	Accessible bool
	Error      string
	TLSVersion string
	ScannedAt  time.Time
}

// MultiPortScanResult aggregates results from multi-port scanning
type MultiPortScanResult struct {
	Domain          string
	TotalPorts      int
	AccessiblePorts int
	Results         []PortScanResult
	CBOMs           []core.CBOM
	StartTime       time.Time
	EndTime         time.Time
}

// ScanCommonPorts scans all common ports on a domain
// Parameters:
//   - ctx: Context for cancellation
//   - domain: The target FQDN
//   - maxWorkers: Number of concurrent workers
//
// Returns aggregated multi-port scan results
func ScanCommonPorts(ctx context.Context, domain string, maxWorkers int) MultiPortScanResult {
	commonPorts := GetCommonPorts()
	tasks := make([]PortScanTask, 0, len(commonPorts))

	for _, cp := range commonPorts {
		tasks = append(tasks, PortScanTask{
			Domain:  domain,
			Port:    cp.Port,
			Service: cp.Service,
		})
	}

	return ScanMultiplePorts(ctx, tasks, maxWorkers)
}

// ScanCustomPorts scans specified custom ports on a domain
// Parameters:
//   - ctx: Context for cancellation
//   - domain: The target FQDN
//   - ports: List of ports to scan
//   - maxWorkers: Number of concurrent workers
//
// Returns aggregated multi-port scan results
func ScanCustomPorts(ctx context.Context, domain string, ports []int, maxWorkers int) MultiPortScanResult {
	tasks := make([]PortScanTask, 0, len(ports))

	for _, port := range ports {
		tasks = append(tasks, PortScanTask{
			Domain:  domain,
			Port:    port,
			Service: fmt.Sprintf("SERVICE_%d", port),
		})
	}

	return ScanMultiplePorts(ctx, tasks, maxWorkers)
}

// ScanMultiplePorts performs TLS probes on multiple ports concurrently
// Parameters:
//   - ctx: Context for cancellation
//   - tasks: List of PortScanTasks
//   - maxWorkers: Number of concurrent workers
//
// Returns complete multi-port scan results with CBOM generation for accessible ports
func ScanMultiplePorts(ctx context.Context, tasks []PortScanTask, maxWorkers int) MultiPortScanResult {
	if maxWorkers <= 0 {
		maxWorkers = 10
	}

	result := MultiPortScanResult{
		TotalPorts: len(tasks),
		Results:    make([]PortScanResult, 0),
		CBOMs:      make([]core.CBOM, 0),
		StartTime:  time.Now(),
	}

	if len(tasks) == 0 {
		result.EndTime = time.Now()
		return result
	}

	// Use first task's domain
	result.Domain = tasks[0].Domain

	// Channels for coordinating work
	jobsChan := make(chan PortScanTask, len(tasks))
	resultsChan := make(chan PortScanResult, len(tasks))

	var wg sync.WaitGroup

	// Start worker pool
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go portScanWorker(ctx, &wg, jobsChan, resultsChan)
	}

	// Send jobs to workers
	for _, task := range tasks {
		jobsChan <- task
	}
	close(jobsChan)

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for scanResult := range resultsChan {
		result.Results = append(result.Results, scanResult)

		if scanResult.Accessible {
			result.AccessiblePorts++

			// Generate CBOM for accessible TLS ports
			if scanResult.TLSVersion != "" {
				// TODO: Generate CBOM if TLS state is available
				log.Printf("Port %d on %s is accessible with %s", scanResult.Port, result.Domain, scanResult.TLSVersion)
			}
		}

		if scanResult.Error == "" {
			log.Printf("Port %d/%s on %s: Open", scanResult.Port, scanResult.Service, result.Domain)
		} else {
			log.Printf("Port %d/%s on %s: Closed/Filtered", scanResult.Port, scanResult.Service, result.Domain)
		}
	}

	result.EndTime = time.Now()
	return result
}

// portScanWorker performs individual port scans
func portScanWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan PortScanTask, results chan<- PortScanResult) {
	defer wg.Done()

	for task := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			result := scanPort(task)
			select {
			case <-ctx.Done():
				return
			case results <- result:
			}
		}
	}
}

// scanPort performs a single port scan with TLS detection
func scanPort(task PortScanTask) PortScanResult {
	result := PortScanResult{
		Domain:     task.Domain,
		Port:       task.Port,
		Service:    task.Service,
		ScannedAt:  time.Now(),
		Accessible: false,
	}

	// Try TLS probe first (for HTTPS-like services)
	state, err := ProbeTLS(task.Domain, task.Port)
	if err == nil {
		result.Accessible = true
		result.TLSVersion = TLSVersionString(state.Version)
		result.State = state
		return result
	}

	// If TLS fails, attempt basic TCP connection (for HTTP-like services)
	if isPortOpen(task.Domain, task.Port) {
		result.Accessible = true
		result.Error = "TLS failed but TCP connection successful"
		return result
	}

	result.Error = fmt.Sprintf("Port unreachable: %v", err)
	return result
}

// isPortOpen checks if a TCP port is open on a domain
func isPortOpen(domain string, port int) bool {
	address := fmt.Sprintf("%s:%d", domain, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}
