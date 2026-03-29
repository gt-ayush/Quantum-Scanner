package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"quantum-sentinel/internal/analyzer"
	"quantum-sentinel/internal/core"
	"quantum-sentinel/internal/scanner"
)

// Handler manages HTTP request handling for Quantum Sentinel API
type Handler struct {
	scannerService core.Scanner
	repository     core.Repository
	jwtMiddleware  *JWTMiddleware
}

// NewHandler creates a new HTTP handler
func NewHandler(scannerService core.Scanner, repository core.Repository, jwtMiddleware *JWTMiddleware) *Handler {
	return &Handler{
		scannerService: scannerService,
		repository:     repository,
		jwtMiddleware:  jwtMiddleware,
	}
}

// ScanHandler handles POST /api/v1/scan requests
// Performs a single TLS probe and returns a complete CBOM
// Requires Admin or Operator role
func (h *Handler) ScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req core.ScanRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Domain == "" {
		http.Error(w, "Domain field is required", http.StatusBadRequest)
		return
	}

	// Set defaults
	if req.Port == 0 {
		req.Port = 443
	}
	if req.Service == "" {
		req.Service = "HTTPS"
	}

	// Perform TLS probe
	state, err := scanner.ProbeTLS(req.Domain, req.Port)
	if err != nil {
		response := core.ScanResponse{
			Status:  "FAILED",
			Message: fmt.Sprintf("TLS probe failed: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Generate CBOM
	cbom, err := scanner.GenerateCBOM(req.Domain, req.Port, req.Service, state)
	if err != nil {
		response := core.ScanResponse{
			Status:  "FAILED",
			Message: fmt.Sprintf("CBOM generation failed: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Store in repository
	if h.repository != nil {
		err = h.repository.Save(r.Context(), cbom)
		if err != nil {
			log.Printf("Warning: Failed to store CBOM in database: %v", err)
			// Don't fail the request, just log the warning
		}
	}

	// Log audit trail
	userID := GetUserID(r)
	if userID == "" {
		userID = "anonymous"
	}

	// Return successful response
	response := core.ScanResponse{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("Scan completed for %s:%d", req.Domain, req.Port),
		CBOM:    cbom,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// BatchScanHandler handles POST /api/v1/batch-scan requests
// Performs TLS probes on multiple assets using worker pool pattern
// Requires Admin or Operator role
func (h *Handler) BatchScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req core.BatchScanRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if len(req.Assets) == 0 {
		http.Error(w, "Assets array cannot be empty", http.StatusBadRequest)
		return
	}

	if len(req.Assets) > 1000 {
		http.Error(w, "Maximum 1000 assets per batch scan", http.StatusBadRequest)
		return
	}

	// Configure worker pool (recommended 10-50 workers for network I/O)
	maxWorkers := 20
	if maxWorkersParam := r.URL.Query().Get("maxWorkers"); maxWorkersParam != "" {
		if parsed, err := strconv.Atoi(maxWorkersParam); err == nil && parsed > 0 && parsed <= 100 {
			maxWorkers = parsed
		}
	}

	// Convert assets to discovery tasks
	tasks := make([]scanner.DiscoveryTask, len(req.Assets))
	for i, asset := range req.Assets {
		if asset.Port == 0 {
			asset.Port = 443
		}
		if asset.Service == "" {
			asset.Service = "HTTPS"
		}
		tasks[i] = scanner.DiscoveryTask{
			Domain:  asset.FQDN,
			Port:    asset.Port,
			Service: asset.Service,
		}
	}

	// Execute batch scan with worker pool
	batchResult := scanner.RunBatchScanWithPorts(r.Context(), tasks, maxWorkers)

	// Store CBOMs in repository
	if h.repository != nil {
		for _, cbom := range batchResult.CBOMs {
			err := h.repository.Save(r.Context(), &cbom)
			if err != nil {
				log.Printf("Warning: Failed to store CBOM for %s: %v", cbom.Asset.FQDN, err)
			}
		}
	}

	// Prepare response
	scanResults := make([]core.ScanResult, len(batchResult.Results))
	for i, result := range batchResult.Results {
		scanResults[i] = core.ScanResult{
			Asset:   core.Asset{FQDN: result.Domain},
			Success: result.Error == nil,
		}
		if result.Error != nil {
			scanResults[i].Error = result.Error.Error()
		}
	}

	response := core.BatchScanResponse{
		Status:  "SUCCESS",
		Total:   batchResult.Total,
		Scanned: batchResult.Total,
		Failed:  batchResult.Failed,
		Results: scanResults,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetCBOMHandler handles GET /api/v1/cbom/:domain requests
// Retrieves the latest CBOM for a specific domain
// Requires Checker, Operator, or Auditor role
func (h *Handler) GetCBOMHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain parameter is required", http.StatusBadRequest)
		return
	}

	if h.repository == nil {
		http.Error(w, "Repository service is not available", http.StatusServiceUnavailable)
		return
	}

	// Query repository for latest scan
	cboms, err := h.repository.GetHistory(r.Context(), domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve CBOM: %v", err), http.StatusInternalServerError)
		return
	}

	if len(cboms) == 0 {
		response := core.ScanResponse{
			Status:  "NOT_FOUND",
			Message: fmt.Sprintf("No scan history found for domain: %s", domain),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Return latest CBOM
	response := core.ScanResponse{
		Status:  "SUCCESS",
		Message: fmt.Sprintf("CBOM retrieved for %s", domain),
		CBOM:    &cboms[0], // Latest scan
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetScanHistoryHandler handles GET /api/v1/history/:domain requests
// Retrieves scan history for a domain with optional filtering
// Requires Auditor role
func (h *Handler) GetScanHistoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain parameter is required", http.StatusBadRequest)
		return
	}

	if h.repository == nil {
		http.Error(w, "Repository service is not available", http.StatusServiceUnavailable)
		return
	}

	// Parse optional filter parameters
	limit := 100
	if limitParam := r.URL.Query().Get("limit"); limitParam != "" {
		if parsed, err := strconv.Atoi(limitParam); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	filter := core.HistoryFilter{
		Domain: domain,
		Limit:  limit,
	}

	// Parse risk level filter if provided
	if riskLevel := r.URL.Query().Get("riskLevel"); riskLevel != "" {
		filter.RiskLevel = riskLevel
	}

	// Query repository
	cboms, err := h.repository.GetHistory(r.Context(), domain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve history: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"status":  "SUCCESS",
		"domain":  domain,
		"count":   len(cboms),
		"history": cboms,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetRiskSummaryHandler handles GET /api/v1/risk-summary requests
// Returns summary of vulnerability scores across all scans
// Requires Checker or Auditor role
func (h *Handler) GetRiskSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// This would aggregate data from repository
	// For now, return a sample structure
	summary := map[string]interface{}{
		"status":    "SUCCESS",
		"timestamp": time.Now(),
		"risk_summary": map[string]interface{}{
			"critical": 5,
			"high":     12,
			"medium":   34,
			"low":      98,
		},
		"total_scans": 149,
		"critical_domains": []string{
			"legacy-api.example.com",
			"old-payment-gateway.example.com",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(summary)
}

// AnalyzeCipherSuiteHandler handles GET /api/v1/analyze/cipher-suite requests
// Provides detailed quantum vulnerability analysis of a cipher suite
// Requires Checker role
func (h *Handler) AnalyzeCipherSuiteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cipherName := r.URL.Query().Get("cipher")
	if cipherName == "" {
		http.Error(w, "Cipher parameter is required", http.StatusBadRequest)
		return
	}

	// Analyze cipher suite (mock implementation)
	score, riskLevel, reason := analyzer.ScoreCipherSuite(0, cipherName)

	analysis := map[string]interface{}{
		"status":     "SUCCESS",
		"cipher":     cipherName,
		"score":      score,
		"risk_level": riskLevel,
		"reason":     reason,
		"recommendations": []string{
			"Use PQC-based cipher suites (MLKEM+ECC)",
			"Implement hybrid classical-quantum key exchange",
			"Monitor NIST PQC standardization updates",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(analysis)
}

// HealthCheckHandler handles GET /health requests
// Simple health check endpoint
func (h *Handler) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":    "UP",
		"timestamp": time.Now(),
		"service":   "Quantum Sentinel AI",
		"version":   "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}

// MultiPortScanHandler handles POST /api/v1/multiport-scan requests
// Performs TLS probes on multiple ports on a single domain
// Requires Admin or Operator role
func (h *Handler) MultiPortScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req core.MultiPortScanRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Domain == "" {
		http.Error(w, "Domain field is required", http.StatusBadRequest)
		return
	}

	if !req.Common && (req.Ports == nil || len(req.Ports) == 0) {
		http.Error(w, "Either use_common_ports=true or provide ports array", http.StatusBadRequest)
		return
	}

	// Set defaults
	maxWorkers := 10
	if req.MaxWorkers > 0 && req.MaxWorkers <= 100 {
		maxWorkers = req.MaxWorkers
	}

	startTime := time.Now()
	var result scanner.MultiPortScanResult

	// Perform scan
	if req.Common {
		result = scanner.ScanCommonPorts(r.Context(), req.Domain, maxWorkers)
	} else {
		result = scanner.ScanCustomPorts(r.Context(), req.Domain, req.Ports, maxWorkers)
	}

	// Convert results
	portResults := make([]core.MultiPortResultItem, 0, len(result.Results))
	for _, scanResult := range result.Results {
		portResults = append(portResults, core.MultiPortResultItem{
			Port:          scanResult.Port,
			Service:       scanResult.Service,
			Accessible:    scanResult.Accessible,
			TLSVersion:    scanResult.TLSVersion,
			StatusMessage: scanResult.Error,
			ScannedAt:     scanResult.ScannedAt,
		})
	}

	// Prepare response
	response := core.MultiPortScanResponse{
		Status:          "SUCCESS",
		Domain:          result.Domain,
		TotalPorts:      result.TotalPorts,
		AccessiblePorts: result.AccessiblePorts,
		Results:         portResults,
		ScanDurationMs:  time.Since(startTime).Milliseconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// APIFinderHandler handles POST /api/v1/api-finder requests
// Discovers API endpoints on a domain
// Requires Admin or Operator role
func (h *Handler) APIFinderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req core.APIFinderRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Domain == "" {
		http.Error(w, "Domain field is required", http.StatusBadRequest)
		return
	}

	// Set defaults
	if req.Port == 0 {
		req.Port = 443
	}
	if req.Protocol == "" {
		req.Protocol = "https"
	}
	if req.Timeout == 0 {
		req.Timeout = 5
	}

	startTime := time.Now()

	// Perform API discovery
	result := scanner.FindAPIs(r.Context(), req.Domain, req.Port, req.Protocol, req.Timeout)

	// Convert results
	apiList := make([]core.APIEndpointInfo, 0, len(result.ValidEndpointsList))
	for _, endpoint := range result.ValidEndpointsList {
		apiList = append(apiList, core.APIEndpointInfo{
			URL:        endpoint.URL,
			Method:     endpoint.Method,
			StatusCode: endpoint.StatusCode,
			Service:    endpoint.Service,
			Headers:    endpoint.Headers,
			IsValid:    endpoint.IsValid,
			FoundAt:    endpoint.FoundAt,
		})
	}

	// Prepare response
	response := core.APIFinderResponse{
		Status:         "SUCCESS",
		Domain:         result.Domain,
		Port:           result.Port,
		Protocol:       result.Protocol,
		TotalEndpoints: result.TotalEndpoints,
		ValidEndpoints: result.ValidEndpoints,
		DiscoveredAPIs: apiList,
		ScanDurationMs: time.Since(startTime).Milliseconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// DNSFinderHandler handles POST /api/v1/dns-finder requests
// Enumerates DNS records for a domain
// Requires Admin or Operator role
func (h *Handler) DNSFinderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req core.DNSFinderRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	err = json.Unmarshal(body, &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON payload: %v", err), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Domain == "" && req.ReverseIP == "" {
		http.Error(w, "Either domain or reverse_ip parameter is required", http.StatusBadRequest)
		return
	}

	startTime := time.Now()

	response := core.DNSFinderResponse{
		Status:       "SUCCESS",
		Domain:       req.Domain,
		TotalRecords: 0,
	}

	// Perform DNS enumeration
	if req.ReverseIP != "" {
		// Reverse DNS lookup
		hostnames := scanner.ReverseIPLookup(r.Context(), req.ReverseIP)
		response.Domain = req.ReverseIP
		response.TotalRecords = len(hostnames)
		// Add hostnames as TXT record-like results
		for _, hostname := range hostnames {
			response.TXTRecords = append(response.TXTRecords, core.DNSRecordInfo{
				Type:    "PTR",
				Name:    req.ReverseIP,
				Value:   hostname,
				FoundAt: time.Now(),
			})
		}
	} else {
		// Full DNS enumeration
		result := scanner.FindDNSRecords(r.Context(), req.Domain)

		// Convert A records
		for _, record := range result.ARecords {
			response.ARecords = append(response.ARecords, core.DNSRecordInfo{
				Type:    record.Type,
				Name:    record.Name,
				Value:   record.Value,
				FoundAt: record.FoundAt,
			})
		}

		// Convert AAAA records
		for _, record := range result.AAAARecords {
			response.AAAARecords = append(response.AAAARecords, core.DNSRecordInfo{
				Type:    record.Type,
				Name:    record.Name,
				Value:   record.Value,
				FoundAt: record.FoundAt,
			})
		}

		// Convert MX records
		for _, record := range result.MXRecords {
			response.MXRecords = append(response.MXRecords, core.DNSRecordInfo{
				Type:     record.Type,
				Name:     record.Name,
				Value:    record.Value,
				Priority: record.Priority,
				FoundAt:  record.FoundAt,
			})
		}

		// Convert NS records
		for _, record := range result.NSRecords {
			response.NSRecords = append(response.NSRecords, core.DNSRecordInfo{
				Type:    record.Type,
				Name:    record.Name,
				Value:   record.Value,
				FoundAt: record.FoundAt,
			})
		}

		// Convert TXT records
		for _, record := range result.TXTRecords {
			response.TXTRecords = append(response.TXTRecords, core.DNSRecordInfo{
				Type:    record.Type,
				Name:    record.Name,
				Value:   record.Value,
				FoundAt: record.FoundAt,
			})
		}

		// Convert CNAME records
		for _, record := range result.CNAMERecords {
			response.CNAMERecords = append(response.CNAMERecords, core.DNSRecordInfo{
				Type:    record.Type,
				Name:    record.Name,
				Value:   record.Value,
				FoundAt: record.FoundAt,
			})
		}

		// Add subdomain enumeration if requested
		if req.IncludeSubdomains {
			subdomains := scanner.EnumerateSubdomains(r.Context(), req.Domain)
			for _, record := range subdomains {
				response.DiscoveredSubdomains = append(response.DiscoveredSubdomains, core.DNSRecordInfo{
					Type:    record.Type,
					Name:    record.Name,
					Value:   record.Value,
					FoundAt: record.FoundAt,
				})
			}
		}

		response.TotalRecords = len(result.AllRecords)
	}

	response.ScanDurationMs = time.Since(startTime).Milliseconds()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// RegisterRoutes registers all API endpoints with the provided handler
func RegisterRoutes(mux *http.ServeMux, handler *Handler, jwt *JWTMiddleware) {
	// Health check (no authentication required)
	mux.HandleFunc("GET /health", handler.HealthCheckHandler)

	// Scan endpoints (require Admin or Operator role)
	scanMiddleware := jwt.RequireRole(RoleAdmin, RoleOperator)
	mux.HandleFunc("POST /api/v1/scan", scanMiddleware(handler.ScanHandler))
	mux.HandleFunc("POST /api/v1/batch-scan", scanMiddleware(handler.BatchScanHandler))

	// Multi-port scan endpoints (require Admin or Operator role)
	mux.HandleFunc("POST /api/v1/multiport-scan", scanMiddleware(handler.MultiPortScanHandler))

	// API discovery endpoints (require Admin or Operator role)
	mux.HandleFunc("POST /api/v1/api-finder", scanMiddleware(handler.APIFinderHandler))

	// DNS enumeration endpoints (require Admin or Operator role)
	mux.HandleFunc("POST /api/v1/dns-finder", scanMiddleware(handler.DNSFinderHandler))

	// CBOM endpoints (require Checker, Operator, or Auditor role)
	cbomMiddleware := jwt.RequireRole(RoleChecker, RoleOperator, RoleAuditor)
	mux.HandleFunc("GET /api/v1/cbom", cbomMiddleware(handler.GetCBOMHandler))

	// History endpoints (require Auditor role)
	historyMiddleware := jwt.RequireRole(RoleAuditor)
	mux.HandleFunc("GET /api/v1/history", historyMiddleware(handler.GetScanHistoryHandler))

	// Summary endpoints (require Checker or Auditor role)
	summaryMiddleware := jwt.RequireRole(RoleChecker, RoleAuditor)
	mux.HandleFunc("GET /api/v1/risk-summary", summaryMiddleware(handler.GetRiskSummaryHandler))

	// Analysis endpoints (require Checker role)
	analyzeMiddleware := jwt.RequireRole(RoleChecker, RoleAuditor)
	mux.HandleFunc("GET /api/v1/analyze/cipher-suite", analyzeMiddleware(handler.AnalyzeCipherSuiteHandler))
}
