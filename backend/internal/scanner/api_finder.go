package scanner

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// APIEndpoint represents a discovered API endpoint
type APIEndpoint struct {
	URL        string
	Method     string
	Path       string
	StatusCode int
	Headers    map[string]string
	IsValid    bool
	FoundAt    time.Time
	Service    string // e.g., "REST", "GraphQL", "SOAP"
}

// APIFinderResult contains discovered API endpoints for a domain
type APIFinderResult struct {
	Domain             string
	Port               int
	Protocol           string
	TotalEndpoints     int
	ValidEndpoints     int
	ValidEndpointsList []APIEndpoint
	StartTime          time.Time
	EndTime            time.Time
}

// CommonAPIPaths defines common API endpoint patterns
func GetCommonAPIPatterns() []string {
	return []string{
		// RESTful API endpoints
		"/api/v1",
		"/api/v2",
		"/api/v3",
		"/api/v4",
		"/api/version",
		"/api/info",
		"/api/status",
		"/api/health",
		"/api/metrics",
		"/api/config",
		"/api/test",

		// Authentication endpoints
		"/api/auth",
		"/api/login",
		"/api/logout",
		"/api/register",
		"/api/token",
		"/oauth",
		"/oauth2",
		"/authorize",

		// Common REST resources
		"/api/users",
		"/api/accounts",
		"/api/products",
		"/api/orders",
		"/api/services",
		"/api/resources",
		"/api/items",

		// GraphQL endpoints
		"/graphql",
		"/api/graphql",
		"/graphql/query",
		"/graphql/execute",

		// SOAP endpoints
		"/soap",
		"/webservice",
		"/ws",
		"/service",
		"/Services.asmx",

		// Documentation endpoints
		"/api/docs",
		"/api/documentation",
		"/swagger",
		"/swagger-ui",
		"/swagger.json",
		"/swagger.yaml",
		"/openapi",
		"/openapi.json",
		"/api-docs",
		"/apidocs",
		"/doc",
		"/docs",
		"/redoc",

		// Admin/Management endpoints
		"/admin",
		"/admin/api",
		"/management",
		"/control",

		// Data endpoints
		"/data",
		"/api/data",
		"/download",
		"/export",

		// Search endpoints
		"/search",
		"/api/search",
		"/query",
		"/find",

		// Alternative API versions
		"/v1",
		"/v2",
		"/v3",
		"/v4",
		"/beta",

		// Internal/Debug endpoints
		"/debug",
		"/internals",
		"/internal",
		"/_debug",
		"/.debug",

		// Other common patterns
		"/rest",
		"/restapi",
		"/backend",
		"/server",
		"/application",
		"/app",
		"/api",
	}
}

// FindAPIs discovers API endpoints on a specified domain and port
// Parameters:
//   - ctx: Context for cancellation
//   - domain: The target FQDN
//   - port: The target port
//   - protocol: "http" or "https"
//   - timeout: Request timeout in seconds
//
// Returns discovered API endpoints
func FindAPIs(ctx context.Context, domain string, port int, protocol string, timeout int) APIFinderResult {
	if timeout <= 0 {
		timeout = 5
	}

	result := APIFinderResult{
		Domain:             domain,
		Port:               port,
		Protocol:           protocol,
		ValidEndpointsList: make([]APIEndpoint, 0),
		StartTime:          time.Now(),
	}

	patterns := GetCommonAPIPatterns()
	jobsChan := make(chan string, len(patterns))
	resultsChan := make(chan APIEndpoint, len(patterns))

	var wg sync.WaitGroup
	maxWorkers := 5

	// Start workers
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go apiFindWorker(ctx, &wg, domain, port, protocol, timeout, jobsChan, resultsChan)
	}

	// Send jobs
	for _, pattern := range patterns {
		jobsChan <- pattern
	}
	close(jobsChan)

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Aggregate results
	for apiEndpoint := range resultsChan {
		result.TotalEndpoints++
		if apiEndpoint.IsValid {
			result.ValidEndpoints++
			result.ValidEndpointsList = append(result.ValidEndpointsList, apiEndpoint)
			log.Printf("Found valid API endpoint: %s [%d]", apiEndpoint.URL, apiEndpoint.StatusCode)
		}
	}

	result.EndTime = time.Now()
	return result
}

// apiFindWorker probes individual API endpoints
func apiFindWorker(ctx context.Context, wg *sync.WaitGroup, domain string, port int, protocol string, timeout int, jobs <-chan string, results chan<- APIEndpoint) {
	defer wg.Done()

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for pattern := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			endpoint := probeAPIEndpoint(ctx, client, domain, port, protocol, pattern)
			select {
			case <-ctx.Done():
				return
			case results <- endpoint:
			}
		}
	}
}

// probeAPIEndpoint tests a single API endpoint
func probeAPIEndpoint(ctx context.Context, client *http.Client, domain string, port int, protocol string, path string) APIEndpoint {
	endpoint := APIEndpoint{
		Path:    path,
		Service: "REST",
		FoundAt: time.Now(),
		Headers: make(map[string]string),
		IsValid: false,
	}

	// Build URL
	baseURL := fmt.Sprintf("%s://%s:%d%s", protocol, domain, port, path)
	endpoint.URL = baseURL

	// Detect service type from path
	if strings.Contains(path, "graphql") {
		endpoint.Service = "GraphQL"
	} else if strings.Contains(path, "soap") || strings.Contains(path, "asmx") {
		endpoint.Service = "SOAP"
	}

	// Try GET request first
	resp, err := client.Get(baseURL)
	if err != nil {
		// Try OPTIONS method
		req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, baseURL, nil)
		resp, err = client.Do(req)
		if err != nil {
			return endpoint
		}
	}
	defer resp.Body.Close()

	endpoint.StatusCode = resp.StatusCode
	endpoint.Method = http.MethodGet

	// Capture response headers
	for key, values := range resp.Header {
		if len(values) > 0 {
			endpoint.Headers[key] = values[0]
		}
	}

	// Determine if endpoint is valid
	endpoint.IsValid = isValidAPIResponse(resp, path)

	// Try to read response body (limited)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	bodyStr := strings.ToLower(string(body))

	// Additional validation
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		if strings.Contains(resp.Header.Get("Content-Type"), "json") ||
			strings.Contains(resp.Header.Get("Content-Type"), "xml") ||
			strings.Contains(bodyStr, "error") || strings.Contains(bodyStr, "message") {
			endpoint.IsValid = true
		}
	}

	// Check for API documentation indicators
	if strings.Contains(path, "swagger") || strings.Contains(path, "openapi") ||
		strings.Contains(resp.Header.Get("Content-Type"), "json") &&
			(strings.Contains(bodyStr, "swagger") || strings.Contains(bodyStr, "openapi")) {
		endpoint.Service = "API-DOCS"
		endpoint.IsValid = true
	}

	return endpoint
}

// isValidAPIResponse determines if a response indicates a valid API
func isValidAPIResponse(resp *http.Response, path string) bool {
	// Status codes that indicate API presence
	validStatusCodes := map[int]bool{
		200: true, 201: true, 202: true, 204: true,
		400: true, 401: true, 403: true, 404: true,
		405: true, 406: true, 500: true, 501: true,
		503: true,
	}

	// Check for API indicators
	contentType := resp.Header.Get("Content-Type")
	hasAPIContentType := strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/xml") ||
		strings.Contains(contentType, "application/ld+json") ||
		strings.Contains(contentType, "text/xml")

	// GraphQL always returns 200 even for errors
	if strings.Contains(path, "graphql") {
		return resp.StatusCode == 200
	}

	// Valid if status code is known API response code
	if validStatusCodes[resp.StatusCode] {
		return hasAPIContentType || resp.StatusCode >= 400
	}

	return false
}

// FindAPIsByURL discovers APIs by directly probing a URL
// Parameters:
//   - ctx: Context for cancellation
//   - targetURL: The full URL to probe
//   - timeout: Request timeout in seconds
//
// Returns API endpoint information
func FindAPIsByURL(ctx context.Context, targetURL string, timeout int) APIEndpoint {
	if timeout <= 0 {
		timeout = 5
	}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return APIEndpoint{
			URL:     targetURL,
			IsValid: false,
		}
	}

	endpoint := probeAPIEndpoint(ctx, client, parsedURL.Hostname(), getPort(parsedURL), parsedURL.Scheme, parsedURL.Path)
	endpoint.URL = targetURL

	return endpoint
}

// getPort extracts port from parsed URL or returns default
func getPort(u *url.URL) int {
	if u.Port() != "" {
		var port int
		fmt.Sscanf(u.Port(), "%d", &port)
		return port
	}

	if u.Scheme == "https" {
		return 443
	}
	return 80
}
