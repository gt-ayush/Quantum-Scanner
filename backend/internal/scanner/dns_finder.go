package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// DNSRecord represents a DNS record
type DNSRecord struct {
	Type     string
	Name     string
	Value    string
	TTL      int
	Priority int
	Weight   int
	Port     int
	Target   string
	FoundAt  time.Time
}

// DNSFinderResult contains all discovered DNS records for a domain
type DNSFinderResult struct {
	Domain       string
	ARecords     []DNSRecord
	AAAARecords  []DNSRecord
	MXRecords    []DNSRecord
	NSRecords    []DNSRecord
	TXTRecords   []DNSRecord
	CNAMERecords []DNSRecord
	SRVRecords   []DNSRecord
	SOARecords   []DNSRecord
	CAARecords   []DNSRecord
	AllRecords   []DNSRecord
	StartTime    time.Time
	EndTime      time.Time
}

// FindDNSRecords performs comprehensive DNS enumeration for a domain
func FindDNSRecords(ctx context.Context, domain string) DNSFinderResult {
	result := DNSFinderResult{
		Domain:       domain,
		ARecords:     make([]DNSRecord, 0),
		AAAARecords:  make([]DNSRecord, 0),
		MXRecords:    make([]DNSRecord, 0),
		NSRecords:    make([]DNSRecord, 0),
		TXTRecords:   make([]DNSRecord, 0),
		CNAMERecords: make([]DNSRecord, 0),
		SRVRecords:   make([]DNSRecord, 0),
		SOARecords:   make([]DNSRecord, 0),
		CAARecords:   make([]DNSRecord, 0),
		AllRecords:   make([]DNSRecord, 0),
		StartTime:    time.Now(),
	}

	recordsChan := make(chan DNSRecord, 100)
	var wg sync.WaitGroup

	// Execute DNS queries concurrently
	queryFuncs := []struct {
		name      string
		queryFn   func(context.Context, string) []DNSRecord
		destSlice *[]DNSRecord
	}{
		{"A", queryARecords, &result.ARecords},
		{"AAAA", queryAAAARecords, &result.AAAARecords},
		{"MX", queryMXRecords, &result.MXRecords},
		{"NS", queryNSRecords, &result.NSRecords},
		{"TXT", queryTXTRecords, &result.TXTRecords},
		{"CNAME", queryCNAMERecords, &result.CNAMERecords},
		{"SRV", querySRVRecords, &result.SRVRecords},
		{"SOA", querySOARecords, &result.SOARecords},
		{"CAA", queryCAARecords, &result.CAARecords},
	}

	for _, qf := range queryFuncs {
		wg.Add(1)
		go func(queryType string, queryFunc func(context.Context, string) []DNSRecord, destSlice *[]DNSRecord) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
				records := queryFunc(ctx, domain)
				for _, record := range records {
					recordsChan <- record
				}
				*destSlice = records
			}
		}(qf.name, qf.queryFn, qf.destSlice)
	}

	go func() {
		wg.Wait()
		close(recordsChan)
	}()

	for record := range recordsChan {
		result.AllRecords = append(result.AllRecords, record)
	}

	result.EndTime = time.Now()
	return result
}

func queryARecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Printf("Failed to resolve A records for %s: %v", domain, err)
		return records
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			records = append(records, DNSRecord{
				Type:    "A",
				Name:    domain,
				Value:   ip.String(),
				FoundAt: time.Now(),
			})
		}
	}
	return records
}

func queryAAAARecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Printf("Failed to resolve AAAA records for %s: %v", domain, err)
		return records
	}

	for _, ip := range ips {
		if ip.To16() != nil && ip.To4() == nil {
			records = append(records, DNSRecord{
				Type:    "AAAA",
				Name:    domain,
				Value:   ip.String(),
				FoundAt: time.Now(),
			})
		}
	}
	return records
}

func queryMXRecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		log.Printf("Failed to resolve MX records for %s: %v", domain, err)
		return records
	}

	for _, mx := range mxRecords {
		records = append(records, DNSRecord{
			Type:     "MX",
			Name:     domain,
			Value:    mx.Host,
			Priority: int(mx.Pref),
			FoundAt:  time.Now(),
		})
	}
	return records
}

func queryNSRecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		log.Printf("Failed to resolve NS records for %s: %v", domain, err)
		return records
	}

	for _, ns := range nsRecords {
		records = append(records, DNSRecord{
			Type:    "NS",
			Name:    domain,
			Value:   ns.Host,
			FoundAt: time.Now(),
		})
	}
	return records
}

func queryTXTRecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		log.Printf("Failed to resolve TXT records for %s: %v", domain, err)
		return records
	}

	for _, txt := range txtRecords {
		records = append(records, DNSRecord{
			Type:    "TXT",
			Name:    domain,
			Value:   txt,
			FoundAt: time.Now(),
		})
	}
	return records
}

func queryCNAMERecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		log.Printf("Failed to resolve CNAME record for %s: %v", domain, err)
		return records
	}

	if cname != domain {
		records = append(records, DNSRecord{
			Type:    "CNAME",
			Name:    domain,
			Value:   cname,
			FoundAt: time.Now(),
		})
	}
	return records
}

func querySRVRecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)

	// SRV record lookup is simplified - requires external DNS library for full support
	// Placeholder for future implementation with miekg/dns library

	return records
}

func querySOARecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	nsRecords, err := net.LookupNS(domain)
	if err != nil {
		log.Printf("Failed to resolve SOA records for %s: %v", domain, err)
		return records
	}

	if len(nsRecords) > 0 {
		records = append(records, DNSRecord{
			Type:    "SOA",
			Name:    domain,
			Value:   nsRecords[0].Host,
			FoundAt: time.Now(),
		})
	}
	return records
}

func queryCAARecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	log.Printf("CAA record lookup for %s requires external DNS library", domain)
	return records
}

// ReverseIPLookup performs reverse DNS lookup on an IP address
func ReverseIPLookup(ctx context.Context, ip string) []string {
	hostnames := make([]string, 0)
	names, err := net.LookupAddr(ip)
	if err != nil {
		log.Printf("Failed to reverse lookup IP %s: %v", ip, err)
		return hostnames
	}

	hostnames = append(hostnames, names...)
	return hostnames
}

// EnumerateSubdomains attempts to discover common subdomains
func EnumerateSubdomains(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)

	commonSubdomains := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp",
		"pop", "pop3", "imap", "ns1", "ns2", "dns", "vpn",
		"api", "admin", "test", "staging", "dev", "development",
		"prod", "production", "app", "apps", "mail1", "web",
		"service", "server", "members", "forum", "blog", "billing",
		"support", "cdn", "images", "assets", "media", "static",
		"docs", "documentation", "help", "download", "downloads",
		"repository", "repo", "git", "jenkins", "sonar", "monitoring",
		"grafana", "prometheus", "kibana", "elastic", "influx", "graphite",
	}

	for _, sub := range commonSubdomains {
		select {
		case <-ctx.Done():
			return records
		default:
			subdomain := fmt.Sprintf("%s.%s", sub, domain)
			ips, err := net.LookupIP(subdomain)

			if err == nil && len(ips) > 0 {
				for _, ip := range ips {
					records = append(records, DNSRecord{
						Type:    "SUBDOMAIN",
						Name:    subdomain,
						Value:   ip.String(),
						FoundAt: time.Now(),
					})
				}
			}
		}
	}

	return records
}
