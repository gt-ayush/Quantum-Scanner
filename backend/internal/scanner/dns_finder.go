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
// Parameters:
//   - ctx: Context for cancellation
//   - domain: The target FQDN
//
// Returns all discovered DNS records
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

	// Channels for parallel DNS queries
	recordsChan := make(chan DNSRecord, 100)
	var wg sync.WaitGroup

	// Define DNS query types
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

	// Execute DNS queries concurrently
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

	// Collect results in separate goroutine
	go func() {
		wg.Wait()
		close(recordsChan)
	}()

	// Aggregate all records
	for record := range recordsChan {
		result.AllRecords = append(result.AllRecords, record)
	}

	result.EndTime = time.Now()
	return result
}

// queryARecords retrieves A records (IPv4)
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
			log.Printf("Found A record: %s -> %s", domain, ip.String())
		}
	}

	return records
}

// queryAAAARecords retrieves AAAA records (IPv6)
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
			log.Printf("Found AAAA record: %s -> %s", domain, ip.String())
		}
	}

	return records
}

// queryMXRecords retrieves Mail Exchange records
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
		log.Printf("Found MX record: %s (Priority: %d)", mx.Host, mx.Pref)
	}

	return records
}

// queryNSRecords retrieves Nameserver records
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
		log.Printf("Found NS record: %s", ns.Host)
	}

	return records
}

// queryTXTRecords retrieves Text records
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
		log.Printf("Found TXT record: %s", txt)
	}

	return records
}

// queryCNAMERecords retrieves CNAME records
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
		log.Printf("Found CNAME record: %s -> %s", domain, cname)
	}

	return records
}

// querySRVRecords retrieves Service records (common services)
func querySRVRecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)

	// Common SRV records to query
	services := []string{
		"_http._tcp",
		"_https._tcp",
		"_ldap._tcp",
		"_kerberos._tcp",
		"_kerberos._udp",
		"_sip._tcp",
		"_sip._udp",
		"_xmpp-server._tcp",
		"_xmpp-client._tcp",
		"_smtp._tcp",
		"_pop3._tcp",
		"_imap._tcp",
	}

	for _, service := range services {
		srvRecords, _, err := net.LookupSRV("", "", fmt.Sprintf("%s.%s", service, domain))
		if err != nil {
			continue
		}

		for _, srv := range srvRecords {
			records = append(records, DNSRecord{
				Type:     "SRV",
				Name:     fmt.Sprintf("%s.%s", service, domain),
				Value:    srv.Target.String(),
				Priority: int(srv.Priority),
				Weight:   int(srv.Weight),
				Port:     int(srv.Port),
				FoundAt:  time.Now(),
			})
			log.Printf("Found SRV record: %s.%s -> %s:%d (Priority: %d, Weight: %d)",
				service, domain, srv.Target, srv.Port, srv.Priority, srv.Weight)
		}
	}

	return records
}

// querySOARecords retrieves Start of Authority records
func querySOARecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	// Note: Go's net library doesn't have direct SOA lookup, but we can try NS lookup as alternative
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
		log.Printf("Found SOA record: %s", nsRecords[0].Host)
	}

	return records
}

// queryCAARecords retrieves Certification Authority Authorization records
func queryCAARecords(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)
	// Note: Go's net library doesn't have direct CAA lookup
	// This is a placeholder - would need custom DNS library for full support
	log.Printf("CAA record lookup for %s requires external DNS library", domain)
	return records
}

// ReverseIPLookup performs reverse DNS lookup on an IP address
// Parameters:
//   - ctx: Context for cancellation
//   - ip: The IP address to reverse lookup
//
// Returns the hostname(s) associated with the IP
func ReverseIPLookup(ctx context.Context, ip string) []string {
	hostnames := make([]string, 0)
	names, err := net.LookupAddr(ip)
	if err != nil {
		log.Printf("Failed to reverse lookup IP %s: %v", ip, err)
		return hostnames
	}

	hostnames = append(hostnames, names...)
	log.Printf("Reverse lookup for %s: %v", ip, names)

	return hostnames
}

// EnumerateSubdomains attempts to discover common subdomains
// Parameters:
//   - ctx: Context for cancellation
//   - domain: The base domain
//
// Returns discovered subdomains
func EnumerateSubdomains(ctx context.Context, domain string) []DNSRecord {
	records := make([]DNSRecord, 0)

	commonSubdomains := []string{
		"www",
		"mail",
		"ftp",
		"localhost",
		"webmail",
		"smtp",
		"pop",
		"pop3",
		"imap",
		"ns1",
		"ns2",
		"dns",
		"vpn",
		"api",
		"admin",
		"test",
		"staging",
		"dev",
		"development",
		"prod",
		"production",
		"app",
		"apps",
		"mail1",
		"web",
		"service",
		"server",
		"members",
		"forum",
		"blog",
		"billing",
		"support",
		"cdn",
		"images",
		"assets",
		"media",
		"static",
		"docs",
		"documentation",
		"help",
		"download",
		"downloads",
		"repository",
		"repo",
		"git",
		"jenkins",
		"sonar",
		"monitoring",
		"grafana",
		"prometheus",
		"kibana",
		"elastic",
		"influx",
		"graphite",
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
					log.Printf("Found subdomain: %s -> %s", subdomain, ip.String())
				}
			}
		}
	}

	return records
}
