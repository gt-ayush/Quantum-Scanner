package scanner

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// ProbeTLS initiates a TLS handshake and extracts connection state for cryptographic analysis.
// This is a passive discovery mechanism that does not establish persistent connections.
// Parameters:
//   - domain: The target FQDN (e.g., "example.com")
//   - port: The target port (typically 443 for HTTPS)
//
// Returns the TLS ConnectionState for security analysis or an error if the probe fails.
func ProbeTLS(domain string, port int) (*tls.ConnectionState, error) {
	address := fmt.Sprintf("%s:%d", domain, port)

	// Configure TLS client to accept various versions for passive discovery
	config := &tls.Config{
		InsecureSkipVerify: true, // Required to analyze invalid/expired certs passively
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         domain, // For SNI
	}

	// Create a connection with timeout
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed for %s:%d: %w", domain, port, err)
	}
	defer conn.Close()

	// Extract the connection state
	state := conn.ConnectionState()
	return &state, nil
}

// ExtractCertificateInfo extracts cryptographic details from the peer certificate chain
func ExtractCertificateInfo(state *tls.ConnectionState) (map[string]interface{}, error) {
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates available")
	}

	cert := state.PeerCertificates[0]

	certInfo := map[string]interface{}{
		"subject":             cert.Subject.String(),
		"issuer":              cert.Issuer.String(),
		"not_before":          cert.NotBefore,
		"not_after":           cert.NotAfter,
		"public_key_alg":      cert.PublicKeyAlgorithm.String(),
		"signature_alg":       cert.SignatureAlgorithm.String(),
		"key_size":            getKeySize(cert),
		"serial_number":       cert.SerialNumber.String(),
		"dns_names":           cert.DNSNames,
		"extended_key_usages": cert.ExtKeyUsage,
	}

	return certInfo, nil
}

// GetKeySize extracts key size in bits from certificate public key
func getKeySize(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 253 // Ed25519 equivalent strength
	default:
		return 0
	}
}

// TLSVersionString converts TLS version constant to human-readable string
func TLSVersionString(version uint16) string {
	switch version {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// CipherSuiteName returns the human-readable name of a cipher suite
func CipherSuiteName(id uint16) string {
	for _, suite := range tls.CipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}

	// Check insecure suites
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}

	return fmt.Sprintf("Unknown (0x%04x)", id)
}

// ValidateExposure checks if certificate is within validity period
func ValidateExposure(state *tls.ConnectionState) (bool, error) {
	if len(state.PeerCertificates) == 0 {
		return false, fmt.Errorf("no certificates available")
	}

	cert := state.PeerCertificates[0]
	now := time.Now()

	if now.Before(cert.NotBefore) {
		return false, fmt.Errorf("certificate not yet valid (notBefore: %v)", cert.NotBefore)
	}

	if now.After(cert.NotAfter) {
		return false, fmt.Errorf("certificate expired (notAfter: %v)", cert.NotAfter)
	}

	return true, nil
}
