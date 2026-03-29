package analyzer

import (
	"crypto/tls"
	"fmt"

	"quantum-sentinel/internal/core"
)

const (
	// Scoring thresholds (Annexure-B)
	ScoreLowThreshold      = 2.5
	ScoreMediumThreshold   = 5.0
	ScoreHighThreshold     = 7.5
	ScoreCriticalThreshold = 10.0
)

// ScoreTLSVersion applies the Annexure-B scoring logic for TLS version vulnerability
// Returns (score: 0.0-10.0, riskLevel: LOW|MEDIUM|HIGH|CRITICAL)
func ScoreTLSVersion(version uint16) (float64, string) {
	switch version {
	case tls.VersionTLS13:
		return 1.0, core.RiskLevelsLow // TLS 1.3 is quantum-resistant friendly
	case tls.VersionTLS12:
		return 5.0, core.RiskLevelsMedium // Upgrade to TLS 1.3 with PQC suites [cite: 59]
	case tls.VersionTLS11:
		return 9.0, core.RiskLevelsCritical // TLS 1.1 is obsolete and weak
	case tls.VersionTLS10:
		return 9.5, core.RiskLevelsCritical // TLS 1.0 is critically weak [cite: 59]
	default:
		return 10.0, core.RiskLevelsCritical // Unknown/Legacy versions
	}
}

// ScoreCipherSuite evaluates the quantum vulnerability of a cipher suite
// Focuses on key exchange and symmetric cipher strength
// Returns (score: 0.0-10.0, riskLevel, reason)
func ScoreCipherSuite(suiteID uint16, cipherName string) (float64, string, string) {
	// Post-Quantum Cryptography (PQC) cipher suites - SAFE
	if contains(cipherName, "MLKEM") || contains(cipherName, "KYBER") {
		return 1.0, core.RiskLevelsLow, "PQC-based key exchange (quantum-resistant)"
	}

	// ECDH-based suites - Medium quantum risk (requires harvesting of encrypted data)
	if contains(cipherName, "ECDHE") {
		if contains(cipherName, "AES_256") {
			return 4.0, core.RiskLevelsMedium, "ECDHE with AES-256 provides medium quantum resistance"
		}
		if contains(cipherName, "AES_128") {
			return 5.5, core.RiskLevelsMedium, "ECDHE with AES-128 vulnerable to quantum key recovery"
		}
		return 5.0, core.RiskLevelsMedium, "ECDHE requires harvest-now-decrypt-later attack mitigation"
	}

	// DHE-based suites - Medium-high quantum risk
	if contains(cipherName, "DHE") {
		return 6.0, core.RiskLevelsHigh, "DHE is vulnerable to quantum algorithms (Shor's algorithm)"
	}

	// RSA key exchange - CRITICAL for quantum
	if contains(cipherName, "RSA") {
		return 9.5, core.RiskLevelsCritical, "RSA key exchange is completely broken against quantum computers"
	}

	// Chacha20 with ECDH
	if contains(cipherName, "CHACHA20") && contains(cipherName, "ECDH") {
		return 4.5, core.RiskLevelsMedium, "ChaCha20-ECDH provides good symmetric encryption but quantum-vulnerable key exchange"
	}

	// AEAD suites without PQC
	if contains(cipherName, "AEAD") || contains(cipherName, "GCM") {
		if contains(cipherName, "RSA") {
			return 9.0, core.RiskLevelsCritical, "RSA key exchange negates symmetric cipher strength"
		}
		return 5.0, core.RiskLevelsMedium, "Strong symmetric cipher but key exchange needs quantum evaluation"
	}

	// Default scoring for unknown suites
	return 6.0, core.RiskLevelsHigh, "Unknown cipher suite - cannot verify quantum resistance"
}

// ScoreKeyLength evaluates the cryptographic key length against quantum threats
// Returns (score: 0.0-10.0, riskLevel, reason)
func ScoreKeyLength(keyLength int, algorithm string) (float64, string, string) {
	// RSA key size evaluation (Post-quantum threat)
	if contains(algorithm, "RSA") {
		if keyLength >= 4096 {
			return 4.0, core.RiskLevelsMedium, "RSA-4096 provides temporary quantum resistance but not long-term safe"
		}
		if keyLength >= 2048 {
			return 7.0, core.RiskLevelsHigh, "RSA-2048 is vulnerable to near-term quantum attacks"
		}
		if keyLength < 2048 {
			return 9.5, core.RiskLevelsCritical, fmt.Sprintf("RSA-%d is critically weak (harvest-now threat)", keyLength)
		}
	}

	// ECC key size evaluation
	if contains(algorithm, "ECDSA") || contains(algorithm, "ECDH") {
		if keyLength >= 384 {
			return 3.5, core.RiskLevelsMedium, "P-384/P-521 provides moderate quantum resistance"
		}
		if keyLength >= 256 {
			return 5.0, core.RiskLevelsMedium, "P-256/P-384 vulnerable to Grover's algorithm in long-term"
		}
		if keyLength < 256 {
			return 8.0, core.RiskLevelsHigh, fmt.Sprintf("ECC-%d is quantum-vulnerable (Shor's algorithm)", keyLength)
		}
	}

	// AES symmetric key evaluation
	if contains(algorithm, "AES") {
		if keyLength >= 256 {
			return 2.0, core.RiskLevelsLow, "AES-256 is quantum-resistant (Grover's requires 2^128 operations)"
		}
		if keyLength >= 128 {
			return 4.0, core.RiskLevelsMedium, "AES-128 vulnerable to Grover's algorithm in post-quantum era"
		}
	}

	// Default evaluation
	if keyLength >= 256 {
		return 3.0, core.RiskLevelsMedium, "Key length provides moderate quantum resistance"
	}
	if keyLength >= 128 {
		return 6.0, core.RiskLevelsHigh, "Key length insufficient for post-quantum threats"
	}

	return 9.0, core.RiskLevelsCritical, fmt.Sprintf("Key length %d bits is critically weak", keyLength)
}

// AnalyzeQuantumVulnerability performs comprehensive quantum vulnerability assessment
// Implements Annexure-B scoring methodology
// Returns (score, riskLevel, componentScores)
func AnalyzeQuantumVulnerability(state *tls.ConnectionState, certInfo map[string]interface{}) (float64, string, []core.ComponentScore) {
	components := []core.ComponentScore{}

	// 1. Score TLS Version
	tlsScore, tlsRiskLevel := ScoreTLSVersion(state.Version)
	components = append(components, core.ComponentScore{
		Component: "TLS_VERSION",
		Score:     tlsScore,
		RiskLevel: tlsRiskLevel,
		Reason:    fmt.Sprintf("TLS version %x", state.Version),
	})

	// 2. Score Cipher Suite
	cipherName := getCipherSuiteName(state.CipherSuite)
	cipherScore, cipherRiskLevel, cipherReason := ScoreCipherSuite(state.CipherSuite, cipherName)
	components = append(components, core.ComponentScore{
		Component: "CIPHER_SUITE",
		Score:     cipherScore,
		RiskLevel: cipherRiskLevel,
		Reason:    cipherReason,
	})

	// 3. Score Key Exchange Algorithm
	keyExchangeName := extractKeyExchangeName(cipherName)
	keyExScore := scoreKeyExchange(keyExchangeName)
	components = append(components, core.ComponentScore{
		Component: "KEY_EXCHANGE",
		Score:     keyExScore,
		RiskLevel: getRiskLevel(keyExScore),
		Reason:    fmt.Sprintf("Key exchange: %s", keyExchangeName),
	})

	// 4. Score Key Length (from certificate)
	keyLength := extractKeyLengthFromCert(certInfo)
	pubKeyAlg := extractPublicKeyAlgorithm(certInfo)
	keyLenScore, keyLenRiskLevel, keyLenReason := ScoreKeyLength(keyLength, pubKeyAlg)
	components = append(components, core.ComponentScore{
		Component: "KEY_LENGTH",
		Score:     keyLenScore,
		RiskLevel: keyLenRiskLevel,
		Reason:    keyLenReason,
	})

	// 5. Calculate aggregate score (maximum of component scores)
	maxScore := tlsScore
	if cipherScore > maxScore {
		maxScore = cipherScore
	}
	if keyExScore > maxScore {
		maxScore = keyExScore
	}
	if keyLenScore > maxScore {
		maxScore = keyLenScore
	}

	// Round to nearest 0.5
	maxScore = roundToHalf(maxScore)

	riskLevel := getRiskLevel(maxScore)

	return maxScore, riskLevel, components
}

// AnalyzeConnection generates the final assessment (legacy function name compatibility)
func AnalyzeConnection(state *tls.ConnectionState) (float64, string) {
	// In a full implementation, you would also score the Cipher Suite (e.g., ECDH P-256 = 8.0) [cite: 59]
	// The asset-level score is the max(component scores)
	score, level := ScoreTLSVersion(state.Version)
	return score, level
}

// Helper functions

func getRiskLevel(score float64) string {
	if score <= ScoreLowThreshold {
		return core.RiskLevelsLow
	}
	if score <= ScoreMediumThreshold {
		return core.RiskLevelsMedium
	}
	if score <= ScoreHighThreshold {
		return core.RiskLevelsHigh
	}
	return core.RiskLevelsCritical
}

func roundToHalf(value float64) float64 {
	return float64(int(value*2)) / 2
}

func getCipherSuiteName(id uint16) string {
	for _, suite := range tls.CipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	for _, suite := range tls.InsecureCipherSuites() {
		if suite.ID == id {
			return suite.Name
		}
	}
	return fmt.Sprintf("UNKNOWN_0x%04x", id)
}

func extractKeyExchangeName(cipherName string) string {
	if contains(cipherName, "ECDHE") {
		return "ECDHE"
	}
	if contains(cipherName, "DHE") {
		return "DHE"
	}
	if contains(cipherName, "MLKEM") || contains(cipherName, "KYBER") {
		return "PQC"
	}
	if contains(cipherName, "RSA") {
		return "RSA"
	}
	return "UNKNOWN"
}

func scoreKeyExchange(keyExName string) float64 {
	switch keyExName {
	case "PQC":
		return 1.0 // Post-quantum safe
	case "ECDHE":
		return 5.0 // Medium quantum risk
	case "DHE":
		return 6.5 // Higher quantum risk
	case "RSA":
		return 9.5 // Critical quantum risk
	default:
		return 6.0 // Unknown
	}
}

func extractKeyLengthFromCert(certInfo map[string]interface{}) int {
	if certInfo == nil {
		return 0
	}
	if keySize, ok := certInfo["key_size"].(int); ok {
		return keySize
	}
	return 0
}

func extractPublicKeyAlgorithm(certInfo map[string]interface{}) string {
	if certInfo == nil {
		return "UNKNOWN"
	}
	if pubKeyAlg, ok := certInfo["public_key_alg"].(string); ok {
		return pubKeyAlg
	}
	return "UNKNOWN"
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
