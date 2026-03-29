package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Define context keys to avoid collisions
type contextKey string

const (
	userRoleKey  contextKey = "userRole"
	userIDKey    contextKey = "userID"
	userEmailKey contextKey = "userEmail"
	tokenKey     contextKey = "token"
)

// Allowed roles in the system (Annexure-A: RBAC)
const (
	RoleAdmin    = "Admin"
	RoleChecker  = "Checker"
	RoleOperator = "Operator"
	RoleAuditor  = "Auditor"
)

// CustomClaims represents JWT token claims for Quantum Sentinel
type CustomClaims struct {
	UserID   string   `json:"user_id"`
	Email    string   `json:"email"`
	Role     string   `json:"role"`
	Roles    []string `json:"roles"`
	Org      string   `json:"org"`
	IssuedAt int64    `json:"iat"`
	jwt.RegisteredClaims
}

// JWTMiddleware validates JWT tokens and extracts claims
type JWTMiddleware struct {
	secretKey string
	publicKey string // For RS256 verification
}

// NewJWTMiddleware creates a new JWT middleware instance
func NewJWTMiddleware(secretKey string) *JWTMiddleware {
	return &JWTMiddleware{
		secretKey: secretKey,
	}
}

// RequireAuth validates the JWT token and extracts the role.
// This middleware checks for a valid Bearer token in the Authorization header.
func (m *JWTMiddleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized: Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Extract Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Unauthorized: Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		// Parse and validate token
		claims := &CustomClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(m.secretKey), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, fmt.Sprintf("Unauthorized: Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		// Pass claims to context
		ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
		ctx = context.WithValue(ctx, userEmailKey, claims.Email)
		ctx = context.WithValue(ctx, userRoleKey, claims.Role)
		ctx = context.WithValue(ctx, tokenKey, tokenString)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// RequireRole wraps a handler and ensures the user has one of the permitted roles.
// This implements RBAC (Role-Based Access Control) per Annexure-A.
func (m *JWTMiddleware) RequireRole(permittedRoles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return m.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := r.Context().Value(userRoleKey).(string)
			if !ok {
				http.Error(w, "Forbidden: Role not found in token", http.StatusForbidden)
				return
			}

			// Check if user has one of the permitted roles
			isPermitted := false
			for _, role := range permittedRoles {
				if userRole == role {
					isPermitted = true
					break
				}
			}

			if !isPermitted {
				http.Error(w, fmt.Sprintf("Forbidden: User role '%s' not in permitted roles %v", userRole, permittedRoles), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuth validates JWT token if present, but doesn't fail if absent
func (m *JWTMiddleware) OptionalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		// If no auth header, continue without token
		if authHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			// Invalid format, but continue
			next.ServeHTTP(w, r)
			return
		}

		tokenString := parts[1]

		// Try to parse token
		claims := &CustomClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(m.secretKey), nil
		})

		// If valid, add to context
		if err == nil && token.Valid {
			ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
			ctx = context.WithValue(ctx, userEmailKey, claims.Email)
			ctx = context.WithValue(ctx, userRoleKey, claims.Role)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	}
}

// GetUserID retrieves the user ID from request context
func GetUserID(r *http.Request) string {
	if val := r.Context().Value(userIDKey); val != nil {
		return val.(string)
	}
	return ""
}

// GetUserRole retrieves the user role from request context
func GetUserRole(r *http.Request) string {
	if val := r.Context().Value(userRoleKey); val != nil {
		return val.(string)
	}
	return ""
}

// GetUserEmail retrieves the user email from request context
func GetUserEmail(r *http.Request) string {
	if val := r.Context().Value(userEmailKey); val != nil {
		return val.(string)
	}
	return ""
}

// LoggingMiddleware logs HTTP requests for audit purposes
func LoggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := GetUserID(r)
		userRole := GetUserRole(r)

		fmt.Printf("[AUDIT] %s %s - User: %s (Role: %s)\n", r.Method, r.RequestURI, userID, userRole)

		next.ServeHTTP(w, r)
	}
}

// CORSMiddleware handles CORS headers
func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	}
}
