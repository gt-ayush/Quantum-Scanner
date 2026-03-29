package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"quantum-sentinel/internal/api"
	"quantum-sentinel/internal/repository"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Config holds application configuration
type Config struct {
	Host            string
	Port            int
	DBConnectionURL string
	JWTSecret       string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

func main() {
	// Parse command-line flags
	config := parseFlags()

	// Initialize database connection
	dbPool, err := initDatabase(config.DBConnectionURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer dbPool.Close()

	// Initialize repository
	repo := repository.NewPostgresRepo(dbPool)

	// Initialize database schema
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := repo.InitSchema(ctx); err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}

	// Initialize JWT middleware
	jwtMiddleware := api.NewJWTMiddleware(config.JWTSecret)

	// Initialize handler
	handler := api.NewHandler(nil, repo, jwtMiddleware)

	// Setup HTTP server
	mux := http.NewServeMux()

	// Apply global middleware
	globalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		mux.ServeHTTP(w, r)
	})

	// Register all API routes
	api.RegisterRoutes(mux, handler, jwtMiddleware)

	server := &http.Server{
		Addr:           fmt.Sprintf("%s:%d", config.Host, config.Port),
		Handler:        globalHandler,
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting Quantum Sentinel API server on %s:%d", config.Host, config.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down server...")

	// Give running requests a chance to complete
	ctx, cancel = context.WithTimeout(context.Background(), config.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}

	log.Println("Server stopped")
}

// parseFlags parses command-line flags and returns configuration
func parseFlags() Config {
	host := flag.String("host", "0.0.0.0", "Server host")
	port := flag.Int("port", 8080, "Server port")
	dbURL := flag.String("db", "postgresql://postgres:password@localhost:5432/quantum_sentinel", "PostgreSQL connection URL")
	jwtSecret := flag.String("jwt-secret", "your-secret-key-change-this", "JWT secret key")
	flag.Parse()

	// Allow environment variable overrides
	if envURL := os.Getenv("DB_CONNECTION_URL"); envURL != "" {
		*dbURL = envURL
	}

	if envSecret := os.Getenv("JWT_SECRET"); envSecret != "" {
		*jwtSecret = envSecret
	}

	return Config{
		Host:            *host,
		Port:            *port,
		DBConnectionURL: *dbURL,
		JWTSecret:       *jwtSecret,
		ReadTimeout:     15 * time.Second,
		WriteTimeout:    15 * time.Second,
		ShutdownTimeout: 30 * time.Second,
	}
}

// initDatabase initializes the PostgreSQL connection pool
func initDatabase(connectionURL string) (*pgxpool.Pool, error) {
	// Create connection pool config
	config, err := pgxpool.ParseConfig(connectionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure the pool
	config.MaxConns = 50
	config.MinConns = 10
	config.MaxConnLifetime = 5 * time.Minute
	config.MaxConnIdleTime = 2 * time.Minute
	config.HealthCheckPeriod = 30 * time.Second

	// Create the connection pool
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Println("Successfully connected to PostgreSQL database")
	return pool, nil
}
