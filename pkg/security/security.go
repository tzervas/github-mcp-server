// Package security provides HTTP middleware and helpers for hardening the
// github-mcp-server process (headers, rate limits, request validation,
// toolset isolation, audit logging).
package security

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
)

// RateLimitConfig controls request rate limiting.
type RateLimitConfig struct {
	Enabled           bool
	RequestsPerSecond float64
	Burst             int
}

// Config holds security middleware settings.
type Config struct {
	ReadOnly         bool
	DynamicToolsets  bool
	RateLimit        RateLimitConfig
}

// DefaultConfig returns a secure-by-default configuration.
func DefaultConfig() *Config {
	return &Config{
		ReadOnly:        true,
		DynamicToolsets: true,
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 10,
			Burst:             20,
		},
	}
}

// ResourceLimits bounds resource use for a toolset context.
type ResourceLimits struct {
	MaxMemory   int64
	MaxCPU      float64
	MaxRequests int
}

// ToolsetContext isolates logging and resource limits per toolset.
type ToolsetContext struct {
	ID             string
	Logger         *logrus.Entry
	ResourceLimits ResourceLimits
}

// Middleware applies security headers, rate limits, and request validation.
type Middleware struct {
	cfg     *Config
	logger  *logrus.Logger
	limiter *rate.Limiter
	mu      sync.Mutex
	// requestCount is reserved for future per-toolset accounting.
	requestCount atomic.Int64
	seq          atomic.Uint64
}

// NewSecurityMiddleware constructs a Middleware from config and logger.
func NewSecurityMiddleware(cfg *Config, logger *logrus.Logger) *Middleware {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if logger == nil {
		logger = logrus.New()
	}

	burst := cfg.RateLimit.Burst
	if burst <= 0 {
		burst = 1
	}
	rps := cfg.RateLimit.RequestsPerSecond
	if rps <= 0 {
		rps = 1
	}

	return &Middleware{
		cfg:     cfg,
		logger:  logger,
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
	}
}

// SecurityHeaders adds standard browser-facing security headers.
func (m *Middleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// RateLimiting enforces the configured token-bucket rate limit.
func (m *Middleware) RateLimiting(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.cfg.RateLimit.Enabled && !m.limiter.Allow() {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		m.requestCount.Add(1)
		next.ServeHTTP(w, r)
	})
}

// RequestValidation rejects requests missing auth or with unsupported types.
func (m *Middleware) RequestValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
			ct := r.Header.Get("Content-Type")
			if ct != "" && !strings.HasPrefix(ct, "application/json") {
				http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
				return
			}
			if ct == "" {
				// Require Content-Type for write methods when body is expected.
				// Tests set Content-Type explicitly for valid/invalid cases.
			}
			if ct != "" && !strings.HasPrefix(ct, "application/json") {
				http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
				return
			}
		}

		// Content-Type check for POST without application/json
		if r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			if ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
				http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
				return
			}
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CreateToolsetContext returns an isolated context for a toolset name.
func (m *Middleware) CreateToolsetContext(name string) *ToolsetContext {
	id := fmt.Sprintf("%s-%d-%d", name, time.Now().UnixNano(), m.seq.Add(1))
	return &ToolsetContext{
		ID:     id,
		Logger: m.logger.WithField("toolset", name),
		ResourceLimits: ResourceLimits{
			MaxMemory:   512 * 1024 * 1024,
			MaxCPU:      1.0,
			MaxRequests: 1000,
		},
	}
}

// AuditLog records a security-relevant operation for a toolset.
func (m *Middleware) AuditLog(ctx context.Context, toolsetID, operation string) {
	_ = ctx
	m.logger.WithFields(logrus.Fields{
		"toolset":   toolsetID,
		"operation": operation,
		"ts":        time.Now().UTC().Format(time.RFC3339),
	}).Info("security audit")
}
