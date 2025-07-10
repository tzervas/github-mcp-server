package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestSecurityConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		cfg := DefaultConfig()
		assert.True(t, cfg.ReadOnly, "Default config should be read-only")
		assert.True(t, cfg.DynamicToolsets, "Dynamic toolsets should be enabled by default")
		assert.True(t, cfg.RateLimit.Enabled, "Rate limiting should be enabled by default")
		assert.Equal(t, float64(10), cfg.RateLimit.RequestsPerSecond, "Default RPS should be 10")
	})
}

func TestSecurityHeaders(t *testing.T) {
	logger := logrus.New()
	cfg := DefaultConfig()
	middleware := NewSecurityMiddleware(cfg, logger)

	handler := middleware.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	expectedHeaders := map[string]string{
		"Content-Security-Policy":     "default-src 'self'",
		"X-Content-Type-Options":      "nosniff",
		"X-Frame-Options":            "DENY",
		"X-XSS-Protection":           "1; mode=block",
		"Strict-Transport-Security":   "max-age=31536000; includeSubDomains",
	}

	for header, expected := range expectedHeaders {
		assert.Equal(t, expected, rec.Header().Get(header), "Security header %s not set correctly", header)
	}
}

func TestRateLimiting(t *testing.T) {
	logger := logrus.New()
	cfg := DefaultConfig()
	cfg.RateLimit.RequestsPerSecond = 2
	cfg.RateLimit.Burst = 1
	middleware := NewSecurityMiddleware(cfg, logger)

	handler := middleware.RateLimiting(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Within Limits", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Exceeds Limits", func(t *testing.T) {
		// Make multiple requests quickly
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if i >= 3 {
				assert.Equal(t, http.StatusTooManyRequests, rec.Code)
			}
		}
	})
}

func TestToolsetIsolation(t *testing.T) {
	logger := logrus.New()
	cfg := DefaultConfig()
	middleware := NewSecurityMiddleware(cfg, logger)

	t.Run("Context Creation", func(t *testing.T) {
		ctx1 := middleware.CreateToolsetContext("toolset1")
		ctx2 := middleware.CreateToolsetContext("toolset2")

		assert.NotEqual(t, ctx1.ID, ctx2.ID)
		assert.NotNil(t, ctx1.Logger)
		assert.NotNil(t, ctx2.Logger)
	})

	t.Run("Resource Limits", func(t *testing.T) {
		ctx := middleware.CreateToolsetContext("test-toolset")
		assert.Equal(t, int64(512*1024*1024), ctx.ResourceLimits.MaxMemory)
		assert.Equal(t, float64(1.0), ctx.ResourceLimits.MaxCPU)
		assert.Equal(t, 1000, ctx.ResourceLimits.MaxRequests)
	})
}

func TestRequestValidation(t *testing.T) {
	logger := logrus.New()
	cfg := DefaultConfig()
	middleware := NewSecurityMiddleware(cfg, logger)

	handler := middleware.RequestValidation(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Valid Request", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("Invalid Content Type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnsupportedMediaType, rec.Code)
	})

	t.Run("Missing Authorization", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestAuditLogging(t *testing.T) {
	logger := logrus.New()
	cfg := DefaultConfig()
	middleware := NewSecurityMiddleware(cfg, logger)

	// Create a test buffer for logging
	buf := &logBuffer{}
	logger.SetOutput(buf)

	ctx := context.Background()
	toolsetID := "test-toolset"
	operation := "test-operation"

	middleware.AuditLog(ctx, toolsetID, operation)

	logs := buf.String()
	assert.Contains(t, logs, toolsetID)
	assert.Contains(t, logs, operation)
}

// Helper type for capturing logs
type logBuffer struct {
	logs []string
}

func (b *logBuffer) Write(p []byte) (n int, err error) {
	b.logs = append(b.logs, string(p))
	return len(p), nil
}

func (b *logBuffer) String() string {
	return string(b.logs[len(b.logs)-1])
}
