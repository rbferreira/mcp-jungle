package api

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal/telemetry"
	"github.com/mcpjungle/mcpjungle/pkg/testhelpers"
)

func TestSafeRequestLoggerDoesNotLogCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var captured bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&captured)
	t.Cleanup(func() { log.SetOutput(previous) })
	router := gin.New()
	router.Use(safeRequestLogger())
	router.GET("/callback", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodGet, "/callback?code=oauth-code-secret&token=query-secret", nil)
	req.Header.Set("Authorization", "Bearer authorization-secret")
	req.Header.Set("Cookie", "mcpjungle_session=cookie-secret")
	router.ServeHTTP(httptest.NewRecorder(), req)
	for _, secret := range []string{"oauth-code-secret", "query-secret", "authorization-secret", "cookie-secret"} {
		if strings.Contains(captured.String(), secret) {
			t.Fatalf("request logger exposed %q: %s", secret, captured.String())
		}
	}
}

func TestOAuthChallengeAdvertisesProtectedResourceMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := &Server{publicURL: "https://mcp.example.com"}
	router := gin.New()
	router.GET("/protected", func(c *gin.Context) {
		server.oauthChallenge(c, http.StatusUnauthorized, "missing access token")
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/protected", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	want := `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="mcp:tools"`
	if got := w.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("unexpected challenge: %q", got)
	}
}

func TestNewServer(t *testing.T) {
	tests := []struct {
		name    string
		opts    *ServerOptions
		wantErr bool
	}{
		{
			name: "valid options",
			opts: &ServerOptions{
				OtelProviders: nil, // Use nil for testing
				Metrics:       telemetry.NewNoopCustomMetrics(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := NewServer(tt.opts)
			if tt.wantErr {
				testhelpers.AssertError(t, err)
				// Check that server is nil when error occurs
				if server != nil {
					t.Error("Expected server to be nil when error occurs")
				}
			} else {
				testhelpers.AssertNoError(t, err)
				testhelpers.AssertNotNil(t, server)
			}
		})
	}
}

func TestRouterSetup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	opts := &ServerOptions{}

	server, err := NewServer(opts)
	testhelpers.AssertNoError(t, err)
	router, err := server.setupRouter()
	testhelpers.AssertNoError(t, err)
	testhelpers.AssertNotNil(t, router)

	// Test that health endpoint is registered
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/health", nil)
	router.ServeHTTP(w, req)
	testhelpers.AssertEqual(t, http.StatusOK, w.Code)
}
