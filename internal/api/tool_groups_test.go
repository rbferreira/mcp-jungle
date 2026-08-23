package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	mcpserver "github.com/mark3labs/mcp-go/server"
	mcpSvc "github.com/mcpjungle/mcpjungle/internal/service/mcp"
	"github.com/mcpjungle/mcpjungle/internal/service/toolgroup"
	"github.com/mcpjungle/mcpjungle/internal/telemetry"
	"github.com/mcpjungle/mcpjungle/pkg/testhelpers"
)

// setupToolGroupServer creates a Server with a real ToolGroupService backed by an in-memory DB.
func setupToolGroupServer(t *testing.T) *Server {
	t.Helper()
	setup := testhelpers.SetupTestDB(t)
	t.Cleanup(setup.Cleanup)

	mcpProxy := mcpserver.NewMCPServer("test", "0.0.1")
	sseMcpProxy := mcpserver.NewMCPServer("test-sse", "0.0.1")
	svc, err := mcpSvc.NewMCPService(&mcpSvc.ServiceConfig{
		DB:                      setup.DB,
		McpProxyServer:          mcpProxy,
		SseMcpProxyServer:       sseMcpProxy,
		Metrics:                 telemetry.NewNoopCustomMetrics(),
		McpServerInitReqTimeout: 5,
	})
	if err != nil {
		t.Fatalf("failed to create MCP service: %v", err)
	}

	tgSvc, err := toolgroup.NewToolGroupService(setup.DB, svc)
	if err != nil {
		t.Fatalf("failed to create tool group service: %v", err)
	}

	return &Server{toolGroupService: tgSvc}
}

func TestGetToolGroupHandler_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupToolGroupServer(t)

	router := gin.New()
	router.GET("/groups/:name", s.getToolGroupHandler())

	req := httptest.NewRequest(http.MethodGet, "/groups/ghost-group", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	testhelpers.AssertEqual(t, http.StatusNotFound, w.Code)
	testhelpers.AssertStringContains(t, w.Body.String(), "not found")
}

func TestUpdateToolGroupHandler_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := setupToolGroupServer(t)

	router := gin.New()
	router.PUT("/groups/:name", s.updateToolGroupHandler())

	req := httptest.NewRequest(http.MethodPut, "/groups/ghost-group",
		strings.NewReader(`{"name":"ghost-group","description":"updated"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	testhelpers.AssertEqual(t, http.StatusNotFound, w.Code)
	testhelpers.AssertStringContains(t, w.Body.String(), "not found")
}

func TestToolGroupEndpointsPreferConfiguredPublicURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{publicURL: "https://mcp.example.com"}

	req := httptest.NewRequest(http.MethodGet, "http://attacker.example/groups", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req

	endpoints := s.getToolGroupEndpoints(c, "research")
	testhelpers.AssertEqual(t, "https://mcp.example.com/v0/groups/research/mcp", endpoints.StreamableHTTPEndpoint)
	testhelpers.AssertEqual(t, "https://mcp.example.com/v0/groups/research/sse", endpoints.SSEEndpoint)
	testhelpers.AssertEqual(t, "https://mcp.example.com/v0/groups/research/message", endpoints.SSEMessageEndpoint)
}

func TestToolGroupEndpointsFallBackToRequestHostWithoutPublicURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{}

	req := httptest.NewRequest(http.MethodGet, "http://registry.example/groups", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req

	endpoints := s.getToolGroupEndpoints(c, "research")
	testhelpers.AssertEqual(t, "https://registry.example/v0/groups/research/mcp", endpoints.StreamableHTTPEndpoint)
}
