package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/security"
	"github.com/mcpjungle/mcpjungle/internal/service/config"
	"github.com/mcpjungle/mcpjungle/internal/service/user"
	"github.com/mcpjungle/mcpjungle/pkg/testhelpers"
)

func TestEnterpriseInitializationRequiresBootstrapAndHashesAdminToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	database, err := testhelpers.CreateTestDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&model.ServerConfig{}, &model.User{}); err != nil {
		t.Fatal(err)
	}
	server := &Server{
		db: database, bootstrapToken: "bootstrap-secret",
		configService: config.NewServerConfigService(database), userService: user.NewUserService(database),
	}
	router := gin.New()
	router.POST("/init", server.registerInitServerHandler())
	body := `{"mode":"enterprise"}`
	missing := httptest.NewRecorder()
	missingReq := httptest.NewRequest(http.MethodPost, "/init", strings.NewReader(body))
	missingReq.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(missing, missingReq)
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", missing.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/init", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-MCPJungle-Bootstrap-Token", "bootstrap-secret")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var admin model.User
	if err := database.Where("username = ?", "admin").First(&admin).Error; err != nil {
		t.Fatal(err)
	}
	if !security.IsHashedToken(admin.AccessToken) || strings.Contains(response.Body.String(), admin.AccessToken) {
		t.Fatal("admin token was not stored as a one-way hash")
	}
}
