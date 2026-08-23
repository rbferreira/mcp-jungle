package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/service/authn"
	"github.com/mcpjungle/mcpjungle/pkg/types"
	"gorm.io/datatypes"
)

const (
	dashboardSessionCookie = "mcpjungle_session"
	dashboardCSRFCookie    = "mcpjungle_csrf"
)

// requireInitialized is middleware to reject requests to certain routes if the server is not initialized
func (s *Server) requireInitialized() gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := s.configService.GetConfig()
		if err != nil || !cfg.Initialized {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "server is not initialized"})
			return
		}
		// propagate the server mode in context for other middleware/handlers to use
		c.Set("mode", cfg.Mode)
		c.Next()
	}
}

// requireDashboardMode allows the open local dashboard in development mode and
// the authenticated dashboard when it is explicitly enabled in enterprise mode.
func (s *Server) requireDashboardMode() gin.HandlerFunc {
	return func(c *gin.Context) {
		mode, exists := c.Get("mode")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server mode not found in context"})
			return
		}
		currentMode, ok := mode.(model.ServerMode)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid server mode in context"})
			return
		}
		if currentMode != model.ModeDev && !(model.IsEnterpriseMode(currentMode) && s.dashboardEnabled) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		c.Next()
	}
}

func (s *Server) requireDashboardPageAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		mode, _ := c.Get("mode")
		if mode == model.ModeDev {
			c.Next()
			return
		}
		if s.authService == nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		token, _ := c.Cookie(dashboardSessionCookie)
		if _, err := s.authService.AuthenticateSession(c.Request.Context(), token); err != nil {
			c.Redirect(http.StatusFound, "/auth/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (s *Server) requireDashboardAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		mode, _ := c.Get("mode")
		if mode == model.ModeDev {
			c.Next()
			return
		}
		if s.authService == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "dashboard authentication is not configured"})
			return
		}
		token, _ := c.Cookie(dashboardSessionCookie)
		session, err := s.authService.AuthenticateSession(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "dashboard session is missing or expired"})
			return
		}
		c.Set("dashboard_session", session)
		c.Next()
	}
}

func (s *Server) requireDashboardCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		mode, _ := c.Get("mode")
		if mode == model.ModeDev {
			c.Next()
			return
		}
		sessionValue, exists := c.Get("dashboard_session")
		session, ok := sessionValue.(*model.DashboardSession)
		if !exists || !ok || !s.authService.VerifyCSRF(session, c.GetHeader("X-CSRF-Token")) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid CSRF token"})
			return
		}
		c.Next()
	}
}

// verifyUserAuthForAPIAccess is middleware that checks for a valid user token if the server is in enterprise mode.
// this middleware doesn't care about the role of the user, it just verifies that they're authenticated.
func (s *Server) verifyUserAuthForAPIAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		mode, exists := c.Get("mode")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server mode not found in context"})
			return
		}
		m, ok := mode.(model.ServerMode)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid server mode in context"})
			return
		}
		if m == model.ModeDev {
			// no auth is required in case of dev mode
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing access token"})
			return
		}

		// Verify that the token is valid and corresponds to a user
		authenticatedUser, err := s.userService.GetUserByAccessToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid access token: " + err.Error()})
			return
		}

		// Store user in context for potential role checks in subsequent handlers
		c.Set("user", authenticatedUser)
		c.Next()
	}
}

// requireAdminUser is middleware that ensures the authenticated user has an admin role when in enterprise mode.
// It assumes that verifyUserAuthForAPIAccess middleware has already run and set the user in context.
func (s *Server) requireAdminUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		mode, exists := c.Get("mode")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server mode not found in context"})
			return
		}
		m, ok := mode.(model.ServerMode)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid server mode in context"})
			return
		}
		if m == model.ModeDev {
			// no admin check is required in dev mode
			c.Next()
			return
		}

		authenticatedUser, exists := c.Get("user")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user is not authenticated"})
			return
		}

		u, ok := authenticatedUser.(*model.User)
		if ok && u.Role == types.UserRoleAdmin {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "user is not authorized to perform this action"})
	}
}

// requireServerMode is middleware that checks if the server is in a specific mode.
// If not, the request is rejected with a 403 Forbidden status.
// This is useful for routes that should only be accessible in certain modes (e.g., enterprise-only features).
// NOTE: ModeProd is supported for backwards compatibility, it is equivalent to ModeEnterprise.
func (s *Server) requireServerMode(m model.ServerMode) gin.HandlerFunc {
	return func(c *gin.Context) {
		mode, exists := c.Get("mode")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server mode not found in context"})
			return
		}
		currentMode, ok := mode.(model.ServerMode)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid server mode in context"})
			return
		}

		if currentMode == m {
			// current mode matches the required mode, allow access
			c.Next()
			return
		}
		if model.IsEnterpriseMode(currentMode) && model.IsEnterpriseMode(m) {
			// both current and required modes are enterprise modes, allow access
			c.Next()
			return
		}
		// current mode does not match the required mode, reject the request
		c.AbortWithStatusJSON(
			http.StatusForbidden,
			gin.H{"error": fmt.Sprintf("this request is only allowed in %s mode", m)},
		)
	}
}

// checkAuthForMcpProxyAccess is middleware for MCP proxy that checks for a valid MCP client token
// if the server is in enterprise mode.
// In development mode, mcp clients do not require auth to access the MCP proxy.
func (s *Server) checkAuthForMcpProxyAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		mode, exists := c.Get("mode")
		if !exists {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server mode not found in context"})
			return
		}
		m, ok := mode.(model.ServerMode)
		if !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "invalid server mode in context"})
			return
		}

		// the gin context doesn't get passed down to the MCP proxy server, so we need to
		// set values in the underlying request's context to be able to access them from proxy.
		ctx := context.WithValue(c.Request.Context(), "mode", m)
		c.Request = c.Request.WithContext(ctx)

		if m == model.ModeDev {
			// no auth is required in case of dev mode
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing MCP client access token"})
			return
		}
		client, err := s.mcpClientService.GetClientByToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid MCP client token"})
			return
		}

		// inject the authenticated MCP client in context for the proxy to use
		ctx = context.WithValue(c.Request.Context(), "client", client)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

func (s *Server) oauthChallenge(c *gin.Context, status int, message string) {
	metadataURL := s.publicURL + "/.well-known/oauth-protected-resource"
	if s.publicURL != "" {
		c.Header("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s", scope="mcp:tools"`, metadataURL))
	}
	c.AbortWithStatusJSON(status, gin.H{"error": message})
}

// checkAuthForToolGroupAccess accepts either a static MCP client token or an
// Auth0 access token. Auth0 clients are atomically bound to one tool group.
func (s *Server) checkAuthForToolGroupAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		modeValue, exists := c.Get("mode")
		mode, ok := modeValue.(model.ServerMode)
		if !exists || !ok {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server mode not found in context"})
			return
		}
		ctx := context.WithValue(c.Request.Context(), "mode", mode)
		c.Request = c.Request.WithContext(ctx)
		if mode == model.ModeDev {
			c.Next()
			return
		}
		token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if token == "" {
			s.oauthChallenge(c, http.StatusUnauthorized, "missing access token")
			return
		}
		if client, err := s.mcpClientService.GetClientByToken(token); err == nil {
			ctx = context.WithValue(c.Request.Context(), "client", client)
			c.Request = c.Request.WithContext(ctx)
			c.Next()
			return
		}
		if s.authService == nil {
			s.oauthChallenge(c, http.StatusUnauthorized, "invalid access token")
			return
		}
		groupName := c.Param("name")
		if _, err := s.toolGroupService.GetToolGroup(groupName); err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "tool group not found"})
			return
		}
		identity, err := s.authService.VerifyAccessToken(c.Request.Context(), token)
		if err != nil {
			if errors.Is(err, authn.ErrForbidden) {
				s.oauthChallenge(c, http.StatusForbidden, "token is not authorized for this gateway")
			} else {
				s.oauthChallenge(c, http.StatusUnauthorized, "invalid access token")
			}
			return
		}
		if _, err := s.authService.BindHostedClient(c.Request.Context(), identity, groupName); err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "hosted client is bound to another tool group or has been revoked"})
			return
		}
		allowList, _ := json.Marshal([]string{types.AllowAllMcpServers})
		client := &model.McpClient{Name: "oauth:" + identity.ClientID, AllowList: datatypes.JSON(allowList)}
		ctx = context.WithValue(c.Request.Context(), "client", client)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
