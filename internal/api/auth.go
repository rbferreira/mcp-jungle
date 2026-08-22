package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal/service/authn"
)

func (s *Server) protectedResourceMetadataHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.authService == nil || s.publicURL == "" {
			c.JSON(http.StatusNotFound, gin.H{"error": "OAuth is not configured"})
			return
		}
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, gin.H{
			"resource":              s.publicURL,
			"authorization_servers": []string{s.authService.Issuer()},
			"scopes_supported":      []string{"mcp:tools"},
		})
	}
}

func (s *Server) readinessHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.db == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "error": "database is not configured"})
			return
		}
		sqlDB, err := s.db.DB()
		if err != nil || sqlDB.PingContext(c.Request.Context()) != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "error": "database is unavailable"})
			return
		}
		initialized, err := s.IsInitialized()
		if err != nil || !initialized {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "not_ready", "error": "server is not initialized"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}
}

func (s *Server) authLoginHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.authService == nil {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		initialized, err := s.IsInitialized()
		if err != nil || !initialized {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "server is not initialized"})
			return
		}
		loginURL, err := s.authService.BeginLogin(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to begin login"})
			return
		}
		c.Redirect(http.StatusFound, loginURL)
	}
}

func (s *Server) authCallbackHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if oauthError := c.Query("error"); oauthError != "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Auth0 login failed"})
			return
		}
		session, csrf, expires, err := s.authService.CompleteLogin(c.Request.Context(), c.Query("state"), c.Query("code"))
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, authn.ErrForbidden) {
				status = http.StatusForbidden
			}
			c.JSON(status, gin.H{"error": "dashboard login was rejected"})
			return
		}
		secure := strings.HasPrefix(s.publicURL, "https://")
		maxAge := int(time.Until(expires).Seconds())
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(dashboardSessionCookie, session, maxAge, "/", "", secure, true)
		c.SetCookie(dashboardCSRFCookie, csrf, maxAge, "/", "", secure, false)
		c.Redirect(http.StatusFound, "/")
	}
}

func (s *Server) authLogoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, _ := c.Cookie(dashboardSessionCookie)
		_ = s.authService.DeleteSession(c.Request.Context(), token)
		secure := strings.HasPrefix(s.publicURL, "https://")
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(dashboardSessionCookie, "", -1, "/", "", secure, true)
		c.SetCookie(dashboardCSRFCookie, "", -1, "/", "", secure, false)
		c.JSON(http.StatusOK, gin.H{"logout_url": s.authService.LogoutURL()})
	}
}
