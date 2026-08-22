package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/security"
	"github.com/mcpjungle/mcpjungle/pkg/types"
	"gorm.io/gorm"
)

var errAlreadyInitialized = errors.New("server is already initialized")

func (s *Server) registerInitServerHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Mode model.ServerMode `json:"mode" binding:"required,oneof=development enterprise production"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
			return
		}
		if model.IsEnterpriseMode(req.Mode) {
			provided := c.GetHeader("X-MCPJungle-Bootstrap-Token")
			if s.bootstrapToken == "" || !security.TokenMatches(security.HashToken(s.bootstrapToken), provided) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or missing bootstrap token"})
				return
			}
		}
		if req.Mode == model.ModeDev {
			ok, err := s.configService.Init(req.Mode)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize server: " + err.Error()})
				return
			}
			if !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Server is already initialized"})
				return
			}
			// If the server was successfully initialized and the mode is dev,
			// return a success message without creating an admin user
			c.JSON(http.StatusOK, gin.H{"status": "Server initialized successfully in development mode"})
			return
		}
		adminToken, err := internal.GenerateAccessToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate admin token"})
			return
		}
		if s.db == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database is not configured"})
			return
		}
		err = s.db.Transaction(func(tx *gorm.DB) error {
			var existing model.ServerConfig
			err := tx.First(&existing).Error
			if err == nil && existing.Initialized {
				return errAlreadyInitialized
			}
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if errors.Is(err, gorm.ErrRecordNotFound) {
				existing = model.ServerConfig{Mode: req.Mode, Initialized: true}
				if err := tx.Create(&existing).Error; err != nil {
					return err
				}
			} else {
				existing.Mode = req.Mode
				existing.Initialized = true
				if err := tx.Save(&existing).Error; err != nil {
					return err
				}
			}
			admin := model.User{Username: "admin", Role: types.UserRoleAdmin, AccessToken: security.HashToken(adminToken)}
			return tx.Create(&admin).Error
		})
		if errors.Is(err, errAlreadyInitialized) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Server is already initialized"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize server"})
			return
		}
		payload := gin.H{
			"status":             "Server initialized successfully",
			"admin_access_token": adminToken,
		}
		c.JSON(http.StatusOK, payload)
	}
}
