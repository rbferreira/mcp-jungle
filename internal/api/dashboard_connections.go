package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"gorm.io/datatypes"
)

type dashboardStaticConnection struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	AllowList   []string   `json:"allow_list"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
}

type dashboardHostedConnection struct {
	ClientID   string     `json:"client_id"`
	ToolGroup  string     `json:"tool_group"`
	Endpoint   string     `json:"endpoint"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func (s *Server) dashboardConnectionsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		staticRecords, err := s.mcpClientService.ListClients()
		if err != nil {
			handleServiceError(c, err)
			return
		}
		staticConnections := make([]dashboardStaticConnection, 0, len(staticRecords))
		for _, record := range staticRecords {
			var allowList []string
			_ = json.Unmarshal(record.AllowList, &allowList)
			staticConnections = append(staticConnections, dashboardStaticConnection{
				Name: record.Name, Description: record.Description, AllowList: allowList, LastSeenAt: record.LastSeenAt,
			})
		}
		hostedConnections := []dashboardHostedConnection{}
		if s.authService != nil {
			bindings, err := s.authService.ListHostedClients(c.Request.Context())
			if err != nil {
				handleServiceError(c, err)
				return
			}
			for _, binding := range bindings {
				hostedConnections = append(hostedConnections, dashboardHostedConnection{
					ClientID:   binding.ClientID,
					ToolGroup:  binding.ToolGroupName,
					Endpoint:   s.publicURL + "/v0/groups/" + binding.ToolGroupName + "/mcp",
					LastSeenAt: binding.LastSeenAt,
					RevokedAt:  binding.RevokedAt,
				})
			}
		}
		c.JSON(http.StatusOK, gin.H{"static_connections": staticConnections, "hosted_connections": hostedConnections})
	}
}

func (s *Server) dashboardCreateStaticConnectionHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var input struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			AllowList   []string `json:"allow_list"`
		}
		if err := c.ShouldBindJSON(&input); err != nil || input.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name and allow_list are required"})
			return
		}
		allowList, _ := json.Marshal(input.AllowList)
		created, err := s.mcpClientService.CreateClient(model.McpClient{Name: input.Name, Description: input.Description, AllowList: datatypes.JSON(allowList)})
		if err != nil {
			handleServiceError(c, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{"name": created.Name, "access_token": created.AccessToken})
	}
}

func (s *Server) dashboardRotateStaticConnectionHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		client, err := s.mcpClientService.RotateClientToken(c.Param("name"))
		if err != nil {
			handleServiceError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"name": client.Name, "access_token": client.AccessToken})
	}
}

func (s *Server) dashboardDeleteStaticConnectionHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := s.mcpClientService.DeleteClient(c.Param("name")); err != nil {
			handleServiceError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func (s *Server) dashboardRevokeHostedConnectionHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.authService == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "hosted OAuth connections are not configured"})
			return
		}
		if err := s.authService.RevokeHostedClient(c.Request.Context(), c.Param("client_id")); err != nil {
			handleServiceError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}
