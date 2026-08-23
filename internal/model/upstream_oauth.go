package model

import (
	"encoding/json"
	"time"

	"github.com/mcpjungle/mcpjungle/internal/security"
	"github.com/mcpjungle/mcpjungle/pkg/types"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// UpstreamOAuthPendingSession stores an in-progress OAuth authorization flow for
// an upstream MCP server registration.
type UpstreamOAuthPendingSession struct {
	gorm.Model

	SessionID string `json:"session_id" gorm:"uniqueIndex;not null"`

	ServerName string                   `json:"server_name" gorm:"index;not null"`
	Transport  types.McpServerTransport `json:"transport" gorm:"type:varchar(30);not null"`

	// ServerInput stores the original RegisterServerInput payload so registration
	// can be resumed after the OAuth callback completes.
	ServerInput datatypes.JSON `json:"server_input" gorm:"type:jsonb;not null"`

	Force bool `json:"force" gorm:"not null;default:false"`

	RedirectURI  string         `json:"redirect_uri"`
	ClientID     string         `json:"client_id"`
	ClientSecret string         `json:"client_secret"`
	Scopes       datatypes.JSON `json:"scopes" gorm:"type:jsonb"`

	State        string    `json:"state" gorm:"not null"`
	CodeVerifier string    `json:"code_verifier" gorm:"not null"`
	ExpiresAt    time.Time `json:"expires_at" gorm:"index;not null"`

	InitiatedBy string `json:"initiated_by"`
}

// UpstreamOAuthToken stores gateway-scoped OAuth credentials for a registered
// upstream MCP server.
type UpstreamOAuthToken struct {
	gorm.Model

	ServerName string                   `json:"server_name" gorm:"uniqueIndex;not null"`
	Transport  types.McpServerTransport `json:"transport" gorm:"type:varchar(30);not null"`

	ClientID     string         `json:"client_id"`
	ClientSecret string         `json:"client_secret"`
	RedirectURI  string         `json:"redirect_uri"`
	Scopes       datatypes.JSON `json:"scopes" gorm:"type:jsonb"`

	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func encryptFields(fields ...*string) error {
	for _, field := range fields {
		value, err := security.EncryptString(*field)
		if err != nil {
			return err
		}
		*field = value
	}
	return nil
}

func decryptFields(fields ...*string) error {
	for _, field := range fields {
		value, err := security.DecryptString(*field)
		if err != nil {
			return err
		}
		*field = value
	}
	return nil
}

func (s *UpstreamOAuthPendingSession) BeforeSave(_ *gorm.DB) error {
	serverInput := string(s.ServerInput)
	if err := encryptFields(&serverInput, &s.ClientSecret, &s.CodeVerifier); err != nil {
		return err
	}
	if security.IsEncrypted(serverInput) {
		s.ServerInput = []byte(`{"_encrypted":"` + serverInput + `"}`)
	}
	return nil
}

func (s *UpstreamOAuthPendingSession) AfterFind(_ *gorm.DB) error {
	var envelope encryptedConfigEnvelope
	if json.Unmarshal(s.ServerInput, &envelope) == nil && envelope.Encrypted != "" {
		value, err := security.DecryptString(envelope.Encrypted)
		if err != nil {
			return err
		}
		s.ServerInput = []byte(value)
	}
	return decryptFields(&s.ClientSecret, &s.CodeVerifier)
}

func (t *UpstreamOAuthToken) BeforeSave(_ *gorm.DB) error {
	return encryptFields(&t.ClientSecret, &t.AccessToken, &t.RefreshToken)
}

func (t *UpstreamOAuthToken) AfterFind(_ *gorm.DB) error {
	return decryptFields(&t.ClientSecret, &t.AccessToken, &t.RefreshToken)
}
