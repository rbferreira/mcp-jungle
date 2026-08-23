package model

import (
	"time"

	"github.com/mcpjungle/mcpjungle/internal/security"
	"gorm.io/gorm"
)

type MigrationRecord struct {
	Name      string    `gorm:"primaryKey;size:160"`
	AppliedAt time.Time `gorm:"not null"`
}

type DashboardSession struct {
	gorm.Model
	TokenHash string    `gorm:"uniqueIndex;not null"`
	CSRFHash  string    `gorm:"not null"`
	Subject   string    `gorm:"index;not null"`
	ExpiresAt time.Time `gorm:"index;not null"`
}

type DashboardLoginState struct {
	gorm.Model
	StateHash    string    `gorm:"uniqueIndex;not null"`
	Nonce        string    `gorm:"not null"`
	CodeVerifier string    `gorm:"not null"`
	ExpiresAt    time.Time `gorm:"index;not null"`
}

func (s *DashboardLoginState) BeforeSave(_ *gorm.DB) error {
	value, err := security.EncryptString(s.CodeVerifier)
	if err == nil {
		s.CodeVerifier = value
	}
	return err
}

func (s *DashboardLoginState) AfterFind(_ *gorm.DB) error {
	value, err := security.DecryptString(s.CodeVerifier)
	if err == nil {
		s.CodeVerifier = value
	}
	return err
}

type HostedClientBinding struct {
	gorm.Model
	ClientID      string     `json:"client_id" gorm:"uniqueIndex;not null"`
	Subject       string     `json:"subject" gorm:"index;not null"`
	ToolGroupName string     `json:"tool_group" gorm:"index;not null"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty" gorm:"index"`
}
