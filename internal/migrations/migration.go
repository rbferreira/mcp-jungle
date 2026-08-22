// Package migrations provides database migration functionality for the MCPJungle application.
package migrations

import (
	"fmt"
	"time"

	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/security"
	"gorm.io/gorm"
)

// Migrate performs the database migration for the application.
func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&model.MigrationRecord{}); err != nil {
		return fmt.Errorf("auto-migration failed for MigrationRecord model: %v", err)
	}
	if err := db.AutoMigrate(&model.McpServer{}); err != nil {
		return fmt.Errorf("auto‑migration failed for McpServer model: %v", err)
	}
	if err := db.AutoMigrate(&model.Tool{}); err != nil {
		return fmt.Errorf("auto‑migration failed for Tool model: %v", err)
	}
	if err := db.AutoMigrate(&model.ServerConfig{}); err != nil {
		return fmt.Errorf("auto‑migration failed for ServerConfig model: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}); err != nil {
		return fmt.Errorf("auto‑migration failed for User model: %v", err)
	}
	if err := db.AutoMigrate(&model.McpClient{}); err != nil {
		return fmt.Errorf("auto‑migration failed for McpClient model: %v", err)
	}
	if err := db.AutoMigrate(&model.ToolGroup{}); err != nil {
		return fmt.Errorf("auto‑migration failed for ToolGroup model: %v", err)
	}
	if err := db.AutoMigrate(&model.Prompt{}); err != nil {
		return fmt.Errorf("auto‑migration failed for Prompt model: %v", err)
	}
	if err := db.AutoMigrate(&model.Resource{}); err != nil {
		return fmt.Errorf("auto‑migration failed for Resource model: %v", err)
	}
	if err := db.AutoMigrate(&model.UpstreamOAuthPendingSession{}); err != nil {
		return fmt.Errorf("auto-migration failed for UpstreamOAuthPendingSession model: %v", err)
	}
	if err := db.AutoMigrate(&model.UpstreamOAuthToken{}); err != nil {
		return fmt.Errorf("auto-migration failed for UpstreamOAuthToken model: %v", err)
	}
	if err := db.AutoMigrate(&model.DashboardSession{}, &model.DashboardLoginState{}, &model.HostedClientBinding{}); err != nil {
		return fmt.Errorf("auto-migration failed for security models: %v", err)
	}
	if err := runOnce(db, "2026-08-22-hash-access-tokens", func(tx *gorm.DB) error {
		for _, table := range []string{"users", "mcp_clients"} {
			var rows []struct {
				ID          uint
				AccessToken string
			}
			if err := tx.Table(table).Select("id", "access_token").Find(&rows).Error; err != nil {
				return err
			}
			for _, row := range rows {
				if row.AccessToken == "" || security.IsHashedToken(row.AccessToken) {
					continue
				}
				if err := tx.Table(table).Where("id = ?", row.ID).Update("access_token", security.HashToken(row.AccessToken)).Error; err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to hash existing access tokens: %w", err)
	}
	if security.EncryptionEnabled() {
		if err := runOnce(db, "2026-08-22-encrypt-stored-secrets", func(tx *gorm.DB) error {
			var servers []model.McpServer
			if err := tx.Find(&servers).Error; err != nil {
				return err
			}
			for i := range servers {
				if err := tx.Save(&servers[i]).Error; err != nil {
					return err
				}
			}
			var tokens []model.UpstreamOAuthToken
			if err := tx.Find(&tokens).Error; err != nil {
				return err
			}
			for i := range tokens {
				if err := tx.Save(&tokens[i]).Error; err != nil {
					return err
				}
			}
			var pending []model.UpstreamOAuthPendingSession
			if err := tx.Find(&pending).Error; err != nil {
				return err
			}
			for i := range pending {
				if err := tx.Save(&pending[i]).Error; err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to encrypt existing stored secrets: %w", err)
		}
	}
	return nil
}

func runOnce(db *gorm.DB, name string, migration func(*gorm.DB) error) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.MigrationRecord{}).Where("name = ?", name).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return nil
		}
		if err := migration(tx); err != nil {
			return err
		}
		return tx.Create(&model.MigrationRecord{Name: name, AppliedAt: time.Now().UTC()}).Error
	})
}
