package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mcpjungle/mcpjungle/internal/db"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/security"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

var (
	rotateOldKey string
	rotateNewKey string
)

var rotateEncryptionKeyCmd = &cobra.Command{
	Use:   "rotate-encryption-key",
	Short: "Re-encrypt stored credentials with a new key",
	RunE:  runRotateEncryptionKey,
	Annotations: map[string]string{
		"group": string(subCommandGroupAdvanced),
		"order": "7",
	},
}

func init() {
	rotateEncryptionKeyCmd.Flags().StringVar(&rotateOldKey, "old-key", "", "current base64 encryption key (or MCPJUNGLE_PREVIOUS_ENCRYPTION_KEY)")
	rotateEncryptionKeyCmd.Flags().StringVar(&rotateNewKey, "new-key", "", "replacement base64 encryption key (or MCPJUNGLE_ENCRYPTION_KEY)")
	rootCmd.AddCommand(rotateEncryptionKeyCmd)
}

func runRotateEncryptionKey(_ *cobra.Command, _ []string) error {
	oldKey := strings.TrimSpace(rotateOldKey)
	if oldKey == "" {
		oldKey = strings.TrimSpace(os.Getenv("MCPJUNGLE_PREVIOUS_ENCRYPTION_KEY"))
	}
	newKey := strings.TrimSpace(rotateNewKey)
	if newKey == "" {
		newKey = strings.TrimSpace(os.Getenv(EncryptionKeyEnvVar))
	}
	if oldKey == "" || newKey == "" {
		return errors.New("both old and new encryption keys are required")
	}
	if oldKey == newKey {
		return errors.New("old and new encryption keys must differ")
	}
	dsn := os.Getenv(DBUrlEnvVar)
	if dsn == "" {
		if value, ok, err := getPostgresDSN(); err != nil {
			return err
		} else if ok {
			dsn = value
		}
	}
	database, err := db.NewDBConnection(dsn, getSQLiteDBPathOverride())
	if err != nil {
		return err
	}
	return rotateStoredEncryptionKey(database, oldKey, newKey)
}

func rotateStoredEncryptionKey(database *gorm.DB, oldKey, newKey string) error {
	if err := security.ConfigureEncryptionKey(oldKey); err != nil {
		return fmt.Errorf("invalid old key: %w", err)
	}
	var servers []model.McpServer
	var tokens []model.UpstreamOAuthToken
	var pending []model.UpstreamOAuthPendingSession
	var loginStates []model.DashboardLoginState
	if err := database.Find(&servers).Error; err != nil {
		return fmt.Errorf("decrypt server credentials: %w", err)
	}
	if err := database.Find(&tokens).Error; err != nil {
		return fmt.Errorf("decrypt OAuth tokens: %w", err)
	}
	if err := database.Find(&pending).Error; err != nil {
		return fmt.Errorf("decrypt OAuth sessions: %w", err)
	}
	if err := database.Find(&loginStates).Error; err != nil {
		return fmt.Errorf("decrypt login states: %w", err)
	}
	if err := security.ConfigureEncryptionKey(newKey); err != nil {
		return fmt.Errorf("invalid new key: %w", err)
	}
	return database.Transaction(func(tx *gorm.DB) error {
		for i := range servers {
			if err := tx.Save(&servers[i]).Error; err != nil {
				return err
			}
		}
		for i := range tokens {
			if err := tx.Save(&tokens[i]).Error; err != nil {
				return err
			}
		}
		for i := range pending {
			if err := tx.Save(&pending[i]).Error; err != nil {
				return err
			}
		}
		for i := range loginStates {
			if err := tx.Save(&loginStates[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
