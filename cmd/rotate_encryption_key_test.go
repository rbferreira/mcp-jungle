package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/security"
	"github.com/mcpjungle/mcpjungle/pkg/testhelpers"
)

func TestRotateStoredEncryptionKey(t *testing.T) {
	database, err := testhelpers.CreateTestDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(
		&model.McpServer{}, &model.UpstreamOAuthToken{},
		&model.UpstreamOAuthPendingSession{}, &model.DashboardLoginState{},
	); err != nil {
		t.Fatal(err)
	}
	oldKey := testEncryptionKey(t)
	newKey := testEncryptionKey(t)
	if err := security.ConfigureEncryptionKey(oldKey); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = security.ConfigureEncryptionKey("") })
	server, err := model.NewStreamableHTTPServer("remote", "", "https://example.com/mcp", "rotation-secret", nil, "stateless")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Create(server).Error; err != nil {
		t.Fatal(err)
	}
	var before string
	if err := database.Table("mcp_servers").Select("config").Where("name = ?", "remote").Scan(&before).Error; err != nil {
		t.Fatal(err)
	}
	if err := rotateStoredEncryptionKey(database, oldKey, newKey); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := database.Table("mcp_servers").Select("config").Where("name = ?", "remote").Scan(&after).Error; err != nil {
		t.Fatal(err)
	}
	if before == after || strings.Contains(after, "rotation-secret") {
		t.Fatal("rotation did not replace the encrypted envelope")
	}
	var loaded model.McpServer
	if err := database.Where("name = ?", "remote").First(&loaded).Error; err != nil {
		t.Fatalf("new key could not decrypt rotated data: %v", err)
	}
	config, err := loaded.GetStreamableHTTPConfig()
	if err != nil || config.BearerToken != "rotation-secret" {
		t.Fatal("rotated secret did not round-trip")
	}
	if err := security.ConfigureEncryptionKey(oldKey); err != nil {
		t.Fatal(err)
	}
	if err := database.Where("name = ?", "remote").First(&model.McpServer{}).Error; err == nil {
		t.Fatal("old key decrypted data after rotation")
	}
}

func testEncryptionKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}
