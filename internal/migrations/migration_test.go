package migrations

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/security"
	"github.com/mcpjungle/mcpjungle/pkg/testhelpers"
)

func TestMigrateHashesTokensAndEncryptsServerConfig(t *testing.T) {
	database, err := testhelpers.CreateTestDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&model.User{}, &model.McpClient{}, &model.McpServer{}); err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&model.User{Username: "admin", Role: "admin", AccessToken: "plain-user-token"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&model.McpClient{Name: "local", AccessToken: "plain-client-token", AllowList: []byte("[]")}).Error; err != nil {
		t.Fatal(err)
	}
	server, err := model.NewStreamableHTTPServer("remote", "", "https://example.com/mcp", "upstream-secret", nil, "stateless")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Create(server).Error; err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := security.ConfigureEncryptionKey(base64.StdEncoding.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = security.ConfigureEncryptionKey("") })
	if err := Migrate(database); err != nil {
		t.Fatal(err)
	}
	var userToken, clientToken string
	if err := database.Table("users").Select("access_token").Where("username = ?", "admin").Scan(&userToken).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Table("mcp_clients").Select("access_token").Where("name = ?", "local").Scan(&clientToken).Error; err != nil {
		t.Fatal(err)
	}
	if userToken != security.HashToken("plain-user-token") || clientToken != security.HashToken("plain-client-token") {
		t.Fatal("tokens were not hashed")
	}
	var rawConfig string
	if err := database.Table("mcp_servers").Select("config").Where("name = ?", "remote").Scan(&rawConfig).Error; err != nil {
		t.Fatal(err)
	}
	if !contains(rawConfig, "enc:v1:") || contains(rawConfig, "upstream-secret") {
		t.Fatalf("server config was not encrypted: %s", rawConfig)
	}
}

func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
