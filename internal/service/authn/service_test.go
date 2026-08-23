package authn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/security"
	"github.com/mcpjungle/mcpjungle/pkg/testhelpers"
)

func TestVerifyAccessTokenClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/oauth/token", "jwks_uri": issuer + "/.well-known/jwks.json",
				"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	database, err := testhelpers.CreateTestDB()
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(t.Context(), database, Config{
		PublicURL: "https://mcp.example.com", Issuer: issuer, Audience: "https://mcp.example.com",
		DashboardClientID: "dashboard", DashboardClientSecret: "secret", AdminSubject: "auth0|admin",
	})
	if err != nil {
		t.Fatal(err)
	}

	baseClaims := map[string]any{
		"iss": issuer, "sub": "auth0|admin", "aud": "https://mcp.example.com",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		"scope": "openid mcp:tools", "client_id": "hosted-client",
	}
	valid := signTestJWT(t, key, baseClaims)
	identity, err := service.VerifyAccessToken(t.Context(), valid)
	if err != nil || identity.ClientID != "hosted-client" || identity.Subject != "auth0|admin" {
		t.Fatalf("valid access token was rejected: %#v, %v", identity, err)
	}

	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr error
	}{
		{name: "wrong audience", mutate: func(c map[string]any) { c["aud"] = "https://other.example.com" }, wantErr: ErrUnauthenticated},
		{name: "expired", mutate: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, wantErr: ErrUnauthenticated},
		{name: "wrong administrator", mutate: func(c map[string]any) { c["sub"] = "auth0|other" }, wantErr: ErrForbidden},
		{name: "missing scope", mutate: func(c map[string]any) { c["scope"] = "openid" }, wantErr: ErrForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := make(map[string]any, len(baseClaims))
			for key, value := range baseClaims {
				claims[key] = value
			}
			test.mutate(claims)
			_, err := service.VerifyAccessToken(t.Context(), signTestJWT(t, key, claims))
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("expected %v, got %v", test.wantErr, err)
			}
		})
	}
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "at+jwt"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestHostedClientBindsToExactlyOneGroup(t *testing.T) {
	database, err := testhelpers.CreateTestDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&model.HostedClientBinding{}); err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := database.DB()
	sqlDB.SetMaxOpenConns(1)
	service := &Service{db: database}
	identity := &AccessIdentity{Subject: "auth0|admin", ClientID: "dcr-client"}
	groups := []string{"chatgpt", "claude"}
	errorsSeen := make([]error, 2)
	var wg sync.WaitGroup
	for i := range groups {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			_, errorsSeen[index] = service.BindHostedClient(t.Context(), identity, groups[index])
		}(i)
	}
	wg.Wait()
	successes, forbidden := 0, 0
	for _, err := range errorsSeen {
		if err == nil {
			successes++
		}
		if errors.Is(err, ErrForbidden) {
			forbidden++
		}
	}
	if successes != 1 || forbidden != 1 {
		t.Fatalf("expected one success and one forbidden result, got %#v", errorsSeen)
	}
}

func TestDashboardSessionAndCSRF(t *testing.T) {
	database, err := testhelpers.CreateTestDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&model.DashboardSession{}); err != nil {
		t.Fatal(err)
	}
	service := &Service{db: database, config: Config{AdminSubject: "auth0|admin"}}
	session := &model.DashboardSession{
		TokenHash: security.HashToken("session"), CSRFHash: security.HashToken("csrf"),
		Subject: "auth0|admin", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := database.Create(session).Error; err != nil {
		t.Fatal(err)
	}
	loaded, err := service.AuthenticateSession(t.Context(), "session")
	if err != nil || !service.VerifyCSRF(loaded, "csrf") || service.VerifyCSRF(loaded, "wrong") {
		t.Fatal("session authentication or CSRF validation failed")
	}
	if err := database.Model(session).Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateSession(t.Context(), "session"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("expired session was accepted")
	}
}

func TestLogoutURLUsesConfiguredPublicURL(t *testing.T) {
	service := &Service{config: Config{
		Issuer: "https://tenant.example.auth0.com/", PublicURL: "https://mcp.example.com/", DashboardClientID: "dashboard-client",
	}}
	logout, err := url.Parse(service.LogoutURL())
	if err != nil {
		t.Fatal(err)
	}
	if logout.Scheme != "https" || logout.Host != "tenant.example.auth0.com" || logout.Path != "/v2/logout" ||
		logout.Query().Get("client_id") != "dashboard-client" || logout.Query().Get("returnTo") != "https://mcp.example.com/" {
		t.Fatalf("unexpected Auth0 logout URL: %s", logout.String())
	}
}

func TestHostedClientRevocationIsImmediate(t *testing.T) {
	database, err := testhelpers.CreateTestDB()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&model.HostedClientBinding{}); err != nil {
		t.Fatal(err)
	}
	service := &Service{db: database}
	identity := &AccessIdentity{Subject: "auth0|admin", ClientID: "revoked-client"}
	if _, err := service.BindHostedClient(t.Context(), identity, "research"); err != nil {
		t.Fatal(err)
	}
	if err := service.RevokeHostedClient(t.Context(), identity.ClientID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.BindHostedClient(t.Context(), identity, "research"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked client was accepted: %v", err)
	}
}
