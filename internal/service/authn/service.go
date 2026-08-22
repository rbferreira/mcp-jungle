package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/mcpjungle/mcpjungle/internal/model"
	"github.com/mcpjungle/mcpjungle/internal/security"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const requiredMCPScope = "mcp:tools"

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
)

type Config struct {
	PublicURL             string
	Issuer                string
	Audience              string
	DashboardClientID     string
	DashboardClientSecret string
	AdminSubject          string
	ManagementClientID    string
	ManagementSecret      string
	SessionTTL            time.Duration
}

type Service struct {
	db              *gorm.DB
	config          Config
	provider        *oidc.Provider
	idTokenVerifier *oidc.IDTokenVerifier
	accessVerifier  *oidc.IDTokenVerifier
	oauth           oauth2.Config
	httpClient      *http.Client
}

type AccessIdentity struct {
	Subject  string
	ClientID string
	Scopes   []string
}

func New(ctx context.Context, db *gorm.DB, cfg Config) (*Service, error) {
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.PublicURL == "" || cfg.Issuer == "" || cfg.Audience == "" || cfg.DashboardClientID == "" || cfg.DashboardClientSecret == "" || cfg.AdminSubject == "" {
		return nil, errors.New("Auth0 configuration is incomplete")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("load Auth0 discovery metadata: %w", err)
	}
	redirectURL := strings.TrimRight(cfg.PublicURL, "/") + "/auth/callback"
	return &Service{
		db:              db,
		config:          cfg,
		provider:        provider,
		idTokenVerifier: provider.Verifier(&oidc.Config{ClientID: cfg.DashboardClientID}),
		accessVerifier:  provider.Verifier(&oidc.Config{ClientID: cfg.Audience}),
		oauth: oauth2.Config{
			ClientID:     cfg.DashboardClientID,
			ClientSecret: cfg.DashboardClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

func (s *Service) PublicURL() string { return strings.TrimRight(s.config.PublicURL, "/") }
func (s *Service) Issuer() string    { return strings.TrimRight(s.config.Issuer, "/") + "/" }

func (s *Service) LogoutURL() string {
	issuer, err := url.Parse(s.config.Issuer)
	if err != nil {
		return s.PublicURL() + "/"
	}
	values := url.Values{
		"client_id": {s.config.DashboardClientID},
		"returnTo":  {s.PublicURL() + "/"},
	}
	return strings.TrimRight(issuer.Scheme+"://"+issuer.Host, "/") + "/v2/logout?" + values.Encode()
}

func randomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Service) BeginLogin(ctx context.Context) (string, error) {
	state, err := randomToken(32)
	if err != nil {
		return "", err
	}
	nonce, err := randomToken(32)
	if err != nil {
		return "", err
	}
	verifier, err := randomToken(48)
	if err != nil {
		return "", err
	}
	record := &model.DashboardLoginState{
		StateHash:    hashValue(state),
		Nonce:        nonce,
		CodeVerifier: verifier,
		ExpiresAt:    time.Now().UTC().Add(10 * time.Minute),
	}
	if err := s.db.WithContext(ctx).Create(record).Error; err != nil {
		return "", err
	}
	challenge := hashValue(verifier)
	return s.oauth.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

func (s *Service) CompleteLogin(ctx context.Context, state, code string) (string, string, time.Time, error) {
	var pending model.DashboardLoginState
	if err := s.db.WithContext(ctx).Where("state_hash = ?", hashValue(state)).First(&pending).Error; err != nil {
		return "", "", time.Time{}, ErrUnauthenticated
	}
	_ = s.db.WithContext(ctx).Unscoped().Delete(&pending).Error
	if time.Now().UTC().After(pending.ExpiresAt) {
		return "", "", time.Time{}, ErrUnauthenticated
	}
	token, err := s.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", pending.CodeVerifier))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", "", time.Time{}, errors.New("Auth0 did not return an ID token")
	}
	idToken, err := s.idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("verify ID token: %w", err)
	}
	var claims struct {
		Subject string `json:"sub"`
		Nonce   string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return "", "", time.Time{}, err
	}
	if claims.Subject != s.config.AdminSubject || claims.Nonce != pending.Nonce {
		return "", "", time.Time{}, ErrForbidden
	}
	sessionToken, err := randomToken(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	expires := time.Now().UTC().Add(s.config.SessionTTL)
	session := &model.DashboardSession{
		TokenHash: security.HashToken(sessionToken),
		CSRFHash:  security.HashToken(csrfToken),
		Subject:   claims.Subject,
		ExpiresAt: expires,
	}
	if err := s.db.WithContext(ctx).Create(session).Error; err != nil {
		return "", "", time.Time{}, err
	}
	return sessionToken, csrfToken, expires, nil
}

func (s *Service) AuthenticateSession(ctx context.Context, token string) (*model.DashboardSession, error) {
	if token == "" {
		return nil, ErrUnauthenticated
	}
	var session model.DashboardSession
	if err := s.db.WithContext(ctx).Where("token_hash = ? AND expires_at > ?", security.HashToken(token), time.Now().UTC()).First(&session).Error; err != nil {
		return nil, ErrUnauthenticated
	}
	if session.Subject != s.config.AdminSubject {
		return nil, ErrForbidden
	}
	return &session, nil
}

func (s *Service) VerifyCSRF(session *model.DashboardSession, presented string) bool {
	return session != nil && presented != "" && security.TokenMatches(session.CSRFHash, presented)
}

func (s *Service) DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return s.db.WithContext(ctx).Unscoped().Where("token_hash = ?", security.HashToken(token)).Delete(&model.DashboardSession{}).Error
}

func (s *Service) VerifyAccessToken(ctx context.Context, raw string) (*AccessIdentity, error) {
	token, err := s.accessVerifier.Verify(ctx, raw)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var claims struct {
		Subject     string   `json:"sub"`
		Scope       string   `json:"scope"`
		Permissions []string `json:"permissions"`
		AZP         string   `json:"azp"`
		ClientID    string   `json:"client_id"`
	}
	if err := token.Claims(&claims); err != nil {
		return nil, ErrUnauthenticated
	}
	if claims.Subject != s.config.AdminSubject {
		return nil, ErrForbidden
	}
	scopeSet := map[string]bool{}
	for _, scope := range strings.Fields(claims.Scope) {
		scopeSet[scope] = true
	}
	for _, scope := range claims.Permissions {
		scopeSet[scope] = true
	}
	if !scopeSet[requiredMCPScope] {
		return nil, ErrForbidden
	}
	clientID := claims.ClientID
	if clientID == "" {
		clientID = claims.AZP
	}
	if clientID == "" {
		return nil, ErrUnauthenticated
	}
	return &AccessIdentity{Subject: claims.Subject, ClientID: clientID, Scopes: []string{requiredMCPScope}}, nil
}

func (s *Service) BindHostedClient(ctx context.Context, identity *AccessIdentity, group string) (*model.HostedClientBinding, error) {
	var result model.HostedClientBinding
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var binding model.HostedClientBinding
		err := tx.Where("client_id = ?", identity.ClientID).First(&binding).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			now := time.Now().UTC()
			binding = model.HostedClientBinding{ClientID: identity.ClientID, Subject: identity.Subject, ToolGroupName: group, LastSeenAt: &now}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&binding).Error; err != nil {
				return err
			}
			if err := tx.Where("client_id = ?", identity.ClientID).First(&binding).Error; err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if binding.RevokedAt != nil || binding.Subject != identity.Subject || binding.ToolGroupName != group {
			return ErrForbidden
		}
		now := time.Now().UTC()
		if err := tx.Model(&binding).UpdateColumn("last_seen_at", now).Error; err != nil {
			return err
		}
		binding.LastSeenAt = &now
		result = binding
		return nil
	})
	return &result, err
}

func (s *Service) ListHostedClients(ctx context.Context) ([]model.HostedClientBinding, error) {
	var bindings []model.HostedClientBinding
	err := s.db.WithContext(ctx).Order("created_at desc").Find(&bindings).Error
	return bindings, err
}

func (s *Service) RevokeHostedClient(ctx context.Context, clientID string) error {
	now := time.Now().UTC()
	result := s.db.WithContext(ctx).Model(&model.HostedClientBinding{}).Where("client_id = ?", clientID).Update("revoked_at", now)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	if s.config.ManagementClientID == "" || s.config.ManagementSecret == "" {
		return nil
	}
	return s.deleteAuth0Client(ctx, clientID)
}

func (s *Service) deleteAuth0Client(ctx context.Context, clientID string) error {
	issuerURL, err := url.Parse(s.config.Issuer)
	if err != nil {
		return err
	}
	base := strings.TrimRight(issuerURL.Scheme+"://"+issuerURL.Host, "/")
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.config.ManagementClientID},
		"client_secret": {s.config.ManagementSecret},
		"audience":      {base + "/api/v2/"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("Auth0 management token request returned %s", resp.Status)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return err
	}
	deleteReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, base+"/api/v2/clients/"+url.PathEscape(clientID), nil)
	if err != nil {
		return err
	}
	deleteReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	deleteResp, err := s.httpClient.Do(deleteReq)
	if err != nil {
		return err
	}
	defer deleteResp.Body.Close()
	if deleteResp.StatusCode != http.StatusNoContent && deleteResp.StatusCode != http.StatusNotFound {
		io.Copy(io.Discard, deleteResp.Body)
		return fmt.Errorf("Auth0 client deletion returned %s", deleteResp.Status)
	}
	return nil
}
