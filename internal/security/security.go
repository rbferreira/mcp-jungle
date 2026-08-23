package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	tokenHashPrefix = "sha256:"
	envelopePrefix  = "enc:v1:"
)

var (
	keyMu         sync.RWMutex
	encryptionKey []byte
)

// ConfigureEncryptionKey installs the process-wide key used by model hooks.
// An empty value disables encryption for local development and tests.
func ConfigureEncryptionKey(encoded string) error {
	keyMu.Lock()
	defer keyMu.Unlock()
	if strings.TrimSpace(encoded) == "" {
		encryptionKey = nil
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return fmt.Errorf("encryption key must be base64 encoded: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("encryption key must decode to exactly 32 bytes")
	}
	encryptionKey = append([]byte(nil), key...)
	return nil
}

func EncryptionEnabled() bool {
	keyMu.RLock()
	defer keyMu.RUnlock()
	return len(encryptionKey) == 32
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return tokenHashPrefix + hex.EncodeToString(sum[:])
}

func IsHashedToken(value string) bool { return strings.HasPrefix(value, tokenHashPrefix) }

func TokenMatches(stored, presented string) bool {
	if !IsHashedToken(stored) {
		return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
	}
	want := HashToken(presented)
	return subtle.ConstantTimeCompare([]byte(stored), []byte(want)) == 1
}

func EncryptString(plaintext string) (string, error) {
	if plaintext == "" || IsEncrypted(plaintext) || !EncryptionEnabled() {
		return plaintext, nil
	}
	keyMu.RLock()
	key := append([]byte(nil), encryptionKey...)
	keyMu.RUnlock()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	payload := append(nonce, sealed...)
	return envelopePrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecryptString(value string) (string, error) {
	if value == "" || !IsEncrypted(value) {
		return value, nil
	}
	if !EncryptionEnabled() {
		return "", errors.New("encrypted data is present but MCPJUNGLE_ENCRYPTION_KEY is not configured")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, envelopePrefix))
	if err != nil {
		return "", fmt.Errorf("invalid encrypted envelope: %w", err)
	}
	keyMu.RLock()
	key := append([]byte(nil), encryptionKey...)
	keyMu.RUnlock()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize() {
		return "", errors.New("invalid encrypted envelope length")
	}
	plaintext, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("failed to decrypt value: wrong key or corrupted data")
	}
	return string(plaintext), nil
}

func IsEncrypted(value string) bool { return strings.HasPrefix(value, envelopePrefix) }
