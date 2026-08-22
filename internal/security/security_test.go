package security

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestTokenHashAndMatch(t *testing.T) {
	hashed := HashToken("secret-token")
	if !IsHashedToken(hashed) || !TokenMatches(hashed, "secret-token") || TokenMatches(hashed, "wrong") {
		t.Fatal("token hashing or comparison failed")
	}
}

func TestEncryptionRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureEncryptionKey(base64.StdEncoding.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureEncryptionKey("") })
	ciphertext, err := EncryptString("sensitive")
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == "sensitive" || !IsEncrypted(ciphertext) {
		t.Fatal("value was not encrypted")
	}
	plaintext, err := DecryptString(ciphertext)
	if err != nil || plaintext != "sensitive" {
		t.Fatalf("round trip failed: %q, %v", plaintext, err)
	}
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureEncryptionKey(base64.StdEncoding.EncodeToString(wrongKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptString(ciphertext); err == nil {
		t.Fatal("wrong key decrypted an encrypted value")
	}
}
