package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

type Box struct {
	key [32]byte
}

func New(secret string) *Box {
	return &Box{key: sha256.Sum256([]byte(secret))}
}

func (sb *Box) Encrypt(plaintext string) (string, error) {
	if sb == nil {
		return "", fmt.Errorf("secret box unavailable")
	}
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(sb.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	out := append(nonce, ciphertext...)
	return "enc:" + base64.RawStdEncoding.EncodeToString(out), nil
}

func (sb *Box) Decrypt(value string) (string, error) {
	if sb == nil {
		return "", fmt.Errorf("secret box unavailable")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, "enc:") {
		return value, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "enc:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(sb.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("invalid encrypted secret")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

