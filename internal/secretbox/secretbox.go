package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var ErrDecryptFailed = errors.New("decrypt failed; re-save credentials")

type Box struct {
	// keys are tried in-order for decryption. Encrypt always uses keys[0].
	keys [][32]byte
}

func New(secret string) *Box {
	keys := make([][32]byte, 0, 2)
	keys = append(keys, sha256.Sum256([]byte(secret)))

	// Backward-compat / recovery path:
	// If SKYFORGE_SESSION_SECRET was accidentally deployed as an empty string, some
	// values may have been encrypted using sha256(""). Allow decrypting those values
	// so the system can recover without permanently breaking stored credentials.
	//
	// NOTE: This does not weaken encryption of *new* values since Encrypt always
	// uses keys[0].
	if strings.TrimSpace(secret) != "" {
		keys = append(keys, sha256.Sum256([]byte("")))
	}

	return &Box{keys: keys}
}

func (sb *Box) Encrypt(plaintext string) (string, error) {
	if sb == nil {
		return "", fmt.Errorf("secret box unavailable")
	}
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return "", nil
	}
	if len(sb.keys) == 0 {
		return "", fmt.Errorf("secret box unavailable")
	}
	block, err := aes.NewCipher(sb.keys[0][:])
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
	var lastErr error
	for _, key := range sb.keys {
		block, err := aes.NewCipher(key[:])
		if err != nil {
			lastErr = err
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			lastErr = err
			continue
		}
		if len(raw) < gcm.NonceSize() {
			return "", fmt.Errorf("invalid encrypted secret")
		}
		nonce := raw[:gcm.NonceSize()]
		ciphertext := raw[gcm.NonceSize():]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			lastErr = err
			continue
		}
		return string(plaintext), nil
	}
	if lastErr != nil {
		// Most commonly this happens when the cluster secret changed after values were
		// stored. Surface a stable, user-actionable error instead of the underlying
		// crypto error string.
		return "", ErrDecryptFailed
	}
	return "", fmt.Errorf("secret box unavailable")
}
