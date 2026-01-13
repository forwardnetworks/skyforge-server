package skyforge

import (
	"fmt"
	"strings"
)

func encryptUserSecret(plaintext string) string {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" || ldapPasswordBox == nil {
		return ""
	}
	enc, err := ldapPasswordBox.encrypt(plaintext)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(enc)
}

func decryptUserSecret(ciphertext string) (string, error) {
	ciphertext = strings.TrimSpace(ciphertext)
	if ciphertext == "" || ldapPasswordBox == nil {
		return "", fmt.Errorf("secret unavailable")
	}
	plaintext, err := ldapPasswordBox.decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return "", fmt.Errorf("secret unavailable")
	}
	return plaintext, nil
}
