package common

import (
	"crypto/rand"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

func GenerateSecureKey(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func HashSecret(secret string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckSecretHash(secret, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	return err == nil
}