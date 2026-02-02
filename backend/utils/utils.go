// utils/utils.go
package utils

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func RespondWithError(w http.ResponseWriter, code int, message string) {
	RespondWithJSON(w, code, map[string]string{"error": message})
}

func RespondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateRandomPassword(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "fallbackpass123" // very rare fallback
	}
	return base64.URLEncoding.EncodeToString(b)[:length]
}