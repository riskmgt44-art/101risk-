// utils/jwt.go
package utils

import (
	"time"

	"github.com/golang-jwt/jwt/v4"

	"riskmgt/config"
)

type Claims struct {
	UserID         string `json:"userID"`
	Name           string `json:"name"`
	Role           string `json:"role"`
	OrganizationID string `json:"organizationId"`
	jwt.RegisteredClaims
}

func GenerateJWT(userID string, name string, role string, organizationID string) (string, error) {
	claims := Claims{
		UserID:         userID,
		Name:           name,
		Role:           role,
		OrganizationID: organizationID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(config.JWTExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(config.JWTKey)
}

func ValidateJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return config.JWTKey, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}