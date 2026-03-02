// gen_token.go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Get secret from command line or generate
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Generate a random secret
		fmt.Println("No JWT_SECRET env var found. Using a random one (for testing only):")
		secret = "test_secret_change_this_in_production_12345"
	}

	// Create claims
	claims := jwt.MapClaims{
		"userId": "507f1f77bcf86cd799439011",
		"email":  "admin@example.com",
		"role":   "admin",
		"orgId":  "507f1f77bcf86cd799439022",
		"exp":    time.Now().Add(time.Hour * 24 * 7).Unix(), // 7 days
		"iat":    time.Now().Unix(),
		"iss":    "riskmgt-backend",
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	
	// Sign token
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== JWT TOKEN ===")
	fmt.Println(tokenString)
	fmt.Println("\n=== SECRET ===")
	fmt.Println(secret)
	fmt.Println("\n=== CLAIMS ===")
	for k, v := range claims {
		fmt.Printf("%s: %v\n", k, v)
	}
}