// config/config.go
package config

import (
	"log"
	"os"
	"time"
)

var (
	Port          string
	MongoURI      string
	JWTKey        []byte
	JWTExpiration time.Duration
)

func LoadConfig() {
	Port = os.Getenv("PORT")
	if Port == "" {
		Port = "8080"
	}

	MongoURI = os.Getenv("MONGO_URI")
	if MongoURI == "" {
		MongoURI = "mongodb://localhost:27017"
	}

	JWTKey = []byte(os.Getenv("JWT_SECRET"))
	if len(JWTKey) == 0 {
		JWTKey = []byte("secret")
	}

	expireStr := os.Getenv("JWT_EXPIRE")
	dur := 24 * time.Hour
	if expireStr != "" {
		if expireStr == "7d" {
			dur = 7 * 24 * time.Hour
		} else {
			var err error
			dur, err = time.ParseDuration(expireStr)
			if err != nil {
				log.Printf("Invalid JWT_EXPIRE: %s, using 24h", expireStr)
				dur = 24 * time.Hour
			}
		}
	}
	JWTExpiration = dur
}