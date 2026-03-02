// database/database.go
package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"riskmgt/config"
)

var Client *mongo.Client

func Connect() error {
	// Priority 1: Environment variable (recommended & secure)
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		// Fallback to config only if env var is not set
		mongoURI = config.MongoURI
		if mongoURI == "" {
			return fmt.Errorf("MONGODB_URI environment variable is required (or set config.MongoURI)")
		}
		log.Println("WARNING: MONGODB_URI not set in environment → using config value (not recommended for production)")
	}

	clientOptions := options.Client().
		ApplyURI(mongoURI).
		SetConnectTimeout(20 * time.Second).
		SetServerSelectionTimeout(15 * time.Second).
		SetSocketTimeout(20 * time.Second).
		SetMaxPoolSize(50)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var err error
	Client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		return fmt.Errorf("failed to create MongoDB client: %w", err)
	}

	// Verify actual connection with ping
	ctxPing, cancelPing := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelPing()

	if err = Client.Ping(ctxPing, readpref.Primary()); err != nil {
		_ = Client.Disconnect(context.Background()) // cleanup on failure
		return fmt.Errorf("failed to ping MongoDB (connection/auth/network issue): %w\n"+
			"Most common causes:\n"+
			"• IP not whitelisted in MongoDB Atlas → Network Access\n"+
			"• Wrong username/password in URI\n"+
			"• Cluster paused or wrong cluster name\n"+
			"• Firewall/VPN blocking port 27017", err)
	}

	log.Println("Successfully connected to MongoDB")
	return nil
}

func Disconnect() {
	if Client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Client.Disconnect(ctx); err != nil {
		log.Printf("MongoDB disconnect warning: %v", err)
	}
}