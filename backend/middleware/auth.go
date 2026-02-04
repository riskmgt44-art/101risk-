package middleware

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"riskmgt/database"
	"riskmgt/models"
	"riskmgt/utils"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("AuthMiddleware: %s %s", r.Method, r.URL.Path)
		
		// Skip authentication for WebSocket upgrade requests
		if r.Header.Get("Upgrade") == "websocket" {
			log.Println("AuthMiddleware: WebSocket connection, skipping auth")
			next.ServeHTTP(w, r)
			return
		}
		
		authHeader := r.Header.Get("Authorization")
		log.Printf("AuthMiddleware: Authorization header present: %v", authHeader != "")
		
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			log.Println("AuthMiddleware: Missing or invalid Authorization header")
			utils.RespondWithError(w, http.StatusUnauthorized, "Missing or invalid Authorization header")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		log.Printf("AuthMiddleware: Token string length: %d", len(tokenString))
		if len(tokenString) > 50 {
			log.Printf("AuthMiddleware: Token preview: %s...", tokenString[:50])
		} else {
			log.Printf("AuthMiddleware: Token: %s", tokenString)
		}

		claims, err := utils.ValidateJWT(tokenString)
		if err != nil {
			log.Printf("AuthMiddleware: JWT validation failed: %v", err)
			utils.RespondWithError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		log.Printf("AuthMiddleware: JWT claims - UserID: %s, Name: %s, Role: %s", 
			claims.UserID, claims.Name, claims.Role)

		userID, err := primitive.ObjectIDFromHex(claims.UserID)
		if err != nil {
			log.Printf("AuthMiddleware: Invalid user ID format '%s': %v", claims.UserID, err)
			utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("Invalid user ID format: %s", claims.UserID))
			return
		}

		var user models.User
		err = database.Client.Database("riskmgt").Collection("users").FindOne(r.Context(), bson.M{"_id": userID}).Decode(&user)
		if err != nil {
			log.Printf("AuthMiddleware: User not found in database with ID %s: %v", userID.Hex(), err)
			utils.RespondWithError(w, http.StatusUnauthorized, "User not found")
			return
		}

		log.Printf("AuthMiddleware: Found user - ID: %s, Email: %s, Role: %s, OrgID: %s",
			user.ID.Hex(), user.Email, user.Role, user.OrganizationID.Hex())

		// Verify user has an organization
		if user.OrganizationID.IsZero() {
			log.Printf("AuthMiddleware: User has no organization ID")
			utils.RespondWithError(w, http.StatusBadRequest, "User has no organization")
			return
		}

		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "userName", claims.Name)
		ctx = context.WithValue(ctx, "userRole", claims.Role)
		ctx = context.WithValue(ctx, "orgID", user.OrganizationID.Hex())

		log.Printf("AuthMiddleware: Setting context - userID: %s, orgID: %s", 
			claims.UserID, user.OrganizationID.Hex())

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip for WebSocket connections
		if r.Header.Get("Upgrade") == "websocket" {
			next.ServeHTTP(w, r)
			return
		}
		
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := utils.ValidateJWT(tokenString)
			if err == nil {
				ctx := context.WithValue(r.Context(), "userID", claims.UserID)
				ctx = context.WithValue(ctx, "userName", claims.Name)
				ctx = context.WithValue(ctx, "userRole", claims.Role)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}