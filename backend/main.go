package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	"riskmgt/config"
	"riskmgt/database"
	"riskmgt/handlers"
	"riskmgt/middleware"
	"riskmgt/routes"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found or error loading it")
	}

	config.LoadConfig()

	// Database connection
	if err := database.Connect(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// IMPORTANT: Initialize ALL collections early
	handlers.InitializeCollections()

	// Start WebSocket hub
	go handlers.GetHub().Run()
	log.Println("WebSocket hub started")

	// Create main router
	router := mux.NewRouter()

	// ============================================
	// GLOBAL MIDDLEWARE (applied to all routes)
	// ============================================
	router.Use(middleware.CorsMiddleware)
	router.Use(middleware.LoggingMiddleware)
	router.Use(middleware.RecoveryMiddleware)

	// ============================================
	// HEALTH CHECK (works without auth)
	// ============================================
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"version": "1.0.0",
			"service": "riskmgt-backend",
			"port":    os.Getenv("PORT"), // Add this for debugging
		})
	}).Methods("GET", "OPTIONS")

	// ============================================
	// WEBSOCKET ROUTE (before other API routes)
	// ============================================
	router.HandleFunc("/ws", handlers.HandleWebSocket).Methods("GET")
	router.HandleFunc("/api/ws/audit", handlers.HandleWebSocket).Methods("GET")

	// ============================================
	// REGISTER ALL API ROUTES
	// ============================================
	routes.RegisterRoutes(router)

	// ============================================
	// SERVE STATIC FILES (SPA fallback)
	// ============================================
	
	// Only serve static files if they exist
	if _, err := os.Stat("../frontend"); !os.IsNotExist(err) {
		fs := http.FileServer(http.Dir("../frontend"))
		router.PathPrefix("/").Handler(fs)
		log.Println("Static file serving enabled for ../frontend")
	} else {
		log.Println("Static files directory not found, API-only mode")
	}

	// ============================================
	// HTTP SERVER CONFIGURATION
	// ============================================
	// CRITICAL FIX: Get port from environment variable for Render
	port := os.Getenv("PORT")
	if port == "" {
		port = config.Port // Fallback to your config
		if port == "" {
			port = "8080" // Final fallback
		}
	}
	
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// ============================================
	// START SERVER
	// ============================================
	go func() {
		log.Printf("╔══════════════════════════════════════════════════════════╗")
		log.Printf("║                 RiskMGT Backend + Frontend              ║")
		log.Printf("╠══════════════════════════════════════════════════════════╣")
		log.Printf("║ Server running on port: %s                              ║", port)
		log.Printf("║ Health Check:     http://localhost:%s/health           ║", port)
		log.Printf("║ WebSocket:        ws://localhost:%s/ws                 ║", port)
		log.Printf("║ API Endpoint:     http://localhost:%s/api              ║", port)
		log.Printf("╚══════════════════════════════════════════════════════════╝")
		
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	// ============================================
	// GRACEFUL SHUTDOWN
	// ============================================
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced shutdown: %v", err)
	}

	database.Disconnect()
	log.Println("Server stopped gracefully ✓")
}
