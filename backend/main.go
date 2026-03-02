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
	// FIXED: Changed from InitCollections() to InitializeCollections()
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
	
	// First, try to serve static files
	fs := http.FileServer(http.Dir("../frontend"))
	router.PathPrefix("/").Handler(fs)
	
	// If you want more control over static files:
	// router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	// router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//     // Serve index.html for SPA routing
	//     http.ServeFile(w, r, "../frontend/index.html")
	// })

	// ============================================
	// HTTP SERVER CONFIGURATION
	// ============================================
	srv := &http.Server{
		Addr:         ":" + config.Port,
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
		log.Printf("║ Server running on: http://localhost:%s                  ║", config.Port)
		log.Printf("║ Health Check:     http://localhost:%s/health           ║", config.Port)
		log.Printf("║ Create Org:       http://localhost:%s/create-organization.html ║", config.Port)
		log.Printf("║ Executive Dash:   http://localhost:%s/dashboards/executive/ ║", config.Port)
		log.Printf("║ API Endpoint:     http://localhost:%s/api              ║", config.Port)
		log.Printf("║ WebSocket:        ws://localhost:%s/ws                 ║", config.Port)
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