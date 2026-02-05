package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
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
			"port":    os.Getenv("PORT"),
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
	setupStaticFileServing(router)

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
		log.Printf("║ Frontend:         http://localhost:%s                  ║", port)
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

// setupStaticFileServing handles serving frontend files
func setupStaticFileServing(router *mux.Router) {
	// Try multiple possible frontend locations
	possiblePaths := []string{
		"frontend",           // Current directory/frontend
		"./frontend",         // Same directory
		"../frontend",        // Parent directory
		"../../frontend",     // Two levels up
		"../../../frontend",  // Three levels up
	}
	
	var frontendPath string
	for _, path := range possiblePaths {
		if stat, err := os.Stat(path); err == nil && stat.IsDir() {
			// Check if index.html exists in this directory
			if _, err := os.Stat(filepath.Join(path, "index.html")); err == nil {
				frontendPath = path
				log.Printf("✓ Found frontend at: %s (absolute: %s)", 
					path, getAbsolutePath(path))
				break
			}
		}
	}
	
	if frontendPath == "" {
		log.Println("⚠ Frontend directory not found - running in API-only mode")
		
		// Provide API-only response
		router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow API routes
			if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/health" || r.URL.Path == "/ws" {
				http.NotFound(w, r) // Let the API routes handle 404
				return
			}
			
			// For non-API routes, show API info
			w.Header().Set("Content-Type", "text/html")
			html := `<!DOCTYPE html>
<html>
<head>
	<title>Risk Management API</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
		.code { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }
		a { color: #0066cc; text-decoration: none; }
		a:hover { text-decoration: underline; }
	</style>
</head>
<body>
	<h1>Risk Management API Server</h1>
	<p>This is an API-only server. The frontend should be deployed separately or check if frontend files are included in the deployment.</p>
	
	<div class="code">
		<h3>Available Endpoints:</h3>
		<p>• <a href="/health">GET /health</a> - Health check</p>
		<p>• GET /api/risks - List risks (requires authentication)</p>
		<p>• GET /api/actions - List actions (requires authentication)</p>
		<p>• GET /api/audit-logs - Audit logs (requires authentication)</p>
		<p>• WS /ws - WebSocket connection for real-time updates</p>
	</div>
	
	<h3>Troubleshooting:</h3>
	<ol>
		<li>Make sure frontend files are in the deployment</li>
		<li>Check that index.html exists in the frontend directory</li>
		<li>Verify file paths are correct (Linux is case-sensitive)</li>
	</ol>
</body>
</html>`
			w.Write([]byte(html))
		})
		return
	}
	
	// Create a case-insensitive file server wrapper
	fs := &caseInsensitiveFileSystem{base: http.Dir(frontendPath)}
	
	// File server for static files
	staticHandler := http.FileServer(fs)
	
	// Serve static files
	router.PathPrefix("/").Handler(http.StripPrefix("/", staticHandler))
	
	log.Printf("Static file serving enabled from: %s", frontendPath)
	
	// Log available HTML files for debugging
	logAvailableHTMLFiles(frontendPath)
}

// getAbsolutePath returns the absolute path for debugging
func getAbsolutePath(relativePath string) string {
	absPath, err := filepath.Abs(relativePath)
	if err != nil {
		return relativePath
	}
	return absPath
}

// logAvailableHTMLFiles lists HTML files for debugging
func logAvailableHTMLFiles(basePath string) {
	htmlFiles := []string{}
	
	err := filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".html") {
			relPath, _ := filepath.Rel(basePath, path)
			htmlFiles = append(htmlFiles, relPath)
		}
		return nil
	})
	
	if err == nil && len(htmlFiles) > 0 {
		log.Printf("Found %d HTML files:", len(htmlFiles))
		for i, file := range htmlFiles {
			if i < 20 { // Show first 20 files
				log.Printf("  • /%s", file)
			}
		}
		if len(htmlFiles) > 20 {
			log.Printf("  ... and %d more", len(htmlFiles)-20)
		}
	}
}

// caseInsensitiveFileSystem wraps http.FileSystem to handle case-insensitive file access
type caseInsensitiveFileSystem struct {
	base http.Dir
}

func (fs *caseInsensitiveFileSystem) Open(name string) (http.File, error) {
	// First try the exact path
	f, err := fs.base.Open(name)
	if err == nil {
		return f, nil
	}
	
	// If not found, try case-insensitive search
	dir, file := filepath.Split(name)
	
	// Get the directory listing
	d, err := fs.base.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	
	// Read directory contents
	files, err := d.Readdir(-1)
	if err != nil {
		return nil, err
	}
	
	// Search for case-insensitive match
	lowerFile := strings.ToLower(file)
	for _, fi := range files {
		if strings.ToLower(fi.Name()) == lowerFile {
			// Found case-insensitive match
			return fs.base.Open(filepath.Join(dir, fi.Name()))
		}
	}
	
	// Try common case variations for bowtie.html
	if strings.Contains(strings.ToLower(name), "bowtie") {
		// Try with capital B
		bowtieVariations := []string{
			strings.Replace(name, "bowtie", "Bowtie", -1),
			strings.Replace(name, "bowtie", "BOWTIE", -1),
			strings.Replace(name, "bowtie.html", "Bowtie.html", -1),
			strings.Replace(name, "bowtie.html", "BOWTIE.HTML", -1),
		}
		
		for _, variation := range bowtieVariations {
			if f, err := fs.base.Open(variation); err == nil {
				log.Printf("Found case variation: %s -> %s", name, variation)
				return f, nil
			}
		}
	}
	
	return nil, os.ErrNotExist
}
