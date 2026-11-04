package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ============================================================================
// MAIN APPLICATION ENTRY POINT (Go Backend)
// ============================================================================
// Here is where the backend starts executing:
// 1. Reads configuration (Port, JWT Secret).
// 2. Initializes the database/store.
// 3. Seeds demo data for easy testing.
// 4. Configures HTTP routing endpoints.
// 5. Wraps the router with CORS middleware.
// 6. Starts the HTTP web server listening for incoming client requests.
// ============================================================================

func main() {
	// ========================================================================
	// 1. CONFIGURATION & ENVIRONMENT VARIABLES
	// ========================================================================
	// In production, sensitive values like secrets should NEVER be hardcoded.
	// We read them from OS environment variables, falling back to local defaults.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	secretKeyStr := os.Getenv("JWT_SECRET")
	if secretKeyStr == "" {
		// Default secret for local learning. (In production: use a 64+ char random string)
		secretKeyStr = "super_secret_jwt_key_for_learning_backend_2026_xyz!"
	}
	jwtSecret := []byte(secretKeyStr)

	// ========================================================================
	// 2. INITIALIZE IN-MEMORY DATABASE & SEED DEMO USER
	// ========================================================================
	userStore := NewUserStore()

	// Seed a pre-existing demo account:
	// Email:    demo@example.com
	// Password: password123
	demoPassword := "password123"
	demoHash, err := bcrypt.GenerateFromPassword([]byte(demoPassword), bcrypt.DefaultCost)
	if err == nil {
		userStore.Save(User{
			ID:               "usr_demo_001",
			Email:            "demo@example.com",
			Name:             "Demo Explorer",
			PasswordHash:     string(demoHash),
			SubscriptionPlan: "pro", // Seeded with Pro plan
			CreatedAt:        time.Now(),
		})
	}

	// ========================================================================
	// 3. INITIALIZE HANDLERS
	// ========================================================================
	handlers := NewAppHandlers(userStore, jwtSecret)

	// ========================================================================
	// 4. HTTP ROUTE DEFINITIONS
	// ========================================================================
	// `http.NewServeMux` is Go's standard HTTP request router/multiplexer.
	mux := http.NewServeMux()

	// Public Health Check Endpoint
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"backend": "Golang Standard HTTP + JWT",
			"time":    time.Now().Format(time.RFC3339),
		})
	})

	// Public Authentication Endpoints
	mux.HandleFunc("/api/register", handlers.RegisterHandler)
	mux.HandleFunc("/api/login", handlers.LoginHandler)

	// Protected Endpoint: Wrapped with AuthMiddleware
	// Any request without a valid JWT 'Authorization: Bearer <token>' will be
	// rejected with 401 Unauthorized before ever reaching GetSubscriptionsHandler!
	mux.HandleFunc("/api/subscriptions", AuthMiddleware(jwtSecret, handlers.GetSubscriptionsHandler))

	// ========================================================================
	// 5. ATTACH GLOBAL MIDDLEWARE (CORS)
	// ========================================================================
	// Wrapping our router with EnableCORS ensures all routes (including preflight
	// OPTIONS requests) have the correct Access-Control headers.
	handlerWithCORS := EnableCORS(mux)

	// ========================================================================
	// 6. START SERVER
	// ========================================================================
	serverAddr := ":" + port
	fmt.Println("==============================================================")
	fmt.Println(" 🚀 GOLANG AUTH & SUBSCRIPTIONS BACKEND RUNNING")
	fmt.Println("==============================================================")
	fmt.Printf(" Server listening on : http://localhost:%s\n", port)
	fmt.Println(" Available Endpoints:")
	fmt.Printf("  • GET  http://localhost:%s/api/health        (Public: Status check)\n", port)
	fmt.Printf("  • POST http://localhost:%s/api/register      (Public: Create account)\n", port)
	fmt.Printf("  • POST http://localhost:%s/api/login         (Public: Authenticate & get JWT)\n", port)
	fmt.Printf("  • GET  http://localhost:%s/api/subscriptions (PROTECTED: Requires Bearer Token)\n", port)
	fmt.Println("--------------------------------------------------------------")
	fmt.Println(" Pre-seeded Demo Credentials for Quick Testing:")
	fmt.Println("  Email:    demo@example.com")
	fmt.Println("  Password: password123")
	fmt.Println("==============================================================")

	if err := http.ListenAndServe(serverAddr, handlerWithCORS); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
