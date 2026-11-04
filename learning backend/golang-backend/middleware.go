package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ============================================================================
// CONTEXT KEYS
// ============================================================================
// In Go, `context.Context` is used to carry request-scoped values (like user info)
// across API boundaries and handlers. We use a custom unexported type for context
// keys to prevent collisions with keys from other packages.
// ============================================================================
type contextKey string

const userClaimsKey contextKey = "userClaims"

// ============================================================================
// 1. CORS (CROSS-ORIGIN RESOURCE SHARING) MIDDLEWARE
// ============================================================================
// WHY CORS MATTERS FOR SECURITY:
// Web browsers enforce the "Same-Origin Policy" by default. If your frontend runs
// on http://localhost:3000 and your backend runs on http://localhost:8080, they
// have different origins (different ports).
//
// The browser will block the frontend from reading backend responses unless the
// backend explicitly returns HTTP headers permitting cross-origin access!
//
// HOW IT WORKS:
// For sensitive or modified requests (like POST with JSON), browsers first send an
// automatic "Preflight" request using the HTTP OPTIONS method to ask:
// "Hey backend, do you allow http://localhost:3000 to send POST requests with JSON?"
// If the backend replies with 200 OK and proper headers, the browser sends the actual POST.
// ============================================================================
func EnableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from any origin (in production, replace "*" with your exact domain e.g., "https://myapp.com")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Specify which HTTP headers the client is allowed to send (Authorization is crucial for JWT!)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Specify which HTTP methods are permitted
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")

		// If this is a preflight OPTIONS request, respond immediately with 204 No Content or 200 OK
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Proceed to the actual handler
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// 2. JWT AUTHENTICATION MIDDLEWARE
// ============================================================================
// WHAT IS A MIDDLEWARE?
// A middleware is a function that intercepts an incoming HTTP request BEFORE it
// reaches your business logic handler. It can inspect, validate, modify the request,
// or reject it early if authentication fails.
//
// HOW JWT AUTHENTICATION WORKS:
// 1. The client sends a header: `Authorization: Bearer <jwt-token-string>`
// 2. The middleware extracts the token string.
// 3. It cryptographically verifies that:
//    a) The token was signed using OUR secret key (not forged by an attacker).
//    b) The token has NOT expired yet.
//    c) The signature algorithm is what we expect (HMAC SHA-256).
// 4. If valid, the user's claims are stored in the request's Context, and the
//    request continues to the protected handler.
// 5. If invalid or missing, it immediately stops and returns 401 Unauthorized!
// ============================================================================
func AuthMiddleware(jwtSecret []byte, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Step 1: Read the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			WriteJSONError(w, http.StatusUnauthorized, "Missing Authorization header. Please login first.")
			return
		}

		// Step 2: The standard format is "Bearer <token>"
		// Let's split by space to ensure "Bearer" prefix is present
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			WriteJSONError(w, http.StatusUnauthorized, "Malformed Authorization header. Format must be 'Bearer <token>'.")
			return
		}

		tokenString := parts[1]

		// Step 3: Parse and verify the token
		claims := &JWTClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// SECURITY CHECK: Verify the signing method is HMAC to prevent "algorithm substitution attacks"
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing algorithm")
			}
			return jwtSecret, nil
		})

		// Step 4: Validate token validity and expiration
		if err != nil || !token.Valid {
			WriteJSONError(w, http.StatusUnauthorized, "Invalid or expired token. Please log in again.")
			return
		}

		// Step 5: Inject claims into request context so the protected handler knows who this is
		ctx := context.WithValue(r.Context(), userClaimsKey, claims)

		// Step 6: Call the next handler with the enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetUserClaimsFromContext extracts authenticated user claims from the request context.
func GetUserClaimsFromContext(ctx context.Context) (*JWTClaims, bool) {
	claims, ok := ctx.Value(userClaimsKey).(*JWTClaims)
	return claims, ok
}

// ============================================================================
// JSON HELPER FUNCTIONS
// ============================================================================
// Standardizing how your API formats responses makes your backend predictable
// and clean for frontend consumers.
// ============================================================================

// WriteJSON sends a JSON response with the given HTTP status code.
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// WriteJSONError sends a standardized error response in JSON format.
func WriteJSONError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, ErrorResponse{Error: message})
}
