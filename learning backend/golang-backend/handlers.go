package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Email regex pattern for validation
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ============================================================================
// APP HANDLERS STRUCT
// ============================================================================
// Using a struct to hold our dependencies (like user store and JWT secret) is
// called "Dependency Injection". This keeps code modular and easy to test.
// ============================================================================
type AppHandlers struct {
	store     *UserStore
	jwtSecret []byte
}

func NewAppHandlers(store *UserStore, jwtSecret []byte) *AppHandlers {
	return &AppHandlers{
		store:     store,
		jwtSecret: jwtSecret,
	}
}

// ============================================================================
// 1. USER REGISTRATION HANDLER
// ============================================================================
// ENDPOINT: POST /api/register
//
// WHAT THIS HANDLER DOES:
// 1. Checks HTTP method (rejects GET, PUT, DELETE, etc.)
// 2. Decodes the incoming JSON body into our `RegisterRequest` struct.
// 3. VALIDATION: Verifies email format, password length, and name.
// 4. DUPLICATE CHECK: Verifies no existing account has this email.
// 5. SECURITY CRITICAL - BCRYPT PASSWORD HASHING:
//    - Plaintext passwords MUST NEVER BE STORED in a database!
//    - Bcrypt automatically creates a unique random "salt" for every password.
//    - The "cost" factor (10) makes brute-forcing mathematically infeasible.
// 6. Saves the new user with a default "free" subscription plan.
// 7. Generates a signed JWT token so the user is immediately logged in.
// ============================================================================
func (h *AppHandlers) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Step 1: Ensure request is POST
	if r.Method != http.MethodPost {
		WriteJSONError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}

	// Step 2: Decode JSON request body
	var req RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON payload in request body.")
		return
	}

	// Normalize email to lowercase and trim spaces
	email := strings.ToLower(strings.TrimSpace(req.Email))
	name := strings.TrimSpace(req.Name)
	password := req.Password

	// Step 3: Input Validation
	if name == "" {
		WriteJSONError(w, http.StatusBadRequest, "Name is required.")
		return
	}
	if !emailRegex.MatchString(email) {
		WriteJSONError(w, http.StatusBadRequest, "Please provide a valid email address.")
		return
	}
	// SECURITY: Enforce minimum password strength (at least 6-8 chars)
	if len(password) < 6 {
		WriteJSONError(w, http.StatusBadRequest, "Password must be at least 6 characters long.")
		return
	}

	// Step 4: Check if email already registered (Prevent Duplicate Accounts)
	if _, exists := h.store.FindByEmail(email); exists {
		// HTTP 409 Conflict: Resource already exists
		WriteJSONError(w, http.StatusConflict, "An account with this email already exists.")
		return
	}

	// Step 5: SECURITY - BCRYPT PASSWORD HASHING
	// WHY BCRYPT?
	// - Standard hashes like MD5, SHA-1, and SHA-256 are designed to be fast.
	//   Attackers can test billions of SHA-256 hashes per second using GPUs!
	// - Bcrypt is intentionally SLOW and includes a built-in salt.
	// - bcrypt.DefaultCost is 10 (2^10 = 1024 iterations), balancing security & server CPU.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "Failed to secure password. Please try again.")
		return
	}

	// Generate a random unique ID for the user
	randomBytes := make([]byte, 8)
	_, _ = rand.Read(randomBytes)
	userID := hex.EncodeToString(randomBytes)

	// Step 6: Create user object and save to store
	newUser := User{
		ID:               userID,
		Email:            email,
		Name:             name,
		PasswordHash:     string(hashedPassword),
		SubscriptionPlan: "free", // New signups start on the Free tier!
		CreatedAt:        time.Now(),
	}
	h.store.Save(newUser)

	// Step 7: Generate JWT Token for immediate session authentication
	token, err := h.generateJWT(newUser.ID, newUser.Email)
	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "User created, but token generation failed.")
		return
	}

	// Return HTTP 201 Created
	WriteJSON(w, http.StatusCreated, AuthResponse{
		Message: "Registration successful! Welcome aboard.",
		Token:   token,
		User:    newUser,
	})
}

// ============================================================================
// 2. USER LOGIN HANDLER
// ============================================================================
// ENDPOINT: POST /api/login
//
// WHAT THIS HANDLER DOES:
// 1. Validates input email and password.
// 2. Looks up the user by email in the database.
// 3. SECURITY CRITICAL - DEFENSE AGAINST USER ENUMERATION:
//    - Notice we return the SAME error message ("Invalid email or password")
//      whether the email doesn't exist OR the password is wrong!
//    - If you return "User not found", attackers can test a list of emails to
//      discover which people are registered on your service.
// 4. SECURITY CRITICAL - BCRYPT PASSWORD VERIFICATION:
//    - Uses `bcrypt.CompareHashAndPassword` which executes in constant time
//      to prevent "Timing Attacks" (measuring milliseconds to guess characters).
// 5. Issues a fresh signed JWT token valid for 24 hours.
// ============================================================================
func (h *AppHandlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteJSONError(w, http.StatusMethodNotAllowed, "Method not allowed. Use POST.")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSONError(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	password := req.Password

	if email == "" || password == "" {
		WriteJSONError(w, http.StatusBadRequest, "Both email and password are required.")
		return
	}

	// Step 2: Lookup user
	user, exists := h.store.FindByEmail(email)
	if !exists {
		// Generic error to prevent user enumeration
		WriteJSONError(w, http.StatusUnauthorized, "Invalid email or password.")
		return
	}

	// Step 3: Compare hashed password with user-supplied plaintext password
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		// Passwords do not match
		WriteJSONError(w, http.StatusUnauthorized, "Invalid email or password.")
		return
	}

	// Step 4: Issue signed JWT Token
	token, err := h.generateJWT(user.ID, user.Email)
	if err != nil {
		WriteJSONError(w, http.StatusInternalServerError, "Failed to issue authentication token.")
		return
	}

	// Return 200 OK with token and user details
	WriteJSON(w, http.StatusOK, AuthResponse{
		Message: "Login successful! You are now authenticated.",
		Token:   token,
		User:    user,
	})
}

// ============================================================================
// 3. PROTECTED SUBSCRIPTIONS HANDLER
// ============================================================================
// ENDPOINT: GET /api/subscriptions
//
// WHAT THIS HANDLER DOES:
// 1. This endpoint is wrapped by `AuthMiddleware`. Unauthenticated requests
//    never even make it here (they receive 401 Unauthorized beforehand).
// 2. Extracts authenticated user claims from the context to know WHO is asking.
// 3. Fetches the latest subscription data from our catalog.
// 4. Returns the subscription plans along with the user's current active plan!
// ============================================================================
func (h *AppHandlers) GetSubscriptionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteJSONError(w, http.StatusMethodNotAllowed, "Method not allowed. Use GET.")
		return
	}

	// Extract authenticated user claims injected by AuthMiddleware
	claims, ok := GetUserClaimsFromContext(r.Context())
	if !ok {
		WriteJSONError(w, http.StatusUnauthorized, "User context missing.")
		return
	}

	// Look up the latest profile of the user to see their current plan
	currentUserPlan := "free"
	if user, found := h.store.FindByEmail(claims.Email); found {
		currentUserPlan = user.SubscriptionPlan
	}

	// Catalog of available subscription plans
	plans := []SubscriptionPlan{
		{
			ID:           "free",
			Name:         "Starter Free",
			Description:  "Perfect for exploring and learning the fundamentals.",
			PriceMonthly: 0,
			PriceYearly:  0,
			Currency:     "USD",
			Features: []string{
				"Access to community forum",
				"Basic API access (100 req/day)",
				"Standard documentation",
				"Community support",
			},
			IsPopular: false,
		},
		{
			ID:           "pro",
			Name:         "Developer Pro",
			Description:  "Supercharge your development with unlimited API requests & premium tools.",
			PriceMonthly: 19.99,
			PriceYearly:  190.00,
			Currency:     "USD",
			Features: []string{
				"Unlimited API requests",
				"Advanced security scanning & alerts",
				"Priority email & chat support",
				"Custom domain support",
				"Detailed analytics dashboard",
			},
			IsPopular: true,
		},
		{
			ID:           "enterprise",
			Name:         "Enterprise Scale",
			Description:  "Dedicated infrastructure, SLA guarantees, and 24/7 engineering support.",
			PriceMonthly: 79.99,
			PriceYearly:  790.00,
			Currency:     "USD",
			Features: []string{
				"Everything in Developer Pro",
				"99.99% Uptime SLA guarantee",
				"Dedicated account manager",
				"Single Sign-On (SSO) & SAML integration",
				"Custom security audits & SOC-2 compliance",
			},
			IsPopular: false,
		},
	}

	// Return response with plans and user status
	WriteJSON(w, http.StatusOK, SubscriptionsResponse{
		CurrentUserPlan: currentUserPlan,
		UserEmail:       claims.Email,
		Plans:           plans,
	})
}

// ============================================================================
// HELPER: JWT GENERATION
// ============================================================================
// HOW A JWT IS BORN:
// 1. Claims are configured (UserID, Email, Expiration, IssuedAt).
// 2. Token header specifies algorithm: HMAC-SHA256 (HS256).
// 3. The token is cryptographically signed using our private server secret.
// 4. Returns string: "eyJhbGciOi...header.eyJ1c2Vy...payload.signature"
// ============================================================================
func (h *AppHandlers) generateJWT(userID, email string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Token valid for 24 hours

	claims := &JWTClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "learning-backend-api",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(h.jwtSecret)
}
