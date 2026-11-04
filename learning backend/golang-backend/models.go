package main

import (
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ============================================================================
// DATA MODELS & IN-MEMORY DATABASE
// ============================================================================
// In backend engineering, "Models" represent the structure of data stored in
// databases or sent/received across the network.
//
// In Go, we use `struct` with "struct tags" (like `json:"email"`) to dictate
// how Go converts between Go structs and JSON payloads (serialization/deserialization).
// ============================================================================

// User represents a registered account in our system.
type User struct {
	ID               string    `json:"id"`
	Email            string    `json:"email"`
	Name             string    `json:"name"`
	// SECURITY BEST PRACTICE: Notice `json:"-"` on PasswordHash.
	// This tells Go's JSON encoder to NEVER include the password hash in any JSON
	// response sent to the client, preventing accidental credential leaks!
	PasswordHash     string    `json:"-"`
	SubscriptionPlan string    `json:"subscription_plan"` // e.g., "free", "pro", "enterprise"
	CreatedAt        time.Time `json:"created_at"`
}

// RegisterRequest defines the expected JSON payload when a new user signs up.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// LoginRequest defines the expected JSON payload when an existing user logs in.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse is returned to the client upon successful registration or login.
type AuthResponse struct {
	Message string `json:"message"`
	Token   string `json:"token"` // The signed JWT token
	User    User   `json:"user"`
}

// ErrorResponse provides a uniform error message structure.
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// SubscriptionPlan represents a tier of service available to users.
type SubscriptionPlan struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	PriceMonthly float64  `json:"price_monthly"`
	PriceYearly  float64  `json:"price_yearly"`
	Currency     string   `json:"currency"`
	Features     []string `json:"features"`
	IsPopular    bool     `json:"is_popular"`
}

// SubscriptionsResponse is the payload returned by the protected subscriptions endpoint.
type SubscriptionsResponse struct {
	CurrentUserPlan string             `json:"current_user_plan"`
	UserEmail       string             `json:"user_email"`
	Plans           []SubscriptionPlan `json:"plans"`
}

// JWTClaims represents the custom payload claims embedded inside our JWT token.
//
// WHAT IS A JWT CLAIM?
// Claims are statements about an entity (typically the user) and additional data.
// We embed non-sensitive identity metadata (like UserID, Email) so the backend
// can recognize the user on subsequent requests without querying the database every time.
type JWTClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// ============================================================================
// THREAD-SAFE IN-MEMORY USER STORE
// ============================================================================
// In Go, the `net/http` server handles every incoming HTTP request on its own
// lightweight thread called a "goroutine".
//
// Because multiple goroutines can access shared memory simultaneously,
// we MUST use a mutex (`sync.RWMutex`) to prevent "Race Conditions" (data corruption).
// - RLock() allows multiple readers simultaneously (high performance).
// - Lock() ensures exclusive access when writing/inserting a new user.
// ============================================================================
type UserStore struct {
	mu    sync.RWMutex
	users map[string]User // Keyed by lowercase email
}

// NewUserStore creates an initialized user store.
func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]User),
	}
}

// FindByEmail safely searches for a user by email.
func (s *UserStore) FindByEmail(email string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, exists := s.users[email]
	return user, exists
}

// Save safely stores or updates a user.
func (s *UserStore) Save(user User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.Email] = user
}
