# 🚀 Full-Stack Backend Learning Lab: Golang & Express.js

Welcome to your hands-on backend learning repository! This project contains **two complete, production-pattern REST API backends** built side-by-side to solve the exact same problem:

1. **User Authentication & Registration** (with industry-standard `bcrypt` password hashing)
2. **Session Management** (using cryptographically signed `JWT` - JSON Web Tokens)
3. **Protected API Routes & Middleware** (`Authorization: Bearer <token>`)
4. **Subscription Plans Catalog** (only visible after authenticated login)
5. **Interactive UI Client & API Tester** (to test both backends visually with 1 click)

---

## 📂 Project Directory Structure

```text
learning-backend/
├── golang-backend/            # 🔷 Backend #1 written in Go
│   ├── go.mod                 # Go module definition
│   ├── go.sum                 # Cryptographic dependency checksums
│   ├── models.go              # Data structs, JSON serialization tags & thread-safe store
│   ├── middleware.go          # CORS handling & JWT Auth verification middleware
│   ├── handlers.go            # Register, Login, and Subscriptions controllers
│   ├── main.go                # HTTP router, seed data, and server entry point
│   ├── server.exe             # Pre-compiled executable binary
│   └── .env.example           # Config environment variables
│
├── express-backend/           # 🟩 Backend #2 written in Node.js / Express
│   ├── package.json           # Node.js dependencies (express, bcryptjs, jsonwebtoken, cors)
│   ├── data/
│   │   └── store.js           # In-memory user database & subscription catalog
│   ├── middleware/
│   │   └── auth.js            # Express JWT authentication middleware (req, res, next)
│   ├── routes/
│   │   ├── auth.js            # POST /register and POST /login endpoints
│   │   └── subscriptions.js   # GET /subscriptions protected endpoint
│   ├── server.js              # Express app setup, CORS, and route mounting
│   └── .env.example           # Config environment variables
│
├── frontend/                  # 💻 Interactive Visual Demo Client
│   └── index.html             # Sleek dashboard to test both Go (:8080) and Express (:5000)
│
├── api-requests.http          # One-click REST client requests (VS Code / curl)
├── test-api.ps1               # Automated PowerShell test runner
└── README.md                  # This educational guide
```

---

## 🧠 Core Backend & Security Concepts to Learn

### 1. What is an API and REST?
An **Application Programming Interface (API)** is a structured way for programs to talk to each other over a network.
- **Client (Frontend)**: Runs in the browser/mobile device. Makes HTTP requests.
- **Server (Backend)**: Runs on the server machine. Processes business logic, validates data, accesses databases, and returns HTTP responses (typically formatted as JSON).
- **Statelessness**: REST APIs are *stateless*. Each request must contain all the information necessary for the server to understand and authorize it (e.g., passing a JWT token in the `Authorization` header).

---

### 2. HTTP Status Codes: The Universal Language of Web APIs

| Status Code | Name | When to Use It |
|---|---|---|
| **`200 OK`** | Success | Request succeeded (e.g., successful login or fetching subscription plans). |
| **`201 Created`** | Resource Created | New entity was created (e.g., new user registered). |
| **`400 Bad Request`** | Client Error | Malformed JSON or input validation failure (e.g., invalid email, password too short). |
| **`401 Unauthorized`** | Auth Required | Missing, expired, or invalid JWT token; or incorrect login password. |
| **`409 Conflict`** | Duplicate | Resource conflict (e.g., attempting to register an email that already exists). |
| **`500 Internal Error`** | Server Bug | Unexpected server-side failure. |

---

### 3. Password Security: Why Plain Text is Fatal and Why `bcrypt` Wins

> ⚠️ **Golden Rule of Backend Security**: NEVER store plaintext passwords in a database!

#### Why Not MD5 or SHA-256?
Standard cryptographic hashes like `MD5`, `SHA-1`, or `SHA-256` are designed to be extremely **fast** (for hashing gigabytes of data). Modern graphics cards (GPUs) can compute **billions of SHA-256 hashes per second**, making it trivial for attackers to crack passwords using precomputed lookup tables (**Rainbow Tables**) or brute force.

#### The `bcrypt` Solution:
1. **Cryptographic Salt**: `bcrypt` automatically generates a random 128-bit string called a "salt" for every password. Even if 1,000 users have the password `"password123"`, every single hash will look completely different!
2. **Computational Work Factor (Cost)**: `bcrypt` has a configurable cost factor (e.g., 10 = $2^{10} = 1024$ rounds). This intentionally slows down calculation so humans don't notice a 50ms delay, but an attacker cannot run massive dictionary attacks.
3. **Constant-Time Comparison**: When verifying passwords, `bcrypt.compare` executes in constant time, preventing **Timing Attacks** (where attackers guess characters by measuring response microseconds).

---

### 4. JSON Web Tokens (JWT): How Stateless Sessions Work

When a user logs in, the server generates a **JWT**. A JWT consists of three parts separated by dots (`.`):

$$\underbrace{\text{eyJhbGciOi...}}_{\text{Header}} \ . \ \underbrace{\text{eyJ1c2VySWQiOi...}}_{\text{Payload (Claims)}} \ . \ \underbrace{\text{SflKxwRJSMeKKF2...}}_{\text{Cryptographic Signature}}$$

1. **Header**: Declares the algorithm used (e.g., `HS256` = HMAC-SHA256).
2. **Payload**: Non-sensitive identity statements (called *Claims*), such as `userId`, `email`, and `exp` (expiration timestamp).
   > ⚠️ **Note**: The payload is only base64-encoded, NOT encrypted! Never put passwords or credit cards in a JWT payload.
3. **Signature**: Created by taking the base64 Header + Payload and signing them with the server's private `JWT_SECRET`.
   - If an attacker tampers with the payload (e.g., changes their user ID to an admin's ID), the signature will no longer match, and the backend immediately rejects the request with **401 Unauthorized**!

---

### 5. Middleware Pattern & CORS

#### Middleware Pipeline:
Incoming Request ➡️ **[CORS Middleware]** ➡️ **[JWT Auth Middleware]** ➡️ **[Protected Handler]**

- If the token is missing or invalid, the `AuthMiddleware` terminates the request right there and sends **401 Unauthorized**.
- The protected handler never runs unless the middleware gives the green light!

#### Cross-Origin Resource Sharing (CORS):
Browsers enforce the **Same-Origin Policy**. If your frontend is running on `http://localhost:3000` (or opened as a file) and requests data from `http://localhost:8080`, the browser will block the response unless the backend sends headers like:
```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
```

---

### 6. Account Enumeration Defense
In both backends, observe our login handler logic:
```text
If email is not found   => Return "Invalid email or password"
If password is wrong    => Return "Invalid email or password"
```
**Why not say "User not found"?**
Because if you return "User not found", an attacker can enter a list of 10,000 email addresses to find out which people have accounts on your website!

---

## ⚖️ Side-by-Side Comparison: Go vs Express.js

| Feature | Golang Backend (`golang-backend`) | Node.js Express (`express-backend`) |
|---|---|---|
| **Runtime / Language** | Compiled, statically typed language | Interpreted, dynamic JavaScript / V8 |
| **Concurrency Model** | Goroutines (each HTTP request runs on a lightweight green thread; uses `sync.RWMutex` for memory safety) | Single-threaded Event Loop with non-blocking asynchronous I/O |
| **Data Models** | Explicit `struct` types with struct tags (`json:"email"`) | Plain JavaScript Objects / JSON |
| **Password Hashing** | `golang.org/x/crypto/bcrypt` | `bcryptjs` (Pure JS) |
| **JWT Library** | `github.com/golang-jwt/jwt/v5` | `jsonwebtoken` |
| **Default Port** | `8080` | `5000` |
| **Performance** | Extremely fast, low CPU & RAM footprint | Fast I/O, rapid developer iteration |

---

## 🚀 How to Run the Backends

### Option A: Run the Golang Backend (Port 8080)
Open a terminal in `golang-backend`:
```powershell
cd "c:\Users\PFC-025\Desktop\learning backend\golang-backend"
# Run the pre-compiled binary:
.\server.exe

# Or compile and run directly from source:
go run .
```
You will see:
```text
==============================================================
 🚀 GOLANG AUTH & SUBSCRIPTIONS BACKEND RUNNING
==============================================================
 Server listening on : http://localhost:8080
 Available Endpoints:
  • GET  http://localhost:8080/api/health
  • POST http://localhost:8080/api/register
  • POST http://localhost:8080/api/login
  • GET  http://localhost:8080/api/subscriptions (PROTECTED)
```

---

### Option B: Run the Express Backend (Port 5000)
Open a second terminal in `express-backend`:
```powershell
cd "c:\Users\PFC-025\Desktop\learning backend\express-backend"
npm start
```
You will see:
```text
==============================================================
 🚀 NODE.JS / EXPRESS AUTH & SUBSCRIPTIONS BACKEND RUNNING
==============================================================
 Server listening on : http://localhost:5000
```

---

## 🧪 Testing the APIs

### 1. Interactive Web UI (Recommended!)
Open the test client in any web browser:
- Double click [frontend/index.html](file:///c:/Users/PFC-025/Desktop/learning%20backend/frontend/index.html) or open it directly in Chrome / Edge.
- Toggle between **Golang (Port 8080)** and **Express.js (Port 5000)** with one click!
- Click **"Use Demo"** to log in with `demo@example.com` / `password123`.
- Inspect the colored JWT token (Header, Claims, Signature).
- View the unlocked subscription tiers (**Free**, **Pro**, **Enterprise**).
- Click **"Test Request Without Token"** to watch the security middleware block unauthorized requests in real-time!

---

### 2. Automated PowerShell Test Script
While either server is running, open PowerShell in the project root:
```powershell
# Test Golang backend (port 8080):
.\test-api.ps1 -Port 8080

# Test Express backend (port 5000):
.\test-api.ps1 -Port 5000
```

---

### 3. Quick `curl` Commands

#### 1. Register a new user:
```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Alex","email":"alex@example.com","password":"mypassword123"}'
```

#### 2. Log in and get a JWT token:
```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@example.com","password":"password123"}'
```

#### 3. Attempt accessing subscriptions without token (Fails with 401):
```bash
curl -i http://localhost:8080/api/subscriptions
```

#### 4. Access subscriptions with token (Succeeds with 200):
```bash
curl -H "Authorization: Bearer <PASTE_YOUR_JWT_HERE>" http://localhost:8080/api/subscriptions
```

---

## 🎓 Summary of Learning Checklist
- [x] Know how to structure REST API endpoints (`/api/register`, `/api/login`, `/api/subscriptions`).
- [x] Understand how `bcrypt` salt and cost factors protect user passwords from rainbow tables.
- [x] Understand how `JWT` allows stateless authentication without constant database session lookups.
- [x] Know how to build HTTP middleware that checks headers and protects private routes.
- [x] Understand how browsers handle CORS preflight `OPTIONS` requests.
- [x] Compare Go's compiled type-safety and goroutine concurrency with Node's asynchronous event loop.
