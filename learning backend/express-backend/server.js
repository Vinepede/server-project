const express = require('express');
const cors = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const subscriptionRoutes = require('./routes/subscriptions');

// ============================================================================
// EXPRESS APPLICATION ENTRY POINT
// ============================================================================
// Express is a minimal, flexible Node.js web application framework providing
// robust features for building single, multi-page, and hybrid web applications
// and REST APIs.
// ============================================================================

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================================
// 1. CORS (CROSS-ORIGIN RESOURCE SHARING)
// ============================================================================
// In modern web development, frontends often run on a different port (e.g. 3000)
// or domain than backends (e.g. 5000).
//
// By default, browsers block frontend JavaScript from reading API responses from
// a different origin. The `cors` middleware automatically adds HTTP headers:
// - Access-Control-Allow-Origin: *
// - Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Authorization
// - Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
// ============================================================================
app.use(cors({
  origin: '*', // For local learning; in production specify your domain e.g., 'https://mywebsite.com'
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ============================================================================
// 2. BODY PARSING MIDDLEWARE
// ============================================================================
// When a client sends a POST request with `Content-Type: application/json`,
// the raw HTTP body is a stream of bytes.
// `express.json()` reads that stream and parses it into a JavaScript object
// available under `req.body`.
// ============================================================================
app.use(express.json());

// ============================================================================
// 3. API ROUTES
// ============================================================================

// Public Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    backend: 'Express.js + JWT + bcrypt',
    time: new Date().toISOString()
  });
});

// Authentication routes (Register & Login) -> Public
app.use('/api', authRoutes);

// Subscriptions route -> Protected by authMiddleware inside the router
app.use('/api', subscriptionRoutes);

// ============================================================================
// 4. 404 NOT FOUND HANDLER
// ============================================================================
// If an incoming request does not match any registered route above,
// it falls through to this handler.
// ============================================================================
app.use((req, res) => {
  res.status(404).json({
    error: `Cannot ${req.method} ${req.originalUrl}. Route not found.`
  });
});

// ============================================================================
// 5. GLOBAL ERROR HANDLING MIDDLEWARE
// ============================================================================
// In Express, error handling middleware takes 4 arguments: (err, req, res, next).
// This catches unexpected runtime errors and prevents the server from crashing.
// ============================================================================
app.use((err, req, res, next) => {
  console.error('Unhandled Server Error:', err);
  res.status(500).json({
    error: 'An unexpected internal server error occurred.'
  });
});

// ============================================================================
// 6. START SERVER
// ============================================================================
app.listen(PORT, () => {
  console.log('==============================================================');
  console.log(' 🚀 NODE.JS / EXPRESS AUTH & SUBSCRIPTIONS BACKEND RUNNING');
  console.log('==============================================================');
  console.log(` Server listening on : http://localhost:${PORT}`);
  console.log(' Available Endpoints:');
  console.log(`  • GET  http://localhost:${PORT}/api/health        (Public: Status check)`);
  console.log(`  • POST http://localhost:${PORT}/api/register      (Public: Create account)`);
  console.log(`  • POST http://localhost:${PORT}/api/login         (Public: Authenticate & get JWT)`);
  console.log(`  • GET  http://localhost:${PORT}/api/subscriptions (PROTECTED: Requires Bearer Token)`);
  console.log('--------------------------------------------------------------');
  console.log(' Pre-seeded Demo Credentials for Quick Testing:');
  console.log('  Email:    demo@example.com');
  console.log('  Password: password123');
  console.log('==============================================================');
});
