const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const {
  findUserByEmail,
  createUser,
  sanitizeUser
} = require('../data/store');

const router = express.Router();

// Email validation regular expression
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// Helper to sign JWT tokens
const generateToken = (userId, email) => {
  const jwtSecret = process.env.JWT_SECRET || 'super_secret_jwt_key_for_learning_backend_2026_xyz!';
  // Tokens are configured with a 24-hour expiration time
  return jwt.sign(
    {
      userId: userId,
      email: email
    },
    jwtSecret,
    {
      expiresIn: '24h',
      issuer: 'learning-backend-api'
    }
  );
};

// ============================================================================
// 1. REGISTER ENDPOINT
// ============================================================================
// ROUTE: POST /api/register
//
// WHAT THIS ENDPOINT DOES:
// 1. Parses JSON body: `{ email, password, name }`.
// 2. INPUT VALIDATION: Checks required fields, valid email format, min password length.
// 3. DUPLICATE CHECK: Verifies no account with this email exists (HTTP 409 Conflict).
// 4. PASSWORD SECURITY:
//    - bcrypt generates a unique 128-bit cryptographic "Salt".
//    - It applies the blowfish cipher 2^10 (1024) times.
//    - The resulting hash looks like: $2a$10$e8N8... containing algorithm, cost, salt, and hash.
// 5. Stores new user with a default "free" subscription tier.
// 6. Issues a JWT so the newly registered user doesn't need to log in twice.
// 7. Returns HTTP 201 Created.
// ============================================================================
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Step 1: Input Validation
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ error: 'Name is required.' });
    }

    if (!email || typeof email !== 'string' || !emailRegex.test(email.trim())) {
      return res.status(400).json({ error: 'Please provide a valid email address.' });
    }

    // SECURITY: Enforce minimum password complexity
    if (!password || typeof password !== 'string' || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Step 2: Check for existing account
    if (findUserByEmail(normalizedEmail)) {
      // HTTP 409 Conflict: Request could not be completed because of a conflict with existing data
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    // Step 3: Hash password with bcrypt
    // Salt rounds = 10 (good balance between security and performance)
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Step 4: Create new user record
    const newUser = {
      id: 'usr_' + crypto.randomBytes(6).toString('hex'),
      email: normalizedEmail,
      name: name.trim(),
      passwordHash: passwordHash,
      subscriptionPlan: 'free', // Default tier
      createdAt: new Date()
    };

    createUser(newUser);

    // Step 5: Issue JWT
    const token = generateToken(newUser.id, newUser.email);

    // Step 6: Respond with 201 Created and sanitized user profile
    return res.status(201).json({
      message: 'Registration successful! Welcome aboard.',
      token: token,
      user: sanitizeUser(newUser)
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

// ============================================================================
// 2. LOGIN ENDPOINT
// ============================================================================
// ROUTE: POST /api/login
//
// WHAT THIS ENDPOINT DOES:
// 1. Parses JSON body: `{ email, password }`.
// 2. Looks up user in data store.
// 3. DEFENSE AGAINST ACCOUNT ENUMERATION ATTACKS:
//    - If user doesn't exist, we STILL return "Invalid email or password" (HTTP 401).
//    - If we returned "Email not found", an attacker could easily verify if
//      celebrity/executive emails exist in your system!
// 4. DEFENSE AGAINST TIMING ATTACKS:
//    - `bcrypt.compare` executes constant-time string comparisons.
// 5. Issues a signed JWT token if passwords match.
// 6. Returns HTTP 200 OK.
// ============================================================================
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Both email and password are required.' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Step 1: Find user by email
    const user = findUserByEmail(normalizedEmail);
    if (!user) {
      // Return generic 401 Unauthorized to prevent account enumeration
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Step 2: Compare user-supplied password with stored bcrypt hash
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      // Passwords do not match
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    // Step 3: Issue signed JWT Token
    const token = generateToken(user.id, user.email);

    // Step 4: Return 200 OK
    return res.status(200).json({
      message: 'Login successful! You are now authenticated.',
      token: token,
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Internal server error during login.' });
  }
});

module.exports = router;
