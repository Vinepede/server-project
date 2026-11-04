const jwt = require('jsonwebtoken');

// ============================================================================
// JWT AUTHENTICATION MIDDLEWARE FOR EXPRESS
// ============================================================================
// WHAT IS A MIDDLEWARE IN EXPRESS?
// In Express, a middleware function has the signature `(req, res, next)`.
// It runs before your route handlers and has three superpowers:
// 1. Inspect or modify `req` (e.g., attach `req.user`).
// 2. Respond immediately and abort the pipeline (e.g., `return res.status(401)...`).
// 3. Call `next()` to pass control to the next middleware or route handler.
//
// HOW JWT VERIFICATION WORKS:
// 1. Reads HTTP header: `Authorization: Bearer <token>`
// 2. Extracts the token string.
// 3. `jwt.verify(token, secret)`:
//    - Re-computes the HMAC-SHA256 signature using the server's private secret.
//    - Compares it against the token's signature. If an attacker changed even
//      1 character in the payload (like changing userId to an admin's ID), the
//      cryptographic signature will NOT match!
//    - Checks the expiration timestamp (`exp`). If expired, it throws `TokenExpiredError`.
// 4. If valid, attaches the decoded user payload to `req.user` and calls `next()`.
// ============================================================================

const authMiddleware = (req, res, next) => {
  // Step 1: Extract Authorization header
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    // HTTP 401 Unauthorized: Authentication is required to access this resource
    return res.status(401).json({
      error: 'Missing Authorization header. Please login first.'
    });
  }

  // Step 2: The standard format is 'Bearer <token>'
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return res.status(401).json({
      error: "Malformed Authorization header. Format must be 'Bearer <token>'."
    });
  }

  const token = parts[1];
  const jwtSecret = process.env.JWT_SECRET || 'super_secret_jwt_key_for_learning_backend_2026_xyz!';

  // Step 3: Verify the token
  try {
    const decoded = jwt.verify(token, jwtSecret);

    // Step 4: Attach decoded payload (contains userId, email, iat, exp) to req
    req.user = decoded;

    // Step 5: Proceed to the protected controller
    next();
  } catch (err) {
    // SECURITY NOTE:
    // If jwt.verify fails, err.name could be 'TokenExpiredError' or 'JsonWebTokenError'.
    // We inform the client politely so they know to refresh or re-login.
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Authentication token has expired. Please log in again.'
      });
    }

    return res.status(401).json({
      error: 'Invalid authentication token. Signature verification failed.'
    });
  }
};

module.exports = authMiddleware;
