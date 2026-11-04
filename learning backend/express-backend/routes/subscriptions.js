const express = require('express');
const authMiddleware = require('../middleware/auth');
const {
  subscriptionPlans,
  findUserById
} = require('../data/store');

const router = express.Router();

// ============================================================================
// PROTECTED SUBSCRIPTION PLANS ROUTE
// ============================================================================
// ROUTE: GET /api/subscriptions
//
// HOW AUTHENTICATION WORKS HERE:
// 1. `authMiddleware` runs first.
// 2. If the client did not send a valid JWT in `Authorization: Bearer <token>`,
//    Express stops immediately and returns 401 Unauthorized.
// 3. If valid, `authMiddleware` attaches the verified user payload to `req.user`.
// 4. This handler executes, reading `req.user.userId` to customize the response.
// 5. Returns the user's current subscription plan and the full catalog of plans!
// ============================================================================
router.get('/subscriptions', authMiddleware, (req, res) => {
  try {
    // req.user was placed here by authMiddleware
    const { userId, email } = req.user;

    // Look up user's active tier
    let currentUserPlan = 'free';
    const user = findUserById(userId);
    if (user && user.subscriptionPlan) {
      currentUserPlan = user.subscriptionPlan;
    }

    // Return current user's plan and the catalog of available subscription options
    // (Providing both camelCase and snake_case for seamless client compatibility)
    return res.status(200).json({
      currentUserPlan: currentUserPlan,
      current_user_plan: currentUserPlan,
      userEmail: email,
      user_email: email,
      plans: subscriptionPlans.map(p => ({
        ...p,
        price_monthly: p.priceMonthly,
        price_yearly: p.priceYearly,
        is_popular: p.isPopular
      }))
    });
  } catch (error) {
    console.error('Subscription fetch error:', error);
    return res.status(500).json({ error: 'Failed to retrieve subscription plans.' });
  }
});

module.exports = router;
