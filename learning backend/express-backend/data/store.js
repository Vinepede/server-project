const bcrypt = require('bcryptjs');

// ============================================================================
// IN-MEMORY DATA STORE & CATALOG
// ============================================================================
// In modern production backends, persistent data is stored in databases like
// PostgreSQL, MySQL, or MongoDB.
//
// For learning and local prototyping, we use an in-memory data store.
// In Node.js, JavaScript executes on a single event loop thread, meaning we don't
// need mutexes like in Go, but we still need to keep data organized cleanly.
// ============================================================================

// Users table (in-memory array)
const users = [];

// Seed an initial demo account for testing:
// Email:    demo@example.com
// Password: password123
const seedDemoUser = async () => {
  const salt = await bcrypt.genSalt(10);
  const passwordHash = await bcrypt.hash('password123', salt);

  users.push({
    id: 'usr_demo_001',
    email: 'demo@example.com',
    name: 'Demo Explorer',
    passwordHash: passwordHash,
    subscriptionPlan: 'pro', // Seeded with Pro plan
    createdAt: new Date()
  });
  console.log('✓ In-memory database seeded with demo user (demo@example.com / password123)');
};

// Immediately seed upon requiring this module
seedDemoUser();

// Catalog of available subscription plans
const subscriptionPlans = [
  {
    id: 'free',
    name: 'Starter Free',
    description: 'Perfect for exploring and learning the fundamentals.',
    priceMonthly: 0,
    priceYearly: 0,
    currency: 'USD',
    features: [
      'Access to community forum',
      'Basic API access (100 req/day)',
      'Standard documentation',
      'Community support'
    ],
    isPopular: false
  },
  {
    id: 'pro',
    name: 'Developer Pro',
    description: 'Supercharge your development with unlimited API requests & premium tools.',
    priceMonthly: 19.99,
    priceYearly: 190.00,
    currency: 'USD',
    features: [
      'Unlimited API requests',
      'Advanced security scanning & alerts',
      'Priority email & chat support',
      'Custom domain support',
      'Detailed analytics dashboard'
    ],
    isPopular: true
  },
  {
    id: 'enterprise',
    name: 'Enterprise Scale',
    description: 'Dedicated infrastructure, SLA guarantees, and 24/7 engineering support.',
    priceMonthly: 79.99,
    priceYearly: 790.00,
    currency: 'USD',
    features: [
      'Everything in Developer Pro',
      '99.99% Uptime SLA guarantee',
      'Dedicated account manager',
      'Single Sign-On (SSO) & SAML integration',
      'Custom security audits & SOC-2 compliance'
    ],
    isPopular: false
  }
];

// Helper functions for interacting with users
const findUserByEmail = (email) => {
  return users.find((u) => u.email.toLowerCase() === email.toLowerCase());
};

const findUserById = (id) => {
  return users.find((u) => u.id === id);
};

const createUser = (userData) => {
  users.push(userData);
  return userData;
};

// Safe user serializer: Strips passwordHash so sensitive hashes never leak!
const sanitizeUser = (user) => {
  const { passwordHash, ...safeUserData } = user;
  return safeUserData;
};

module.exports = {
  users,
  subscriptionPlans,
  findUserByEmail,
  findUserById,
  createUser,
  sanitizeUser
};
