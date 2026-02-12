// Simple in-memory store for MVP (replace with DB later)
// For production: use Supabase, PlanetScale, or MongoDB Atlas

const users = new Map();
const sessions = new Map();

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
}

function hashPassword(password) {
  // Simple hash for MVP - use bcrypt in production
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(password + 'vibeqa-salt').digest('hex');
}

// Special accounts that get upgraded plans automatically
const SPECIAL_ACCOUNTS = {
  'mkanaventi@gmail.com': 'team',
  // Add more test accounts here
};

const User = {
  create: async ({ email, password, name }) => {
    if (users.has(email)) {
      throw new Error('Email already registered');
    }
    
    // Check if this email should get a special plan
    const specialPlan = SPECIAL_ACCOUNTS[email.toLowerCase()] || 'free';
    
    const user = {
      id: generateId(),
      email,
      passwordHash: hashPassword(password),
      name: name || email.split('@')[0],
      plan: specialPlan,
      scansToday: 0,
      scansThisMonth: 0,
      lastScanDate: null,
      stripeCustomerId: null,
      stripeSubscriptionId: null,
      createdAt: new Date().toISOString(),
    };
    
    users.set(email, user);
    return { id: user.id, email: user.email, name: user.name, plan: user.plan };
  },
  
  findByEmail: async (email) => {
    return users.get(email) || null;
  },
  
  findById: async (id) => {
    for (const user of users.values()) {
      if (user.id === id) return user;
    }
    return null;
  },
  
  verifyPassword: async (email, password) => {
    const user = users.get(email);
    if (!user) return null;
    if (user.passwordHash !== hashPassword(password)) return null;
    return { id: user.id, email: user.email, name: user.name, plan: user.plan };
  },
  
  updatePlan: async (userId, plan, stripeCustomerId, stripeSubscriptionId) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        user.plan = plan;
        user.stripeCustomerId = stripeCustomerId;
        user.stripeSubscriptionId = stripeSubscriptionId;
        return true;
      }
    }
    return false;
  },
  
  incrementScanCount: async (userId) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        const today = new Date().toDateString();
        if (user.lastScanDate !== today) {
          user.scansToday = 0;
          user.lastScanDate = today;
        }
        user.scansToday++;
        user.scansThisMonth++;
        return user;
      }
    }
    return null;
  },
  
  canScan: async (userId) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        const today = new Date().toDateString();
        if (user.lastScanDate !== today) {
          user.scansToday = 0;
        }
        
        const limits = {
          free: { daily: 1, monthly: Infinity },
          pro: { daily: Infinity, monthly: 30 },
          team: { daily: Infinity, monthly: Infinity },
        };
        
        const limit = limits[user.plan] || limits.free;
        return user.scansToday < limit.daily && user.scansThisMonth < limit.monthly;
      }
    }
    return false;
  },
  
  updateProfile: async (userId, { name }) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        if (name !== undefined) user.name = name;
        return true;
      }
    }
    return false;
  },
  
  updatePassword: async (userId, newPassword) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        user.passwordHash = hashPassword(newPassword);
        return true;
      }
    }
    return false;
  },
  
  delete: async (userId) => {
    for (const [email, user] of users.entries()) {
      if (user.id === userId) {
        users.delete(email);
        return true;
      }
    }
    return false;
  },
};

const Session = {
  create: async (userId) => {
    const token = generateId() + generateId();
    const session = {
      token,
      userId,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(), // 30 days
    };
    sessions.set(token, session);
    return token;
  },
  
  verify: async (token) => {
    const session = sessions.get(token);
    if (!session) return null;
    if (new Date(session.expiresAt) < new Date()) {
      sessions.delete(token);
      return null;
    }
    return session.userId;
  },
  
  destroy: async (token) => {
    sessions.delete(token);
  },
};

module.exports = { User, Session };
