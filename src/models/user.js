// Simple in-memory store for MVP (replace with DB later)
// For production: use Supabase, PlanetScale, or MongoDB Atlas

const users = new Map();
const sessions = new Map();
const apiKeys = new Map();
const usageEvents = new Map(); // Track all usage for analytics

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
}

function generateApiKey() {
  const crypto = require('crypto');
  return 'vqa_' + crypto.randomBytes(24).toString('hex');
}

function hashPassword(password) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(password + 'vibeqa-salt').digest('hex');
}

// Special accounts that get upgraded plans automatically
const SPECIAL_ACCOUNTS = {
  'mkanaventi@gmail.com': 'team',
};

// Plan limits (import from pricing.js in production)
const PLAN_LIMITS = {
  free: { scansPerDay: 1, scansPerMonth: 30, historyDays: 7, apiRequests: 0, webhooks: 0, projects: 1 },
  pro: { scansPerDay: 10, scansPerMonth: 100, historyDays: 90, apiRequests: 1000, webhooks: 3, projects: 10 },
  team: { scansPerDay: Infinity, scansPerMonth: Infinity, historyDays: 365, apiRequests: 10000, webhooks: 10, projects: Infinity },
  enterprise: { scansPerDay: Infinity, scansPerMonth: Infinity, historyDays: Infinity, apiRequests: Infinity, webhooks: Infinity, projects: Infinity },
};

const User = {
  create: async ({ email, password, name }) => {
    if (users.has(email.toLowerCase())) {
      throw new Error('Email already registered');
    }
    
    const specialPlan = SPECIAL_ACCOUNTS[email.toLowerCase()] || 'free';
    
    const user = {
      id: generateId(),
      email: email.toLowerCase(),
      passwordHash: hashPassword(password),
      name: name || email.split('@')[0],
      plan: specialPlan,
      
      // Usage tracking
      usage: {
        scansToday: 0,
        scansThisMonth: 0,
        scansAllTime: 0,
        apiRequestsThisMonth: 0,
        webhooksTriggeredThisMonth: 0,
        lastScanDate: null,
        monthStartDate: new Date().toISOString().slice(0, 7), // YYYY-MM
      },
      
      // Billing
      stripeCustomerId: null,
      stripeSubscriptionId: null,
      
      // Settings
      settings: {
        notifications: {
          emailOnScanComplete: true,
          emailOnIssuesFound: true,
          emailWeeklyDigest: true,
          slackOnScanComplete: false,
        },
        timezone: 'America/Los_Angeles',
        defaultProjectId: null,
      },
      
      // Integrations
      integrations: {
        github: null,
        slack: null,
        vercel: null,
        linear: null,
      },
      
      // Metadata
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
      loginCount: 1,
    };
    
    users.set(email.toLowerCase(), user);
    
    // Track signup event
    trackUsageEvent(user.id, 'user_signup', { plan: user.plan });
    
    return { id: user.id, email: user.email, name: user.name, plan: user.plan };
  },
  
  findByEmail: async (email) => {
    return users.get(email.toLowerCase()) || null;
  },
  
  findById: async (id) => {
    for (const user of users.values()) {
      if (user.id === id) return user;
    }
    return null;
  },
  
  verifyPassword: async (email, password) => {
    const user = users.get(email.toLowerCase());
    if (!user) return null;
    if (user.passwordHash !== hashPassword(password)) return null;
    
    // Update login stats
    user.lastLoginAt = new Date().toISOString();
    user.loginCount++;
    
    return { id: user.id, email: user.email, name: user.name, plan: user.plan };
  },
  
  updatePlan: async (userId, plan, stripeCustomerId, stripeSubscriptionId) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        const oldPlan = user.plan;
        user.plan = plan;
        user.stripeCustomerId = stripeCustomerId;
        user.stripeSubscriptionId = stripeSubscriptionId;
        
        trackUsageEvent(userId, 'plan_changed', { from: oldPlan, to: plan });
        return true;
      }
    }
    return false;
  },
  
  // Enhanced usage tracking
  incrementScanCount: async (userId) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        const today = new Date().toDateString();
        const currentMonth = new Date().toISOString().slice(0, 7);
        
        // Reset daily count if new day
        if (user.usage.lastScanDate !== today) {
          user.usage.scansToday = 0;
          user.usage.lastScanDate = today;
        }
        
        // Reset monthly count if new month
        if (user.usage.monthStartDate !== currentMonth) {
          user.usage.scansThisMonth = 0;
          user.usage.apiRequestsThisMonth = 0;
          user.usage.webhooksTriggeredThisMonth = 0;
          user.usage.monthStartDate = currentMonth;
        }
        
        user.usage.scansToday++;
        user.usage.scansThisMonth++;
        user.usage.scansAllTime++;
        
        trackUsageEvent(userId, 'scan_completed', { 
          scansToday: user.usage.scansToday,
          scansThisMonth: user.usage.scansThisMonth,
        });
        
        return user;
      }
    }
    return null;
  },
  
  canScan: async (userId) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        const today = new Date().toDateString();
        const currentMonth = new Date().toISOString().slice(0, 7);
        
        // Reset if new day/month
        if (user.usage.lastScanDate !== today) {
          user.usage.scansToday = 0;
        }
        if (user.usage.monthStartDate !== currentMonth) {
          user.usage.scansThisMonth = 0;
        }
        
        const limits = PLAN_LIMITS[user.plan] || PLAN_LIMITS.free;
        return user.usage.scansToday < limits.scansPerDay && 
               user.usage.scansThisMonth < limits.scansPerMonth;
      }
    }
    return false;
  },
  
  // Get usage stats with upgrade suggestions
  getUsageStats: async (userId) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        const limits = PLAN_LIMITS[user.plan] || PLAN_LIMITS.free;
        
        const stats = {
          plan: user.plan,
          limits,
          current: {
            scansToday: user.usage.scansToday,
            scansThisMonth: user.usage.scansThisMonth,
            scansAllTime: user.usage.scansAllTime,
            apiRequestsThisMonth: user.usage.apiRequestsThisMonth,
          },
          percentages: {
            dailyScans: limits.scansPerDay === Infinity ? 0 : (user.usage.scansToday / limits.scansPerDay) * 100,
            monthlyScans: limits.scansPerMonth === Infinity ? 0 : (user.usage.scansThisMonth / limits.scansPerMonth) * 100,
            apiRequests: limits.apiRequests === Infinity ? 0 : (user.usage.apiRequestsThisMonth / limits.apiRequests) * 100,
          },
          upgradeNudges: [],
        };
        
        // Add upgrade nudges based on usage
        if (stats.percentages.dailyScans >= 80 && user.plan === 'free') {
          stats.upgradeNudges.push({
            type: 'daily_limit',
            message: 'You\'re close to your daily scan limit. Upgrade to Pro for 10 scans/day.',
            cta: 'Upgrade to Pro',
            plan: 'pro',
          });
        }
        if (stats.percentages.monthlyScans >= 80 && user.plan !== 'team') {
          stats.upgradeNudges.push({
            type: 'monthly_limit',
            message: `You've used ${Math.round(stats.percentages.monthlyScans)}% of your monthly scans.`,
            cta: user.plan === 'free' ? 'Upgrade to Pro' : 'Upgrade to Team',
            plan: user.plan === 'free' ? 'pro' : 'team',
          });
        }
        if (user.usage.scansAllTime >= 50 && user.plan === 'free') {
          stats.upgradeNudges.push({
            type: 'power_user',
            message: 'You\'ve run 50+ scans! Unlock AI analysis and integrations with Pro.',
            cta: 'Upgrade to Pro',
            plan: 'pro',
          });
        }
        
        return stats;
      }
    }
    return null;
  },
  
  // Settings management
  updateSettings: async (userId, newSettings) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        user.settings = { ...user.settings, ...newSettings };
        return true;
      }
    }
    return false;
  },
  
  updateNotificationSettings: async (userId, notifications) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        user.settings.notifications = { ...user.settings.notifications, ...notifications };
        return true;
      }
    }
    return false;
  },
  
  updateProfile: async (userId, { name, timezone }) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        if (name !== undefined) user.name = name;
        if (timezone !== undefined) user.settings.timezone = timezone;
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
  
  // Integration management
  connectIntegration: async (userId, integration, data) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        user.integrations[integration] = {
          ...data,
          connectedAt: new Date().toISOString(),
        };
        trackUsageEvent(userId, 'integration_connected', { integration });
        return true;
      }
    }
    return false;
  },
  
  disconnectIntegration: async (userId, integration) => {
    for (const user of users.values()) {
      if (user.id === userId) {
        user.integrations[integration] = null;
        return true;
      }
    }
    return false;
  },
  
  delete: async (userId) => {
    for (const [email, user] of users.entries()) {
      if (user.id === userId) {
        users.delete(email);
        // Also delete API keys
        for (const [key, data] of apiKeys.entries()) {
          if (data.userId === userId) apiKeys.delete(key);
        }
        return true;
      }
    }
    return false;
  },
};

// API Key management
const ApiKey = {
  create: async (userId, name) => {
    const key = generateApiKey();
    apiKeys.set(key, {
      userId,
      name,
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      usageCount: 0,
    });
    trackUsageEvent(userId, 'api_key_created', { name });
    return { key, name, createdAt: new Date().toISOString() };
  },
  
  list: async (userId) => {
    const keys = [];
    for (const [key, data] of apiKeys.entries()) {
      if (data.userId === userId) {
        keys.push({
          key: key.slice(0, 8) + '...' + key.slice(-4), // Masked
          name: data.name,
          createdAt: data.createdAt,
          lastUsedAt: data.lastUsedAt,
          usageCount: data.usageCount,
        });
      }
    }
    return keys;
  },
  
  verify: async (key) => {
    const data = apiKeys.get(key);
    if (!data) return null;
    
    // Update usage stats
    data.lastUsedAt = new Date().toISOString();
    data.usageCount++;
    
    // Increment user's API request count
    const user = await User.findById(data.userId);
    if (user) {
      user.usage.apiRequestsThisMonth++;
    }
    
    return data.userId;
  },
  
  revoke: async (userId, keyPrefix) => {
    for (const [key, data] of apiKeys.entries()) {
      if (data.userId === userId && key.startsWith(keyPrefix.replace('...', ''))) {
        apiKeys.delete(key);
        return true;
      }
    }
    return false;
  },
};

// Session management
const Session = {
  create: async (userId) => {
    const token = generateId() + generateId();
    const session = {
      token,
      userId,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
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
  
  listForUser: async (userId) => {
    const userSessions = [];
    for (const [token, session] of sessions.entries()) {
      if (session.userId === userId) {
        userSessions.push({
          tokenPrefix: token.slice(0, 8) + '...',
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
        });
      }
    }
    return userSessions;
  },
};

// Usage event tracking (for analytics)
function trackUsageEvent(userId, event, data = {}) {
  const eventId = generateId();
  usageEvents.set(eventId, {
    userId,
    event,
    data,
    timestamp: new Date().toISOString(),
  });
  
  // In production, send to analytics service (Mixpanel, Amplitude, etc.)
  console.log(`[USAGE] ${event}:`, { userId, ...data });
}

// Get usage events for analytics
function getUsageEvents(userId, limit = 100) {
  const events = [];
  for (const [id, event] of usageEvents.entries()) {
    if (event.userId === userId) {
      events.push({ id, ...event });
    }
  }
  return events.slice(-limit);
}

module.exports = { User, Session, ApiKey, trackUsageEvent, getUsageEvents, PLAN_LIMITS };
