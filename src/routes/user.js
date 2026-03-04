const express = require('express');
const { requireAuth } = require('../middleware/auth');
const db = require('../db/supabase');

const router = express.Router();

// Stripe will be initialized if key exists
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
}

const PLAN_LIMITS = {
  free:       { scansPerDay: 1,        scansPerMonth: 30,       historyDays: 7,   apiRequests: 0,     price: '$0',   label: 'Free' },
  pro:        { scansPerDay: 10,       scansPerMonth: 100,      historyDays: 90,  apiRequests: 1000,  price: '$29',  label: 'Pro' },
  team:       { scansPerDay: Infinity, scansPerMonth: Infinity, historyDays: 365, apiRequests: 10000, price: '$79',  label: 'Team' },
  enterprise: { scansPerDay: Infinity, scansPerMonth: Infinity, historyDays: 999, apiRequests: 99999, price: 'Custom', label: 'Enterprise' },
};

// GET /api/user/subscriptions
// Returns current plan, billing status, renewal date, and usage
router.get('/subscriptions', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const planInfo = PLAN_LIMITS[user.plan] || PLAN_LIMITS.free;

    // Base response from what we know locally
    const response = {
      currentPlan: user.plan,
      planLabel: planInfo.label,
      planPrice: planInfo.price,
      status: 'active',
      renewalDate: null,
      stripeCustomerId: user.stripe_customer_id || user.stripeCustomerId || null,
      stripeSubscriptionId: user.stripe_subscription_id || user.stripeSubscriptionId || null,
      limits: {
        scansPerDay: planInfo.scansPerDay === Infinity ? 'Unlimited' : planInfo.scansPerDay,
        scansPerMonth: planInfo.scansPerMonth === Infinity ? 'Unlimited' : planInfo.scansPerMonth,
        historyDays: planInfo.historyDays,
        apiRequests: planInfo.apiRequests === 0 ? 'Not included' : planInfo.apiRequests === Infinity ? 'Unlimited' : planInfo.apiRequests,
      },
      usage: {
        scansToday: 0,
        scansThisMonth: 0,
        scansAllTime: 0,
      },
    };

    // Pull live usage from DB
    try {
      const usage = await db.getUserUsage(user.id);
      if (usage) {
        response.usage.scansToday = usage.scans_today || 0;
        response.usage.scansThisMonth = usage.scans_this_month || 0;
        response.usage.scansAllTime = usage.scans_all_time || 0;
      }
    } catch (usageErr) {
      console.warn('[user/subscriptions] Could not fetch usage:', usageErr.message);
    }

    // Pull live renewal date from Stripe if we have a subscription ID
    const subId = user.stripe_subscription_id || user.stripeSubscriptionId;
    if (stripe && subId && subId !== 'demo_subscription') {
      try {
        const subscription = await stripe.subscriptions.retrieve(subId);
        response.renewalDate = new Date(subscription.current_period_end * 1000).toISOString();
        response.status = subscription.status; // 'active', 'past_due', 'canceled', etc.
      } catch (stripeErr) {
        console.warn('[user/subscriptions] Could not fetch Stripe subscription:', stripeErr.message);
      }
    }

    // For free plan or demo, set a human-friendly status
    if (user.plan === 'free') {
      response.status = 'free';
      response.renewalDate = null;
    } else if (!subId || subId === 'demo_subscription') {
      response.status = 'active';
      response.renewalDate = null; // Demo/manual upgrade — no Stripe billing
    }

    res.json(response);
  } catch (err) {
    console.error('[user/subscriptions] Error:', err);
    res.status(500).json({ error: 'Failed to load subscription data' });
  }
});

// GET /api/user/profile
// Returns full user profile
router.get('/profile', requireAuth, async (req, res) => {
  try {
    const user = req.user;
    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      plan: user.plan,
      createdAt: user.created_at,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
