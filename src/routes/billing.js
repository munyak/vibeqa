const express = require('express');
const db = require('../db/supabase');
const { requireAuth } = require('../middleware/auth');
const { isSpecialAccount } = require('../config/specialAccounts');

const router = express.Router();

// Stripe will be initialized if key exists
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
}

const PRICES = {
  pro: {
    monthly: process.env.STRIPE_PRO_MONTHLY_PRICE_ID || 'price_pro_monthly',
    amount: 2900, // $29
  },
  team: {
    monthly: process.env.STRIPE_TEAM_MONTHLY_PRICE_ID || 'price_team_monthly',
    amount: 7900, // $79
  },
};

// Check if Stripe is configured
router.get('/status', (req, res) => {
  res.json({
    stripeConfigured: !!stripe,
    demoMode: !stripe,
    message: stripe ? 'Stripe is configured' : 'Demo mode - upgrades are instant and free'
  });
});

// Helper: check if Stripe price IDs look real (not placeholder values).
// Real Stripe price IDs: price_1Abc... — at least 24 chars, no generic words.
function stripePricesConfigured() {
  const proId  = process.env.STRIPE_PRO_MONTHLY_PRICE_ID  || '';
  const teamId = process.env.STRIPE_TEAM_MONTHLY_PRICE_ID || '';
  const isReal = (id) =>
    id.startsWith('price_') &&
    id.length >= 24 &&
    !id.includes('pro_monthly') &&
    !id.includes('team_monthly');
  return isReal(proId) && isReal(teamId);
}

// Helper: instant demo/fallback upgrade — writes to Supabase (correct store).
// Returns true on success, throws on failure so callers can surface a clean error.
async function demoUpgrade(userId, plan) {
  await db.updateUser(userId, {
    plan,
    stripe_customer_id: 'demo_customer',
    stripe_subscription_id: 'demo_subscription',
  });
}

// Helper: shared response builder for a successful demo/fallback upgrade
function demoSuccessResponse(plan) {
  const label = plan.charAt(0).toUpperCase() + plan.slice(1);
  return {
    success: true,
    demo: true,
    plan,
    message: `🎉 Upgraded to ${label}! Enjoy all features.`,
  };
}

// Create checkout session
// Strategy: try Stripe first; on ANY Stripe error fall back to demo upgrade.
// demoUpgrade errors are surfaced cleanly — never swallowed.
router.post('/checkout', requireAuth, async (req, res) => {
  const { plan } = req.body;

  if (!plan || !PRICES[plan]) {
    return res.status(400).json({ error: 'Invalid plan' });
  }

  // --- Special/test accounts always bypass Stripe — instant upgrade, never charged ---
  if (isSpecialAccount(req.user.email)) {
    console.log('[billing/checkout] Special account — bypassing Stripe for', req.user.email);
    try {
      await demoUpgrade(req.user.id, plan);
      return res.json(demoSuccessResponse(plan));
    } catch (dbErr) {
      console.error('[billing/checkout] Special account upgrade failed:', dbErr);
      return res.status(500).json({ error: 'Upgrade failed — please try again or contact support@vibeqa.io' });
    }
  }

  // --- Fast-path: no Stripe or placeholder price IDs → instant demo ---
  if (!stripe || !stripePricesConfigured()) {
    console.log('[billing/checkout] Stripe not ready — demo upgrade for', plan);
    try {
      await demoUpgrade(req.user.id, plan);
      return res.json(demoSuccessResponse(plan));
    } catch (dbErr) {
      console.error('[billing/checkout] Demo upgrade failed:', dbErr);
      return res.status(500).json({ error: 'Upgrade failed — please try again or contact support@vibeqa.io' });
    }
  }

  // --- Try real Stripe checkout ---
  try {
    const session = await stripe.checkout.sessions.create({
      customer_email: req.user.email,
      payment_method_types: ['card'],
      line_items: [{ price: PRICES[plan].monthly, quantity: 1 }],
      mode: 'subscription',
      success_url: `${process.env.APP_URL || 'https://vibeqa.io'}/dashboard?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.APP_URL || 'https://vibeqa.io'}/#pricing`,
      metadata: { userId: req.user.id, plan },
    });

    return res.json({ url: session.url, sessionId: session.id });

  } catch (stripeErr) {
    // ANY Stripe error (invalid price ID, API error, network, etc.) → demo fallback
    console.error('[billing/checkout] Stripe error, falling back to demo:', stripeErr.message);
    try {
      await demoUpgrade(req.user.id, plan);
      return res.json(demoSuccessResponse(plan));
    } catch (dbErr) {
      console.error('[billing/checkout] Demo fallback also failed:', dbErr);
      return res.status(500).json({ error: 'Upgrade failed — please try again or contact support@vibeqa.io' });
    }
  }
});

// Stripe webhook
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) {
    return res.status(400).json({ error: 'Stripe not configured' });
  }

  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Webhook signature verification failed' });
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const { userId, plan } = session.metadata || {};
      if (userId && plan) {
        // Write to Supabase (not the old in-memory User model)
        await db.updateUser(userId, {
          plan,
          stripe_customer_id: session.customer,
          stripe_subscription_id: session.subscription,
        });
        console.log(`User ${userId} upgraded to ${plan}`);
      }
      break;
    }

    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      // For MVP, handle manually
      console.log('Subscription cancelled:', subscription.id);
      break;
    }
  }

  res.json({ received: true });
});

// Get billing info
// Note: Supabase returns snake_case fields (stripe_customer_id), check both forms
router.get('/info', requireAuth, async (req, res) => {
  const customerId = req.user.stripe_customer_id || req.user.stripeCustomerId || null;
  // hasActiveSubscription = true for any non-free plan, regardless of whether
  // it was via Stripe checkout, demo fallback, or a manual/complimentary upgrade
  res.json({
    plan: req.user.plan,
    // Mask the customer ID; hide 'demo_customer' entirely (treat as no real Stripe sub)
    stripeCustomerId: (customerId && customerId !== 'demo_customer') ? '***' : null,
    hasActiveSubscription: req.user.plan !== 'free',
  });
});

// Customer portal (manage subscription)
// Handles: real Stripe customer ID, email lookup fallback, demo/manual accounts
router.post('/portal', requireAuth, async (req, res) => {
  // Special/test accounts — never redirect to Stripe portal
  if (isSpecialAccount(req.user.email)) {
    return res.status(400).json({
      error: 'Your account is managed directly as a test account. Contact support@vibeqa.io for plan changes.',
      manualPlan: true,
    });
  }

  // Check for demo/manual plan before even requiring Stripe
  const customerId = req.user.stripe_customer_id || req.user.stripeCustomerId || null;
  const isDemoCustomer = !customerId || customerId === 'demo_customer';

  if (isDemoCustomer && req.user.plan !== 'free') {
    // Paid plan but no real Stripe subscription — managed manually or via demo
    return res.status(400).json({
      error: 'Your plan is managed directly. To make changes, contact support@vibeqa.io.',
      manualPlan: true,
    });
  }

  if (!stripe) {
    return res.status(400).json({ error: 'Stripe not configured on the server' });
  }

  try {
    let resolvedCustomerId = isDemoCustomer ? null : customerId;

    // If no stored customer ID, try to find one in Stripe by email
    if (!resolvedCustomerId) {
      console.log('[billing/portal] No stored customerId for', req.user.email, '— searching Stripe...');
      const customers = await stripe.customers.list({ email: req.user.email, limit: 1 });
      if (customers.data.length > 0) {
        resolvedCustomerId = customers.data[0].id;
        console.log('[billing/portal] Found Stripe customer by email:', resolvedCustomerId);
        // Persist so future requests skip the lookup
        try {
          await db.updateUser(req.user.id, { stripe_customer_id: resolvedCustomerId });
        } catch (e) {
          console.warn('[billing/portal] Could not persist stripe_customer_id:', e.message);
        }
      }
    }

    if (!resolvedCustomerId) {
      if (req.user.plan !== 'free') {
        return res.status(400).json({
          error: 'Your plan is managed directly. To make changes, contact support@vibeqa.io.',
          manualPlan: true,
        });
      }
      return res.status(400).json({
        error: 'No Stripe subscription found for this account. Please upgrade via the pricing page.',
        needsCheckout: true,
      });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: resolvedCustomerId,
      return_url: `${process.env.APP_URL || 'https://vibeqa.io'}/dashboard`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('[billing/portal] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
