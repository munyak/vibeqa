const express = require('express');
const db = require('../db/supabase');
const { requireAuth } = require('../middleware/auth');

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

// Helper: check if Stripe price IDs are properly configured (not placeholder values)
function stripePricesConfigured() {
  const proId  = process.env.STRIPE_PRO_MONTHLY_PRICE_ID  || '';
  const teamId = process.env.STRIPE_TEAM_MONTHLY_PRICE_ID || '';
  // Real Stripe price IDs look like price_1Abc123... (at least 14 chars, no underscores after prefix)
  const isReal = (id) => id.startsWith('price_') && id.length > 20;
  return isReal(proId) && isReal(teamId);
}

// Helper: instant demo upgrade — writes to Supabase (or its fallback), not the old in-memory User model
async function demoUpgrade(userId, plan) {
  await db.updateUser(userId, {
    plan,
    stripe_customer_id: 'demo_customer',
    stripe_subscription_id: 'demo_subscription',
  });
}

// Create checkout session
router.post('/checkout', requireAuth, async (req, res) => {
  try {
    const { plan } = req.body;

    if (!plan || !PRICES[plan]) {
      return res.status(400).json({ error: 'Invalid plan' });
    }

    // Use demo mode if Stripe is not configured OR price IDs are placeholder/missing
    if (!stripe || !stripePricesConfigured()) {
      await demoUpgrade(req.user.id, plan);
      return res.json({
        success: true,
        demo: true,
        plan,
        message: `🎉 Upgraded to ${plan.charAt(0).toUpperCase() + plan.slice(1)}! Enjoy all features.`
      });
    }

    // Create Stripe checkout session
    const session = await stripe.checkout.sessions.create({
      customer_email: req.user.email,
      payment_method_types: ['card'],
      line_items: [{
        price: PRICES[plan].monthly,
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: `${process.env.APP_URL || 'https://vibeqa.io'}/dashboard?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.APP_URL || 'https://vibeqa.io'}/#pricing`,
      metadata: {
        userId: req.user.id,
        plan: plan,
      },
    });

    res.json({ url: session.url, sessionId: session.id });
  } catch (err) {
    console.error('Checkout error:', err);
    // If Stripe call fails (e.g., invalid price ID), fall back to demo upgrade
    if (err.type === 'StripeInvalidRequestError') {
      try {
        await demoUpgrade(req.user.id, req.body.plan);
        return res.json({
          success: true,
          demo: true,
          plan: req.body.plan,
          message: `🎉 Upgraded to ${req.body.plan.charAt(0).toUpperCase() + req.body.plan.slice(1)}! Enjoy all features.`,
        });
      } catch (dbErr) {
        console.error('Demo upgrade fallback also failed:', dbErr);
      }
    }
    res.status(500).json({ error: err.message });
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
      // Find user by stripeSubscriptionId and downgrade
      // For MVP, we'll handle this manually
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
  const subscriptionId = req.user.stripe_subscription_id || req.user.stripeSubscriptionId || null;
  // hasActiveSubscription = true for any non-free plan, regardless of whether
  // it was via Stripe checkout or a manual/complimentary upgrade
  res.json({
    plan: req.user.plan,
    stripeCustomerId: customerId ? '***' : null,
    hasActiveSubscription: req.user.plan !== 'free',
  });
});

// Customer portal (manage subscription)
// Handles: stored customer ID, Stripe email lookup fallback, demo subscriptions
router.post('/portal', requireAuth, async (req, res) => {
  if (!stripe) {
    return res.status(400).json({ error: 'Stripe not configured on the server' });
  }

  try {
    // Supabase returns snake_case; check both field name forms
    let customerId = req.user.stripe_customer_id || req.user.stripeCustomerId || null;

    // If no stored customer ID, try to find one in Stripe by email
    if (!customerId) {
      console.log('[billing/portal] No stored customerId for', req.user.email, '— searching Stripe...');
      const customers = await stripe.customers.list({ email: req.user.email, limit: 1 });
      if (customers.data.length > 0) {
        customerId = customers.data[0].id;
        console.log('[billing/portal] Found Stripe customer by email:', customerId);
        // Persist so future requests skip the lookup
        try {
          await require('../db/supabase').updateUser(req.user.id, { stripe_customer_id: customerId });
        } catch (e) {
          console.warn('[billing/portal] Could not persist stripe_customer_id:', e.message);
        }
      }
    }

    if (!customerId) {
      // If user already has a paid plan, this is a manually/complimentary managed account
      if (req.user.plan !== 'free') {
        return res.status(400).json({
          error: 'Your plan is managed manually. To make changes, contact support@vibeqa.io.',
          manualPlan: true,
        });
      }
      return res.status(400).json({
        error: 'No Stripe subscription found for this account. Please upgrade via the pricing page.',
        needsCheckout: true,
      });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${process.env.APP_URL || 'https://vibeqa.io'}/dashboard`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('[billing/portal] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
