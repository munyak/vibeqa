const express = require('express');
const { User } = require('../models/user');
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

// Create checkout session
router.post('/checkout', requireAuth, async (req, res) => {
  try {
    const { plan } = req.body;
    
    if (!plan || !PRICES[plan]) {
      return res.status(400).json({ error: 'Invalid plan' });
    }
    
    if (!stripe) {
      // Demo mode - just upgrade the user without payment
      await User.updatePlan(req.user.id, plan, 'demo_customer', 'demo_subscription');
      return res.json({ 
        success: true, 
        demo: true,
        plan,
        message: `🎉 Upgraded to ${plan.charAt(0).toUpperCase() + plan.slice(1)}! (Demo mode - enjoy all features)`
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
      const { userId, plan } = session.metadata;
      
      await User.updatePlan(
        userId,
        plan,
        session.customer,
        session.subscription
      );
      
      console.log(`User ${userId} upgraded to ${plan}`);
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
  res.json({
    plan: req.user.plan,
    stripeCustomerId: customerId ? '***' : null,
    hasActiveSubscription: !!(subscriptionId && subscriptionId !== 'demo_subscription'),
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
