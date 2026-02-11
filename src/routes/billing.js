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
        message: 'Upgraded to ' + plan + ' (demo mode - Stripe not configured)'
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
      success_url: `${process.env.APP_URL || 'http://localhost:3848'}/dashboard?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.APP_URL || 'http://localhost:3848'}/#pricing`,
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
router.get('/info', requireAuth, async (req, res) => {
  res.json({
    plan: req.user.plan,
    stripeCustomerId: req.user.stripeCustomerId ? '***' : null,
    hasActiveSubscription: !!req.user.stripeSubscriptionId,
  });
});

// Customer portal (manage subscription)
router.post('/portal', requireAuth, async (req, res) => {
  if (!stripe || !req.user.stripeCustomerId) {
    return res.status(400).json({ error: 'No active subscription' });
  }
  
  try {
    const session = await stripe.billingPortal.sessions.create({
      customer: req.user.stripeCustomerId,
      return_url: `${process.env.APP_URL || 'http://localhost:3848'}/dashboard`,
    });
    
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
