#!/usr/bin/env node
/**
 * VibeQA — Stripe Price Setup Script
 *
 * Run this once to create the $49/mo and $149/mo price objects in Stripe.
 * Then add the returned price IDs to your Railway environment variables:
 *   STRIPE_PRO_MONTHLY_PRICE_ID=price_...
 *   STRIPE_TEAM_MONTHLY_PRICE_ID=price_...
 *
 * Usage:
 *   STRIPE_SECRET_KEY=sk_live_... node scripts/setup-stripe-prices.js
 *
 * Or for test mode:
 *   STRIPE_SECRET_KEY=sk_test_... node scripts/setup-stripe-prices.js
 */

const STRIPE_KEY = process.env.STRIPE_SECRET_KEY;

if (!STRIPE_KEY) {
  console.error('ERROR: Set STRIPE_SECRET_KEY environment variable first.');
  console.error('  STRIPE_SECRET_KEY=sk_test_... node scripts/setup-stripe-prices.js');
  process.exit(1);
}

const stripe = require('stripe')(STRIPE_KEY);

async function setup() {
  const isTest = STRIPE_KEY.startsWith('sk_test_');
  console.log(`\n🔧 Setting up VibeQA Stripe prices (${isTest ? 'TEST' : 'LIVE'} mode)\n`);

  // 1. Create the VibeQA product (or find existing)
  let product;
  const existingProducts = await stripe.products.list({ limit: 100 });
  product = existingProducts.data.find(p => p.name === 'VibeQA');

  if (product) {
    console.log(`✓ Found existing product: ${product.id}`);
    // Update description to reflect security focus
    await stripe.products.update(product.id, {
      description: 'AI-powered website security scanning and quality analysis',
    });
  } else {
    product = await stripe.products.create({
      name: 'VibeQA',
      description: 'AI-powered website security scanning and quality analysis',
    });
    console.log(`✓ Created product: ${product.id}`);
  }

  // 2. Create Pro Monthly price ($49/mo)
  const proPrice = await stripe.prices.create({
    product: product.id,
    unit_amount: 4900, // $49.00
    currency: 'usd',
    recurring: { interval: 'month' },
    metadata: { plan: 'pro', tier: 'standard' },
    lookup_key: 'vibeqa_pro_monthly',
  });
  console.log(`✓ Pro Monthly price created: ${proPrice.id} ($49/mo)`);

  // 3. Create Team Monthly price ($149/mo)
  const teamPrice = await stripe.prices.create({
    product: product.id,
    unit_amount: 14900, // $149.00
    currency: 'usd',
    recurring: { interval: 'month' },
    metadata: { plan: 'team', tier: 'premium' },
    lookup_key: 'vibeqa_team_monthly',
  });
  console.log(`✓ Team Monthly price created: ${teamPrice.id} ($149/mo)`);

  // 4. Output the env vars to set
  console.log('\n' + '='.repeat(60));
  console.log('ADD THESE TO YOUR RAILWAY ENVIRONMENT VARIABLES:');
  console.log('='.repeat(60));
  console.log(`STRIPE_PRO_MONTHLY_PRICE_ID=${proPrice.id}`);
  console.log(`STRIPE_TEAM_MONTHLY_PRICE_ID=${teamPrice.id}`);
  console.log('='.repeat(60));
  console.log('\nDone! After setting these env vars, Railway will redeploy automatically.\n');
}

setup().catch(err => {
  console.error('Setup failed:', err.message);
  process.exit(1);
});
